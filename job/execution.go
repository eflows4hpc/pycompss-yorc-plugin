// Copyright 2020 Bull S.A.S. Atos Technologies - Bull, Rue Jean Jaures, B.P.68, 78340, Les Clayes-sous-Bois, France.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package job

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/mitchellh/mapstructure"
	"github.com/ystia/yorc/v4/deployments"
	"github.com/ystia/yorc/v4/events"
	"github.com/ystia/yorc/v4/helper/executil"
	"github.com/ystia/yorc/v4/helper/sshutil"
	"github.com/ystia/yorc/v4/log"
	"github.com/ystia/yorc/v4/prov"
	"github.com/ystia/yorc/v4/tasks"
	"github.com/ystia/yorc/v4/tosca"
)

// ExecuteAsync executes an asynchronous operation
func (e *Execution) ExecuteAsync(ctx context.Context) (*prov.Action, time.Duration, error) {
	if strings.ToLower(e.Operation.Name) != tosca.RunnableRunOperationName {
		return nil, 0, fmt.Errorf("unsupported asynchronous operation %q", e.Operation.Name)
	}

	jobStr, err := tasks.GetTaskData(e.TaskID, fmt.Sprintf("pycompssjobinfo/%s", e.NodeName))
	if err != nil {
		return nil, 0, err
	}

	data := make(map[string]string)
	data["taskID"] = e.TaskID
	data["nodeName"] = e.NodeName
	data["job"] = jobStr
	data["vaultID"] = e.vaultID

	return &prov.Action{ActionType: PyCOMPSsJobMonitoringActionType, Data: data}, e.MonitoringTimeInterval, err
}

// Execute executes a synchronous operation
func (e *Execution) Execute(ctx context.Context) error {

	var err error
	switch strings.ToLower(e.Operation.Name) {
	case tosca.RunnableSubmitOperationName:
		events.WithContextOptionalFields(ctx).NewLogEntry(events.LogLevelINFO, e.DeploymentID).Registerf(
			"Submitting Job %q", e.NodeName)

		params, err := e.resolveJobParams(ctx)
		if err != nil {
			return err
		}

		pcJob := &pycompssJob{
			JobParams: params,
			JobInfo:   &jobInfo{},
		}

		err = e.submitJob(ctx, pcJob)
		if err != nil {
			events.WithContextOptionalFields(ctx).NewLogEntry(events.LogLevelINFO, e.DeploymentID).Registerf(
				"Failed to submit Job %q, error %s", e.NodeName, err.Error())
			return err
		}

		// Store job info in task data for later use in monitoring and cancel
		jobJson, err := json.Marshal(pcJob)
		if err != nil {
			return fmt.Errorf("failed to format job info in json: %w", err)
		}
		err = tasks.SetTaskData(e.TaskID, fmt.Sprintf("pycompssjobinfo/%s", e.NodeName), string(jobJson))
		if err != nil {
			return fmt.Errorf("failed to store job info in task: %w", err)
		}
	case tosca.RunnableCancelOperationName:
		events.WithContextOptionalFields(ctx).NewLogEntry(events.LogLevelINFO, e.DeploymentID).Registerf(
			"Canceling Job %q", e.NodeName)
		err = e.cancelJob(ctx)
		if err != nil {
			events.WithContextOptionalFields(ctx).NewLogEntry(events.LogLevelINFO, e.DeploymentID).Registerf(
				"Failed to cancel Job %q, error %s", e.NodeName, err.Error())

		}
	default:
		err = fmt.Errorf("unsupported operation %q", e.Operation.Name)
	}

	return err
}

func (e *Execution) resolveJobParams(ctx context.Context) (*pycompssJobParams, error) {
	params := &pycompssJobParams{}
	err := e.resolveNodeProperties(ctx, params)
	if err != nil {
		return params, err
	}

	err = e.resolvePropertiesFromWFInputs(ctx, params)
	return params, err
}

// ResolveExecution resolves inputs and artifacts before the execution of an operation
func (e *Execution) ResolveExecution(ctx context.Context) error {
	log.Debugf("Preparing execution of operation %q on node %q for deployment %q", e.Operation.Name, e.NodeName, e.DeploymentID)
	var err error

	e.privateKeyVaultSecret, e.vaultID, err = getPrivateKeyAndVaultID(e.TaskID)
	return err
}

func (e *Execution) resolvePropertiesFromWFInputs(ctx context.Context, params *pycompssJobParams) error {
	user, err := tasks.GetTaskInput(e.TaskID, "user")
	if err != nil && !tasks.IsTaskDataNotFoundError(err) {
		return err
	}
	if user != "" {
		params.Environment.UserName = user
	}

	data, err := tasks.GetAllTaskData(e.TaskID)
	if err != nil && !tasks.IsTaskDataNotFoundError(err) {
		return err
	}
	for key, d := range data {
		if strings.HasPrefix(key, "inputs/PyCOMPSs_") {
			params.ExtraEnv[strings.TrimPrefix(key, "inputs/PyCOMPSs_")] = d
		}
	}
	for key, d := range data {
		prefix := fmt.Sprintf("inputs/%s_PyCOMPSs_", e.NodeName)
		if strings.HasPrefix(key, prefix) {
			params.ExtraEnv[strings.TrimPrefix(key, prefix)] = d
		}
	}

	numNodes, err := tasks.GetTaskInput(e.TaskID, fmt.Sprintf("%s_num_nodes", e.NodeName))
	if err != nil && !tasks.IsTaskDataNotFoundError(err) {
		return err
	}
	if numNodes != "" {
		nn, err := strconv.Atoi(numNodes)
		if err != nil {
			return fmt.Errorf("invalid value for %s_num_nodes input: %w", e.NodeName, err)
		}
		params.SubmissionParams.NumNodes = nn
	}

	return nil
}

func (e *Execution) resolveNodeProperties(ctx context.Context, params *pycompssJobParams) error {
	rawEnv, err := deployments.GetNodePropertyValue(ctx, e.DeploymentID, e.NodeName, "environment")
	if err != nil {
		return err
	}
	var env Environment
	if rawEnv != nil && rawEnv.RawString() != "" {
		err = mapstructure.Decode(rawEnv.Value, &env)
		if err != nil {
			return fmt.Errorf("failed to decode environment property for node %q: %w", e.NodeName, err)
		}
		params.Environment = env
	}

	rawSubParams, err := deployments.GetNodePropertyValue(ctx, e.DeploymentID, e.NodeName, "submission_params")
	if err != nil {
		return err
	}
	var subParams SubmissionParams
	if rawSubParams != nil && rawSubParams.RawString() != "" {
		config := &mapstructure.DecoderConfig{
			WeaklyTypedInput: true,
			Result:           &subParams,
		}
		decoder, err := mapstructure.NewDecoder(config)
		if err != nil {
			return fmt.Errorf("failed to decode submission_params property for node %q: %w", e.NodeName, err)
		}
		err = decoder.Decode(rawSubParams.Value)
		if err != nil {
			return fmt.Errorf("failed to decode submission_params property for node %q: %w", e.NodeName, err)
		}
		params.SubmissionParams = subParams
	}

	rawApp, err := deployments.GetNodePropertyValue(ctx, e.DeploymentID, e.NodeName, "application")
	if err != nil {
		return err
	}
	var app COMPSsApplication
	if rawApp != nil && rawApp.RawString() != "" {
		err = mapstructure.Decode(rawApp.Value, &app)
		if err != nil {
			return fmt.Errorf("failed to decode application property for node %q: %w", e.NodeName, err)
		}
		params.CompssApplication = app
	}
	return nil
}

var reEnvIDInit = regexp.MustCompile(`Environment ID: (\w+)`)

func (e *Execution) initPycompss(ctx context.Context, agent *sshutil.SSHAgent, params *pycompssJobParams) (string, error) {
	args := []string{"init", "remote", "-l", fmt.Sprintf("%s@%s", params.Environment.UserName, params.Environment.Endpoint), "-m"}
	args = append(args, params.SubmissionParams.CompssModules...)
	cmd := executil.Command(ctx, "pycompss", args...)
	cmd.Env = append(cmd.Env, fmt.Sprintf("SSH_AUTH_SOCK=%s", agent.Socket))

	stdout, err := cmd.Output()
	if err != nil {
		return "", fmt.Errorf("failed to execute pycompss command to initialize environment: %w", err)
	}

	subMatches := reEnvIDInit.FindStringSubmatch(string(stdout))
	if subMatches == nil || len(subMatches) != 2 {
		return "", fmt.Errorf("fail to retrieve PyCOMPSs environment id in init command return: %s", string(stdout))
	}
	return subMatches[1], nil
}

func (e *Execution) deployPycompssApp(ctx context.Context, envID, appName string, agent *sshutil.SSHAgent) error {
	cmd := executil.Command(ctx, "pycompss", "env", "change", envID)
	cmd.Env = append(cmd.Env, fmt.Sprintf("SSH_AUTH_SOCK=%s", agent.Socket))
	err := cmd.Run()
	if err != nil {
		return fmt.Errorf("failed to execute pycompss command to change to env %s: %w", envID, err)
	}

	dir, err := os.MkdirTemp("", "pycompss-app-")
	if err != nil {
		return fmt.Errorf("fail to create temporary directory to deploy PyCOMPSs application: %w", err)
	}
	defer os.RemoveAll(dir)

	cmd = executil.Command(ctx, "pycompss", "app", "deploy", appName)
	cmd.Dir = dir
	cmd.Env = append(cmd.Env, fmt.Sprintf("SSH_AUTH_SOCK=%s", agent.Socket))
	err = cmd.Run()
	if err != nil {
		return fmt.Errorf("failed to execute pycompss command to deploy application %s: %w", appName, err)
	}
	return nil
}

func (e *Execution) generateSubmitCommandArgs(pcJob *pycompssJob) []string {

	// TODO(loicalbertin) data paths
	args := []string{"job", "submit", "-app", pcJob.JobInfo.AppName, "-d"}

	if pcJob.JobParams.SubmissionParams.NumNodes != 0 {
		args = append(args, fmt.Sprintf("--num_nodes=%d", pcJob.JobParams.SubmissionParams.NumNodes))
	}
	if pcJob.JobParams.SubmissionParams.Qos != "" {
		args = append(args, fmt.Sprintf("--qos=%s", pcJob.JobParams.SubmissionParams.Qos))
	}
	if pcJob.JobParams.SubmissionParams.PythonInterpreter != "" {
		args = append(args, fmt.Sprintf("--python_interpreter=%s", pcJob.JobParams.SubmissionParams.PythonInterpreter))
	}
	if pcJob.JobParams.SubmissionParams.ExtraCompssOpts != "" {
		args = append(args, pcJob.JobParams.SubmissionParams.ExtraCompssOpts)
	}

	if pcJob.JobParams.CompssApplication.ContainerOpts.ContainerImage != "" {
		args = append(args, fmt.Sprintf("--container_image=%s", pcJob.JobParams.CompssApplication.ContainerOpts.ContainerImage))
	}

	if pcJob.JobParams.CompssApplication.ContainerOpts.ContainerCompssPath != "" {
		args = append(args, fmt.Sprintf("--container_compss_path=%s", pcJob.JobParams.CompssApplication.ContainerOpts.ContainerCompssPath))
	}

	if pcJob.JobParams.CompssApplication.ContainerOpts.ContainerOpts != "" {
		args = append(args, fmt.Sprintf("--container_opts=%s", pcJob.JobParams.CompssApplication.ContainerOpts.ContainerOpts))
	}
	// Application command & args should be at the end
	args = append(args, pcJob.JobParams.CompssApplication.Command)
	args = append(args, pcJob.JobParams.CompssApplication.Arguments...)
	return args
}

var reJobIDSubmit = regexp.MustCompile(`Job submitted: (\d+)`)

func (e *Execution) submitPycompss(ctx context.Context, agent *sshutil.SSHAgent, pcJob *pycompssJob) (string, error) {
	cmd := executil.Command(ctx, "pycompss", "env", "change", pcJob.JobInfo.EnvironmentID)
	cmd.Env = append(cmd.Env, fmt.Sprintf("SSH_AUTH_SOCK=%s", agent.Socket))
	err := cmd.Run()
	if err != nil {
		return "", fmt.Errorf("failed to execute pycompss command to change to env %s: %w", pcJob.JobInfo.EnvironmentID, err)
	}

	cmd = executil.Command(ctx, "pycompss", e.generateSubmitCommandArgs(pcJob)...)
	cmd.Env = append(cmd.Env, fmt.Sprintf("SSH_AUTH_SOCK=%s", agent.Socket))
	for envKey, envVal := range pcJob.JobParams.ExtraEnv {
		cmd.Env = append(cmd.Env, fmt.Sprintf("%s=%s", envKey, envVal))
	}

	stdout, err := cmd.Output()
	if err != nil {
		return "", fmt.Errorf("failed to execute pycompss command to submit job: %w", err)
	}
	subMatches := reJobIDSubmit.FindStringSubmatch(string(stdout))
	if subMatches == nil || len(subMatches) != 2 {
		return "", fmt.Errorf("fail to retrieve PyCOMPSs job id in submit command return: %s", stdout)
	}
	return subMatches[1], nil
}

func (e *Execution) submitJob(ctx context.Context, pcJob *pycompssJob) error {

	agent, err := setupSSHAgent(ctx, e.privateKeyVaultSecret)
	if err != nil {
		return err
	}
	defer agent.Stop()

	pcJob.JobInfo.EnvironmentID, err = e.initPycompss(ctx, agent, pcJob.JobParams)
	if err != nil {
		return err
	}

	pcJob.JobInfo.AppName = fmt.Sprintf("%s-%s", e.NodeName, e.TaskID)
	err = e.deployPycompssApp(ctx, pcJob.JobInfo.EnvironmentID, pcJob.JobInfo.AppName, agent)
	if err != nil {
		return err
	}

	pcJob.JobInfo.JobID, err = e.submitPycompss(ctx, agent, pcJob)
	return err
}

func (e *Execution) cancelJob(originalCtx context.Context) error {

	pcJob, err := e.getJob()
	if err != nil {
		return err
	}

	// originalCtx is sometimes already cancelled, so let create another one and let 60s to commands to execute
	ctx, timeoutFunc := context.WithTimeout(context.Background(), 60*time.Second)
	defer timeoutFunc()

	agent, err := setupSSHAgent(ctx, e.privateKeyVaultSecret)
	if err != nil {
		return err
	}
	defer agent.Stop()

	cmd := executil.Command(ctx, "pycompss", "env", "change", pcJob.JobInfo.EnvironmentID)
	cmd.Env = append(cmd.Env, fmt.Sprintf("SSH_AUTH_SOCK=%s", agent.Socket))
	err = cmd.Run()
	if err != nil {
		return fmt.Errorf("failed to execute pycompss command to change to env %s: %w", pcJob.JobInfo.EnvironmentID, err)
	}

	cmd = executil.Command(ctx, "pycompss", "job", "cancel", pcJob.JobInfo.JobID)
	cmd.Env = append(cmd.Env, fmt.Sprintf("SSH_AUTH_SOCK=%s", agent.Socket))
	err = cmd.Run()
	if err != nil {
		return fmt.Errorf("failed to execute pycompss command to cancel job %s: %w", pcJob.JobInfo.JobID, err)
	}
	return nil
}

func (e *Execution) getJob() (*pycompssJob, error) {
	jobStr, err := tasks.GetTaskData(e.TaskID, fmt.Sprintf("pycompssjobinfo/%s", e.NodeName))
	if err != nil {
		return nil, err
	}

	job := new(pycompssJob)
	err = json.Unmarshal([]byte(jobStr), job)
	if err != nil {
		return nil, fmt.Errorf("faild to parse json representation of PyCOMPSs job: %w", err)
	}
	return job, nil

}
