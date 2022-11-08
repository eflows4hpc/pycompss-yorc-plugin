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
	"regexp"

	"github.com/hashicorp/go-multierror"
	"github.com/ystia/yorc/v4/config"
	"github.com/ystia/yorc/v4/deployments"
	"github.com/ystia/yorc/v4/events"
	"github.com/ystia/yorc/v4/helper/executil"
	"github.com/ystia/yorc/v4/helper/sshutil"
	"github.com/ystia/yorc/v4/log"
	"github.com/ystia/yorc/v4/prov"
	"github.com/ystia/yorc/v4/tasks"
)

const (
	PyCOMPSsJobMonitoringActionType = "pycompss-job-monitoring"
)

const (
	jobStatePending     = "PENDING"
	jobStateRunning     = "RUNNING"
	jobStateCompleting  = "COMPLETING"
	jobStateCompleted   = "COMPLETED:SUCCESS"
	jobStateFailed      = "COMPLETED:ERROR"
	jobStateCheckFailed = "CHECK FAIL"
)

// ActionOperator holds function allowing to execute an action
type ActionOperator struct {
}

type actionData struct {
	job      *pycompssJob
	taskID   string
	nodeName string
	vaultID  string
}

// ExecAction allows to execute and action
func (o *ActionOperator) ExecAction(ctx context.Context, cfg config.Configuration, taskID, deploymentID string, action *prov.Action) (bool, error) {
	log.Debugf("Execute Action with ID:%q, taskID:%q, deploymentID:%q", action.ID, taskID, deploymentID)

	if action.ActionType == PyCOMPSsJobMonitoringActionType {
		return o.monitorJob(ctx, cfg, deploymentID, action)
	}

	return true, fmt.Errorf("unsupported actionType %q", action.ActionType)
}

func (o *ActionOperator) monitorJob(ctx context.Context, cfg config.Configuration, deploymentID string, action *prov.Action) (bool, error) {
	var (
		err        error
		deregister bool
		ok         bool
	)

	actionData := &actionData{}
	// Check nodeName
	actionData.nodeName, ok = action.Data["nodeName"]
	if !ok {
		return true, fmt.Errorf("missing mandatory information nodeName for actionType: %q", action.ActionType)
	}
	// Check jobID
	jobStr, ok := action.Data["job"]
	if !ok {
		return true, fmt.Errorf("missing mandatory information job for actionType: %q", action.ActionType)
	}
	actionData.job = new(pycompssJob)
	err = json.Unmarshal([]byte(jobStr), actionData.job)
	if err != nil {
		return true, fmt.Errorf("unexpected Job ID value %q for deployment %s node %s: %w", jobStr, deploymentID, actionData.nodeName, err)
	}

	// Check taskID
	actionData.taskID, ok = action.Data["taskID"]
	if !ok {
		return true, fmt.Errorf("missing mandatory information taskID for actionType:%q", action.ActionType)
	}
	// Check vaultID
	actionData.vaultID, ok = action.Data["vaultID"]
	if !ok {
		return true, fmt.Errorf("missing mandatory information vaultID for actionType:%q", action.ActionType)
	}

	privateKeyVaultSecret, err := getPrivateKeyFromVaultID(actionData.vaultID)
	if err != nil {
		return true, err
	}
	agent, err := setupSSHAgent(ctx, privateKeyVaultSecret)
	if err != nil {
		return true, err
	}
	defer agent.Stop()

	status, err := o.monitorJobStatus(ctx, agent, actionData)
	if err != nil {
		events.WithContextOptionalFields(ctx).NewLogEntry(events.LogLevelWARN, deploymentID).Registerf(
			"Failed to monitor Job %q, error %s", actionData.nodeName, err.Error())
		return false, err
	}
	var finalError *multierror.Error
	switch status {
	case jobStateRunning, jobStatePending, jobStateCompleting:
		// Nothing to do here
	case jobStateCompleted:
		deregister = true
	case jobStateFailed:
		deregister = true
		finalError = multierror.Append(finalError, fmt.Errorf("job %q with id: %q ended in error", actionData.nodeName, actionData.job.JobInfo.JobID))
	case jobStateCheckFailed:
		events.WithContextOptionalFields(ctx).NewLogEntry(events.LogLevelWARN, deploymentID).Registerf(
			"PyCOMPSs failed to retrieve job %q status", actionData.nodeName)
		return false, nil
	}
	err = tasks.SetTaskData(action.AsyncOperation.TaskID, fmt.Sprintf("pycompssjobstatus/%s", action.AsyncOperation.NodeName), status)
	if err != nil {
		finalError = multierror.Append(finalError, err)
		return deregister, finalError
	}
	err = deployments.SetInstanceStateStringWithContextualLogs(ctx, deploymentID, actionData.nodeName, "0", status)
	if err != nil {
		finalError = multierror.Append(finalError, err)
	}
	// TODO(loicalbertin) get logs
	return deregister, finalError.ErrorOrNil()
}

var reJobStatus = regexp.MustCompile(`(PENDING|RUNNING|COMPLETING|COMPLETED:SUCCESS|COMPLETED:ERROR|CHECK FAIL)`)

func (o *ActionOperator) monitorJobStatus(ctx context.Context, agent *sshutil.SSHAgent, actionData *actionData) (string, error) {

	cmd := executil.Command(ctx, "pycompss", "env", "change", actionData.job.JobInfo.EnvironmentID)
	cmd.Env = append(cmd.Env, fmt.Sprintf("SSH_AUTH_SOCK=%s", agent.Socket))
	err := cmd.Run()
	if err != nil {
		return "", fmt.Errorf("failed to execute pycompss command to change to env %s: %w", actionData.job.JobInfo.EnvironmentID, err)
	}

	cmd = executil.Command(ctx, "pycompss", "job", "status", actionData.job.JobInfo.JobID)
	cmd.Env = append(cmd.Env, fmt.Sprintf("SSH_AUTH_SOCK=%s", agent.Socket))

	stdout, err := cmd.Output()
	if err != nil {
		return "", fmt.Errorf("failed to execute pycompss command to retrieve status: %w", err)
	}

	subMatches := reJobStatus.FindStringSubmatch(string(stdout))
	if subMatches == nil || len(subMatches) != 2 {
		return "", fmt.Errorf("fail to retrieve PyCOMPSs job status in command return: %s", stdout)
	}
	return subMatches[1], nil
}
