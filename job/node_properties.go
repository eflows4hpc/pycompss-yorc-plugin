package job

import (
	"context"
	"fmt"
	"log"
	"strconv"
	"strings"

	"github.com/mitchellh/mapstructure"
	"github.com/ystia/yorc/v4/deployments"
	"github.com/ystia/yorc/v4/tasks"
)

func (e *Execution) getPropertyFromWFInputs(ctx context.Context, propertyName string, setValueFn func(value string) error) error {
	// First try to get the property name directly
	property, err := tasks.GetTaskInput(e.TaskID, propertyName)
	if err != nil && !tasks.IsTaskDataNotFoundError(err) {
		return err
	}
	if property != "" {
		err = setValueFn(property)
		if err != nil {
			return err
		}
	}

	// Then <node_name>_<property_name> can override it
	property, err = tasks.GetTaskInput(e.TaskID, fmt.Sprintf("%s_%s", e.NodeName, propertyName))
	if err != nil && !tasks.IsTaskDataNotFoundError(err) {
		return err
	}
	if property != "" {
		err = setValueFn(property)
		if err != nil {
			return err
		}
	}

	return nil
}

func (e *Execution) resolvePropertiesFromWFInputs(ctx context.Context, params *pycompssJobParams) error {

	data, err := tasks.GetAllTaskData(e.TaskID)
	if err != nil && !tasks.IsTaskDataNotFoundError(err) {
		return err
	}
	prefix := fmt.Sprintf("inputs/%s_PyCOMPSs_", e.NodeName)
	// First we add every input that is neither starting with PyCOMPSs_ nor <nodeName>_PyCOMPSs_
	for key, d := range data {
		if !strings.HasPrefix(key, "inputs/PyCOMPSs_") && !strings.HasPrefix(key, prefix) {
			params.ExtraEnv[strings.TrimPrefix(key, "inputs/")] = d
		}
	}
	// Then inputs starting with PyCOMPSs_ can overwrite previously set inputs
	for key, d := range data {
		if strings.HasPrefix(key, "inputs/PyCOMPSs_") {
			params.ExtraEnv[strings.TrimPrefix(key, "inputs/PyCOMPSs_")] = d
		}
	}
	// Then inputs starting with <nodeName>_PyCOMPSs_ can overwrite any previously set inputs
	for key, d := range data {

		if strings.HasPrefix(key, prefix) {
			params.ExtraEnv[strings.TrimPrefix(key, prefix)] = d
		}
	}

	err = e.getPropertyFromWFInputs(ctx, "qos", func(value string) error {
		params.SubmissionParams.Qos = value
		return nil
	})
	if err != nil {
		return err
	}

	err = e.getPropertyFromWFInputs(ctx, "extra_compss_opts", func(value string) error {
		params.SubmissionParams.ExtraCompssOpts = value
		return nil
	})
	if err != nil {
		return err
	}

	err = e.getPropertyFromWFInputs(ctx, "endpoint", func(value string) error {
		params.Environment.Endpoint = value
		return nil
	})
	if err != nil {
		return err
	}

	err = e.getPropertyFromWFInputs(ctx, "user_id", func(value string) error {
		params.Environment.UserName = value
		return nil
	})
	if err != nil {
		return err
	}

	err = e.getPropertyFromWFInputs(ctx, "user", func(value string) error {
		params.Environment.UserName = value
		return nil
	})
	if err != nil {
		return err
	}

	err = e.getPropertyFromWFInputs(ctx, "num_nodes", func(value string) error {
		nn, err := strconv.Atoi(value)
		if err != nil {
			return fmt.Errorf("invalid value for num_nodes input: %w", err)
		}
		params.SubmissionParams.NumNodes = nn
		return nil
	})

	return err
}

func (e *Execution) resolveNodeProperties(ctx context.Context, pcJob *pycompssJob) error {

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
		pcJob.JobParams.Environment = env
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
		pcJob.JobParams.SubmissionParams = subParams
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
		pcJob.JobParams.CompssApplication = app
	}

	rawKeepEnv, err := deployments.GetNodePropertyValue(ctx, e.DeploymentID, e.NodeName, "keep_environment")
	if err != nil {
		return err
	}
	if rawKeepEnv != nil && rawKeepEnv.RawString() != "" {
		pcJob.KeepEnvironment, err = strconv.ParseBool(rawKeepEnv.RawString())
		if err != nil {
			return fmt.Errorf("fail to parse boolean value %q for node %q: %w", rawKeepEnv.String(), e.NodeName, err)
		}
	}
	return nil
}

func (e *Execution) getContainerImageFromRequirement(ctx context.Context, params *pycompssJobParams) error {
	targetNode, err := deployments.GetTargetNodeForRequirementByName(ctx, e.DeploymentID, e.NodeName, "img_transfer")
	if err != nil {
		return err
	}
	if targetNode != "" {
		log.Printf("found target node of img_transfer requirement %s", targetNode)
		containerImage, err := tasks.GetTaskData(e.TaskID, fmt.Sprintf("operation_outputs/%s-tosca.interfaces.node.lifecycle.runnable.submit-0-image_file_path", targetNode))
		if err != nil && !tasks.IsTaskDataNotFoundError(err) {
			return err
		}
		if containerImage != "" {
			log.Printf("found container image from task data %s", containerImage)
			params.CompssApplication.ContainerOpts.ContainerImage = containerImage
			return nil
		}
		// not found here let's try to access the node attribute
		containerImageValue, err := deployments.GetInstanceAttributeValue(ctx, e.DeploymentID, targetNode, "0", "image_file_path_start")
		if err != nil {
			return err
		}
		if containerImageValue != nil && containerImageValue.RawString() != "" {
			log.Printf("found container image from target node attribute (start operation): %s", containerImageValue.RawString())
			params.CompssApplication.ContainerOpts.ContainerImage = containerImageValue.RawString()
		}

		containerImageValue, err = deployments.GetInstanceAttributeValue(ctx, e.DeploymentID, targetNode, "0", "image_file_path_submit")
		if err != nil {
			return err
		}
		if containerImageValue != nil && containerImageValue.RawString() != "" {
			log.Printf("found container image from target node attribute (submit operation): %s", containerImageValue.RawString())
			params.CompssApplication.ContainerOpts.ContainerImage = containerImageValue.RawString()
		}

	}
	return nil
}

func (e *Execution) resolvePropertiesFromEnvRequirement(ctx context.Context, params *pycompssJobParams) error {
	targetNode, err := deployments.GetTargetNodeForRequirementByName(ctx, e.DeploymentID, e.NodeName, "environment")
	if err != nil {
		return err
	}
	if targetNode != "" {
		log.Printf("found target node of environment requirement %s", targetNode)

		endpoint, err := deployments.GetInstanceAttributeValue(ctx, e.DeploymentID, targetNode, "0", "cluster_login_host")
		if err != nil {
			return err
		}
		if endpoint != nil && endpoint.RawString() != "" {
			log.Printf("found environment endpoint from target node attribute: %s", endpoint.RawString())
			params.Environment.Endpoint = endpoint.RawString()
		}

		pycompssModules, err := deployments.GetInstanceAttributeValue(ctx, e.DeploymentID, targetNode, "0", "pycompss_modules")
		if err != nil {
			return err
		}
		if pycompssModules != nil && pycompssModules.RawString() != "" {
			log.Printf("found environment pycompss_modules from target node attribute: %s", pycompssModules.RawString())
			params.SubmissionParams.CompssModules = strings.Split(pycompssModules.RawString(), ",")
		}

	}
	return nil
}
