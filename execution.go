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

package main

import (
	"context"
	"fmt"
	"strconv"
	"time"

	"github.com/ystia/yorc/v4/config"
	"github.com/ystia/yorc/v4/deployments"
	"github.com/ystia/yorc/v4/prov"

	"github.com/eflows4hpc/pycompss-yorc-plugin/job"
)

const (
	pycompssJobType = "org.eflows4hpc.pycompss.plugin.nodes.PyCOMPSJob"
)

// Execution is the interface holding functions to execute an operation
type Execution interface {
	ResolveExecution(ctx context.Context) error
	ExecuteAsync(ctx context.Context) (*prov.Action, time.Duration, error)
	Execute(ctx context.Context) error
}

func newExecution(ctx context.Context, cfg config.Configuration, taskID, deploymentID, nodeName string, operation prov.Operation) (Execution, error) {

	consulClient, err := cfg.GetConsulClient()
	if err != nil {
		return nil, err
	}
	kv := consulClient.KV()

	var exec Execution

	nodeType, err := deployments.GetNodeType(ctx, deploymentID, nodeName)
	if err != nil {
		return exec, err
	}

	isJob, err := deployments.IsTypeDerivedFrom(ctx, deploymentID, nodeType, pycompssJobType)
	if err != nil {
		return exec, err
	}
	if !isJob {
		return exec, fmt.Errorf("unsupported type %q for node %q", nodeType, nodeName)
	}

	ids, err := deployments.GetNodeInstancesIds(ctx, deploymentID, nodeName)
	if err != nil {
		return exec, err
	}

	if len(ids) == 0 {
		return exec, fmt.Errorf("found no instance for node %s in deployment %s", nodeName, deploymentID)
	}

	strVal, err := deployments.GetStringNodePropertyValue(ctx, deploymentID, nodeName, "monitoringTimeInterval")
	if err != nil {
		return exec, err
	}
	var monitoringTimeInterval time.Duration
	monitoringTimeInterval = 10 * time.Second
	if len(strVal) > 0 {
		monitoringIntervalInSeconds, err := strconv.Atoi(strVal)
		if err != nil {
			return exec, err
		}
		monitoringTimeInterval = time.Duration(monitoringIntervalInSeconds) * time.Second
	}

	exec = &job.Execution{
		KV:                     kv,
		Cfg:                    cfg,
		DeploymentID:           deploymentID,
		TaskID:                 taskID,
		NodeName:               nodeName,
		Operation:              operation,
		MonitoringTimeInterval: monitoringTimeInterval,
	}

	return exec, exec.ResolveExecution(ctx)

}
