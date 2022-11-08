package job

import (
	"time"

	"github.com/hashicorp/consul/api"
	"github.com/ystia/yorc/v4/config"
	"github.com/ystia/yorc/v4/prov"
	"github.com/ystia/yorc/v4/prov/operations"
	"github.com/ystia/yorc/v4/vault"
)

//go:generate tdt2go -m org\.eflows4hpc\.pycompss\.plugin\.types\.(.*)=$DOLLAR{1} -f struct_tosca_gen.go ../tosca/yorc/types.yaml

type jobInfo struct {
	EnvironmentID string `json:"environment_id,omitempty"`
	AppName       string `json:"app_name,omitempty"`
	JobID         string `json:"job_id,omitempty"`
}

// Execution holds job Execution properties
type Execution struct {
	KV                     *api.KV
	Cfg                    config.Configuration
	DeploymentID           string
	TaskID                 string
	NodeName               string
	Operation              prov.Operation
	MonitoringTimeInterval time.Duration
	EnvInputs              []*operations.EnvInput
	VarInputsNames         []string
	privateKeyVaultSecret  vault.Secret
	vaultID                string
}

type pycompssJobParams struct {
	SubmissionParams  SubmissionParams  `json:"submission_params,omitempty"`
	Environment       Environment       `json:"environment,omitempty"`
	CompssApplication COMPSsApplication `json:"compss_application,omitempty"`
	ExtraEnv          map[string]string `json:"extra_env,omitempty"`
}

type pycompssJob struct {
	JobInfo   *jobInfo           `json:"job_info,omitempty"`
	JobParams *pycompssJobParams `json:"job_params,omitempty"`
}
