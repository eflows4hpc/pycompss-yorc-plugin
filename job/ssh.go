package job

import (
	"context"

	"github.com/ystia/yorc/v4/deployments"
	"github.com/ystia/yorc/v4/helper/sshutil"
	"github.com/ystia/yorc/v4/tasks"
	"github.com/ystia/yorc/v4/vault"
)

func setupSSHAgent(ctx context.Context, privateKey vault.Secret) (*sshutil.SSHAgent, error) {

	sshAgent, err := sshutil.NewSSHAgent(ctx)
	if err != nil {
		return nil, err
	}

	err = sshAgent.AddKey(privateKey.String(), 0)
	return sshAgent, err
}

func getPrivateKeyAndVaultID(taskID string) (vault.Secret, string, error) {
	vaultID, err := tasks.GetTaskData(taskID, "inputs/vault_id")
	if err != nil {
		return nil, vaultID, err
	}
	secret, err := getPrivateKeyFromVaultID(vaultID)
	return secret, vaultID, err
}
func getPrivateKeyFromVaultID(vaultID string) (vault.Secret, error) {
	return deployments.DefaultVaultClient.GetSecret("/secret/data/ssh-credentials/"+vaultID, "data=privateKey")
}
