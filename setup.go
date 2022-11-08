package main

import (
	"sync"

	"github.com/ystia/yorc/v4/config"
	"github.com/ystia/yorc/v4/deployments"
	"github.com/ystia/yorc/v4/registry"

	// Registering hashicorp vault client builder in registry
	_ "github.com/ystia/yorc/v4/vault/hashivault"
)

var setupOnce sync.Once

func setup(cfg config.Configuration) {

	setupOnce.Do(func() {
		vaultCB, err := registry.GetRegistry().GetVaultClientBuilder("hashicorp")
		if err != nil {
			panic(err)
		}
		vaultClient, err := vaultCB.BuildClient(cfg)
		if err != nil {
			panic(err)
		}

		deployments.DefaultVaultClient = vaultClient

	})
}
