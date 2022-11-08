package main

import (
	"embed"
	"errors"
	"fmt"
)

// content holds TOSCA definitions content.
//
//go:embed tosca/yorc/*.yaml
var content embed.FS

// Get TOSCA types bundled in binary
func getToscaResources() (map[string][]byte, error) {

	entries, err := content.ReadDir("tosca/yorc")
	if err != nil {
		return nil, fmt.Errorf("error reading embedded TOSCA resources: %w", err)
	}
	resources := make(map[string][]byte)
	for _, entry := range entries {
		if !entry.IsDir() {
			entryPath := "tosca/yorc/" + entry.Name()
			fc, err := content.ReadFile(entryPath)
			if err != nil {
				return nil, fmt.Errorf("error reading embedded TOSCA resource %q: %w", entryPath, err)
			}
			resources[entry.Name()] = fc
		}
	}

	if len(resources) == 0 {
		return nil, errors.New("expecting embedded TOSCA resources but none found")
	}
	return resources, nil

}
