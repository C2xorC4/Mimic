package control

import (
	"fmt"
	"os"
	"path/filepath"
	"sort"
)

// ServiceCatalog lists service templates available to the running instance.
type ServiceCatalog struct {
	Names []string `json:"names"`
}

// ListServices discovers service directories with a manifest.yaml under servicesDir.
func ListServices(servicesDir string) (ServiceCatalog, error) {
	entries, err := os.ReadDir(servicesDir)
	if err != nil {
		return ServiceCatalog{}, fmt.Errorf("reading services dir: %w", err)
	}
	var names []string
	for _, entry := range entries {
		if !entry.IsDir() {
			continue
		}
		manifestPath := filepath.Join(servicesDir, entry.Name(), "manifest.yaml")
		if _, err := os.Stat(manifestPath); err == nil {
			names = append(names, entry.Name())
		}
	}
	sort.Strings(names)
	return ServiceCatalog{Names: names}, nil
}