package control

import (
	"sort"
	"strings"

	"github.com/c2xorc4/mimic/internal/config"
)

// ProfileCatalog lists OS profiles available to the running instance.
type ProfileCatalog struct {
	Names    []string            `json:"names"`
	Families map[string][]string `json:"families"`
}

// ListProfiles loads profile names from profilesDir using the same layout as mimic run.
func ListProfiles(profilesDir string) (ProfileCatalog, error) {
	pm := config.NewProfileManager(profilesDir)
	if err := pm.LoadAllProfiles(); err != nil {
		return ProfileCatalog{}, err
	}
	grouped := pm.ListProfiles()
	names := pm.ListProfileNames()
	sort.Strings(names)
	for family := range grouped {
		sort.Strings(grouped[family])
	}
	// Normalize family keys to lowercase for stable JSON.
	families := make(map[string][]string, len(grouped))
	for family, list := range grouped {
		families[strings.ToLower(family)] = list
	}
	return ProfileCatalog{Names: names, Families: families}, nil
}