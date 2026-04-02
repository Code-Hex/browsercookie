//go:build windows

package electroninspect

import (
	"encoding/json"
	"os"
	"path/filepath"

	"github.com/Code-Hex/browsercookie/internal/browsercfg"
	"github.com/Code-Hex/browsercookie/internal/pathutil"
)

type windowsLocalState struct {
	OSCrypt struct {
		EncryptedKey         string `json:"encrypted_key"`
		AppBoundEncryptedKey string `json:"app_bound_encrypted_key"`
	} `json:"os_crypt"`
}

func probeSecretLocations(spec browsercfg.ChromiumSpec, sessionRoots []string) []Location {
	allowed := map[string]struct{}{}
	for _, source := range spec.WindowsKeySources("windows") {
		allowed[string(source)] = struct{}{}
	}
	if len(allowed) == 0 {
		allowed[string(browsercfg.WindowsEncryptedKey)] = struct{}{}
		allowed[string(browsercfg.WindowsAppBoundEncryptedKey)] = struct{}{}
	}

	var locations []Location
	for _, root := range uniqueNonEmptyStrings(sessionRoots) {
		localStatePath := filepath.Join(pathutil.ExpandPath(root), "Local State")
		state, ok := readWindowsLocalState(localStatePath)
		if !ok {
			continue
		}
		if state.OSCrypt.EncryptedKey != "" {
			if _, ok := allowed[string(browsercfg.WindowsEncryptedKey)]; ok {
				locations = append(locations, Location{
					Kind:   "safe_storage",
					Status: "present",
					Scope:  "app",
					Path:   localStatePath,
					Format: "local_state",
					SecretRef: &SecretRef{
						Source: string(browsercfg.WindowsEncryptedKey),
					},
					Evidence: []string{"Local State contains encrypted_key"},
				})
			}
		}
		if state.OSCrypt.AppBoundEncryptedKey != "" {
			if _, ok := allowed[string(browsercfg.WindowsAppBoundEncryptedKey)]; ok {
				locations = append(locations, Location{
					Kind:   "safe_storage",
					Status: "present",
					Scope:  "app",
					Path:   localStatePath,
					Format: "local_state",
					SecretRef: &SecretRef{
						Source: string(browsercfg.WindowsAppBoundEncryptedKey),
					},
					Evidence: []string{"Local State contains app_bound_encrypted_key"},
				})
			}
		}
	}
	return locations
}

func readWindowsLocalState(path string) (windowsLocalState, bool) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return windowsLocalState{}, false
	}
	var state windowsLocalState
	if err := json.Unmarshal(raw, &state); err != nil {
		return windowsLocalState{}, false
	}
	return state, true
}
