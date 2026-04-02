//go:build windows

package electroninspect

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/Code-Hex/browsercookie/internal/browsercfg"
)

func TestProbeSecretLocationsWindowsReadsLocalState(t *testing.T) {
	t.Parallel()

	root := t.TempDir()
	localStatePath := filepath.Join(root, "Local State")
	if err := os.WriteFile(localStatePath, []byte(`{"os_crypt":{"encrypted_key":"legacy","app_bound_encrypted_key":"bound"}}`), 0o644); err != nil {
		t.Fatalf("WriteFile() error = %v", err)
	}

	locations := probeSecretLocations(browsercfg.ElectronSpec("Discord", []string{root}, nil), []string{root})
	if len(locations) != 2 {
		t.Fatalf("len(locations) = %d, want 2", len(locations))
	}
}
