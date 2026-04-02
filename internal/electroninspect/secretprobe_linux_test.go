//go:build linux

package electroninspect

import (
	"errors"
	"testing"

	"github.com/Code-Hex/browsercookie/internal/browsercfg"
)

func TestProbeSecretLocationsLinuxUsesExactMatchRefs(t *testing.T) {
	t.Parallel()

	restore := newLinuxKeyringProber
	newLinuxKeyringProber = func() (linuxKeyringProber, error) {
		return fakeLinuxProber{
			secrets: map[string]bool{
				"chrome_libsecret_os_crypt_password_v2|Code": true,
			},
		}, nil
	}
	t.Cleanup(func() {
		newLinuxKeyringProber = restore
	})

	locations := probeSecretLocations(browsercfg.ElectronSpec("Code", nil, []string{"Code"}), nil)
	if len(locations) == 0 {
		t.Fatal("probeSecretLocations() returned no locations")
	}
	if locations[0].SecretRef == nil || locations[0].SecretRef.Schema != "chrome_libsecret_os_crypt_password_v2" {
		t.Fatalf("locations[0] = %#v", locations[0])
	}
}

type fakeLinuxProber struct {
	secrets map[string]bool
}

func (f fakeLinuxProber) HasSecret(schema, application string) (bool, error) {
	return f.secrets[schema+"|"+application], nil
}

func (f fakeLinuxProber) HasKWalletEntry(string, string) (bool, error) {
	return false, errors.New("not found")
}
