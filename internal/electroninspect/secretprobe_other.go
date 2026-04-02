//go:build !darwin && !linux && !windows

package electroninspect

import "github.com/Code-Hex/browsercookie/internal/browsercfg"

func probeSecretLocations(browsercfg.ChromiumSpec, []string) []Location {
	return nil
}
