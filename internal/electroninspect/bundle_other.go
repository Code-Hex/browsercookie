//go:build !darwin

package electroninspect

func autoDiscoveredAppPaths(string) []string {
	return nil
}

func enrichBundleMetadata(*discoveredBundle) {}
