package electroninspect

import (
	"os"
	"path/filepath"
	"strings"

	"github.com/Code-Hex/browsercookie/internal/pathutil"
)

func discoverBundles(app string, explicitPaths []string) []discoveredBundle {
	paths := explicitPaths
	if len(paths) == 0 {
		paths = autoDiscoveredAppPaths(app)
	}

	seen := map[string]struct{}{}
	bundles := make([]discoveredBundle, 0, len(paths))
	for _, candidate := range paths {
		bundle, ok := loadBundle(candidate)
		if !ok {
			continue
		}
		if _, exists := seen[bundle.Path]; exists {
			continue
		}
		seen[bundle.Path] = struct{}{}
		bundles = append(bundles, bundle)
	}
	return bundles
}

func loadBundle(candidate string) (discoveredBundle, bool) {
	root := normalizeAppPath(candidate)
	if root == "" {
		return discoveredBundle{}, false
	}
	info, err := os.Stat(root)
	if err != nil {
		return discoveredBundle{}, false
	}
	if !info.IsDir() {
		root = filepath.Dir(root)
	}

	bundle := discoveredBundle{
		Bundle: Bundle{
			Path: root,
			Name: strings.TrimSuffix(filepath.Base(root), filepath.Ext(root)),
		},
		appPath: root,
	}
	enrichBundleMetadata(&bundle)
	configureBundleResources(&bundle)
	return bundle, true
}

func normalizeAppPath(candidate string) string {
	candidate = pathutil.ExpandPath(strings.TrimSpace(candidate))
	if candidate == "" {
		return ""
	}
	if idx := strings.Index(candidate, ".app"+string(filepath.Separator)); idx >= 0 {
		return candidate[:idx+4]
	}
	return candidate
}

func configureBundleResources(bundle *discoveredBundle) {
	if bundle == nil {
		return
	}
	resourceRoots := bundleResourceRoots(bundle.Path)
	for _, root := range resourceRoots {
		if root == "" {
			continue
		}
		if _, err := os.Stat(root); err == nil {
			bundle.resourcesPath = root
			break
		}
	}
	if bundle.resourcesPath == "" {
		return
	}

	for _, candidate := range []string{
		filepath.Join(bundle.resourcesPath, "app.asar"),
		filepath.Join(bundle.resourcesPath, "app", "package.json"),
		filepath.Join(bundle.resourcesPath, "package.json"),
	} {
		if _, err := os.Stat(candidate); err != nil {
			continue
		}
		if filepath.Base(candidate) == "app.asar" {
			bundle.appAsarPath = candidate
			continue
		}
	}

	if pathExists(filepath.Join(bundle.resourcesPath, "app")) {
		bundle.appDirPath = filepath.Join(bundle.resourcesPath, "app")
	}
	if pathExists(filepath.Join(bundle.resourcesPath, "app.asar.unpacked")) {
		bundle.unpackedPath = filepath.Join(bundle.resourcesPath, "app.asar.unpacked")
	}
}

func bundleResourceRoots(root string) []string {
	if strings.HasSuffix(strings.ToLower(root), ".app") {
		return []string{filepath.Join(root, "Contents", "Resources")}
	}
	return []string{
		filepath.Join(root, "resources"),
		filepath.Join(root, "Resources"),
		root,
	}
}

func pathExists(path string) bool {
	_, err := os.Stat(path)
	return err == nil
}
