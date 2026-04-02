//go:build darwin

package electroninspect

import (
	"encoding/json"
	"os/exec"
	"path/filepath"
	"strings"

	"github.com/Code-Hex/browsercookie/internal/pathutil"
)

type darwinInfoPlist struct {
	BundleID           string `json:"CFBundleIdentifier"`
	Name               string `json:"CFBundleName"`
	DisplayName        string `json:"CFBundleDisplayName"`
	Executable         string `json:"CFBundleExecutable"`
	BundleVersion      string `json:"CFBundleVersion"`
	ShortVersionString string `json:"CFBundleShortVersionString"`
}

func autoDiscoveredAppPaths(app string) []string {
	app = strings.TrimSpace(app)
	if app == "" {
		return nil
	}

	var matches []string
	for _, base := range []string{"/Applications", "~/Applications"} {
		base = pathutil.ExpandPath(base)
		candidates, err := filepath.Glob(filepath.Join(base, "*.app"))
		if err != nil {
			continue
		}
		for _, candidate := range candidates {
			plist, ok := readDarwinInfoPlist(filepath.Join(candidate, "Contents", "Info.plist"))
			if !ok {
				continue
			}
			if !matchesBundleQuery(app, candidate, plist) {
				continue
			}
			matches = append(matches, candidate)
		}
	}
	return uniqueNonEmptyStrings(matches)
}

func enrichBundleMetadata(bundle *discoveredBundle) {
	if bundle == nil {
		return
	}
	plistPath := filepath.Join(bundle.Path, "Contents", "Info.plist")
	plist, ok := readDarwinInfoPlist(plistPath)
	if !ok {
		return
	}
	if plist.BundleID != "" {
		bundle.BundleID = plist.BundleID
	}
	if plist.Name != "" {
		bundle.Name = plist.Name
	}
	if plist.DisplayName != "" {
		bundle.DisplayName = plist.DisplayName
	}
	if version := readElectronFrameworkVersion(bundle.Path); version != "" {
		bundle.ElectronVersion = version
	}
}

func readDarwinInfoPlist(path string) (darwinInfoPlist, bool) {
	cmd := exec.Command("/usr/bin/plutil", "-convert", "json", "-o", "-", path)
	out, err := cmd.Output()
	if err != nil {
		return darwinInfoPlist{}, false
	}
	var plist darwinInfoPlist
	if err := json.Unmarshal(out, &plist); err != nil {
		return darwinInfoPlist{}, false
	}
	return plist, true
}

func matchesBundleQuery(app, bundlePath string, plist darwinInfoPlist) bool {
	candidates := []string{
		strings.TrimSuffix(filepath.Base(bundlePath), ".app"),
		plist.Name,
		plist.DisplayName,
		plist.Executable,
	}
	if plist.BundleID != "" {
		parts := strings.Split(plist.BundleID, ".")
		candidates = append(candidates, parts[len(parts)-1])
	}
	for _, candidate := range candidates {
		if strings.EqualFold(strings.TrimSpace(candidate), app) {
			return true
		}
	}
	return false
}

func readElectronFrameworkVersion(bundlePath string) string {
	plistPath := filepath.Join(
		bundlePath,
		"Contents",
		"Frameworks",
		"Electron Framework.framework",
		"Versions",
		"A",
		"Resources",
		"Info.plist",
	)
	plist, ok := readDarwinInfoPlist(plistPath)
	if !ok {
		return ""
	}
	if plist.BundleVersion != "" {
		return plist.BundleVersion
	}
	return plist.ShortVersionString
}
