//go:build darwin

package browsercookie

import (
	"os"
	"path/filepath"
	"testing"
)

func TestInspectElectronAuthStorageUsesExplicitPaths(t *testing.T) {
	root := t.TempDir()
	writePlainCookieDB(t, filepath.Join(root, "Cookies"), nil)

	appPath := filepath.Join(t.TempDir(), "Discord.app")
	writeElectronAppFixture(t, appPath)

	report, err := InspectElectronAuthStorage(
		"Discord",
		WithElectronAppPaths(appPath),
		WithElectronSessionRoots(root),
	)
	if err != nil {
		t.Fatalf("InspectElectronAuthStorage() error = %v", err)
	}
	if len(report.Bundles) != 1 {
		t.Fatalf("len(Bundles) = %d, want 1", len(report.Bundles))
	}
	if report.Bundles[0].PackageName != "discord" {
		t.Fatalf("PackageName = %q, want %q", report.Bundles[0].PackageName, "discord")
	}
	if !reportHasLocation(report, "cookies", filepath.Join(root, "Cookies")) {
		t.Fatalf("cookies location missing from %#v", report.Locations)
	}
}

func writeElectronAppFixture(t *testing.T, appPath string) {
	t.Helper()

	infoPlist := `<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
	<key>CFBundleIdentifier</key><string>com.hnc.Discord</string>
	<key>CFBundleName</key><string>Discord</string>
	<key>CFBundleDisplayName</key><string>Discord</string>
</dict>
</plist>`
	packageJSON := `{"name":"discord","productName":"Discord"}`

	for path, contents := range map[string]string{
		filepath.Join(appPath, "Contents", "Info.plist"):                       infoPlist,
		filepath.Join(appPath, "Contents", "Resources", "app", "package.json"): packageJSON,
		filepath.Join(appPath, "Contents", "Resources", "app", "main.js"):      `const { safeStorage } = require("electron")`,
	} {
		if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
			t.Fatalf("MkdirAll() error = %v", err)
		}
		if err := os.WriteFile(path, []byte(contents), 0o644); err != nil {
			t.Fatalf("WriteFile() error = %v", err)
		}
	}
}

func reportHasLocation(report *ElectronAuthReport, kind, path string) bool {
	for _, location := range report.Locations {
		if location.Kind == kind && location.Path == path && location.Status == "present" {
			return true
		}
	}
	return false
}
