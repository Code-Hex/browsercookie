//go:build darwin

package electroninspect

import (
	"database/sql"
	"os"
	"path/filepath"
	"strings"
	"testing"

	_ "modernc.org/sqlite"
)

func TestInspectFindsLowercaseRootAndSecretRefOnDarwin(t *testing.T) {
	restore := newDarwinGenericPasswordProber
	newDarwinGenericPasswordProber = func() darwinGenericPasswordProber {
		return fakeDarwinProber{
			items: map[string]bool{
				"Discord Safe Storage\x00Discord": true,
			},
		}
	}
	t.Cleanup(func() {
		newDarwinGenericPasswordProber = restore
	})

	home := t.TempDir()
	t.Setenv("HOME", home)

	appPath := filepath.Join(t.TempDir(), "Discord.app")
	writeDarwinBundleFixture(t, appPath)

	root := filepath.Join(home, "Library", "Application Support", "discord")
	writeInspectCookieDB(t, filepath.Join(root, "Cookies"), "cookies")
	writeLevelDBFixture(t, filepath.Join(root, "Local Storage", "leveldb"))
	writeLevelDBFixture(t, filepath.Join(root, "Session Storage"))
	writeLevelDBFixture(t, filepath.Join(root, "WebStorage", "1", "IndexedDB", "indexeddb.leveldb"))

	report, err := Inspect("Discord", Config{
		AppPaths: []string{appPath},
	})
	if err != nil {
		t.Fatalf("Inspect() error = %v", err)
	}
	if report.ElectronVersion != "37.6.0" {
		t.Fatalf("ElectronVersion = %q, want %q", report.ElectronVersion, "37.6.0")
	}
	if report.ChromiumVersion != "138" {
		t.Fatalf("ChromiumVersion = %q, want %q", report.ChromiumVersion, "138")
	}
	if len(report.Bundles) != 1 {
		t.Fatalf("len(Bundles) = %d, want 1", len(report.Bundles))
	}
	if report.Bundles[0].PackageName != "discord" {
		t.Fatalf("PackageName = %q, want %q", report.Bundles[0].PackageName, "discord")
	}
	if !hasLocation(report.Locations, "cookies", filepath.Join(root, "Cookies")) {
		t.Fatalf("cookies location missing from %#v", report.Locations)
	}
	if !hasLocation(report.Locations, "local_storage", filepath.Join(root, "Local Storage")) {
		t.Fatalf("local storage location missing from %#v", report.Locations)
	}
	if !hasLocation(report.Locations, "session_storage", filepath.Join(root, "Session Storage")) {
		t.Fatalf("session storage location missing from %#v", report.Locations)
	}
	if !hasLocation(report.Locations, "indexeddb", filepath.Join(root, "WebStorage", "1", "IndexedDB")) {
		t.Fatalf("indexeddb location missing from %#v", report.Locations)
	}
	if !hasSecretLocation(report.Locations, "Discord Safe Storage", "Discord") {
		t.Fatalf("safe storage secret ref missing from %#v", report.Locations)
	}
	if !hasSignal(report.Signals, "uses_safe_storage") {
		t.Fatalf("uses_safe_storage signal missing from %#v", report.Signals)
	}
	if !hasSignal(report.Signals, "uses_session_from_partition") {
		t.Fatalf("uses_session_from_partition signal missing from %#v", report.Signals)
	}
	if !hasSignal(report.Signals, "overrides_user_data_path") {
		t.Fatalf("overrides_user_data_path signal missing from %#v", report.Signals)
	}
}

type fakeDarwinProber struct {
	items map[string]bool
}

func (f fakeDarwinProber) HasGenericPassword(service, account string) (bool, error) {
	return f.items[service+"\x00"+account], nil
}

func writeDarwinBundleFixture(t *testing.T, appPath string) {
	t.Helper()

	infoPlist := `<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
	<key>CFBundleIdentifier</key><string>com.hnc.Discord</string>
	<key>CFBundleName</key><string>Discord</string>
	<key>CFBundleDisplayName</key><string>Discord</string>
	<key>CFBundleExecutable</key><string>Discord</string>
</dict>
</plist>`
	frameworkPlist := `<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
	<key>CFBundleVersion</key><string>37.6.0</string>
</dict>
</plist>`

	writeTextFile(t, filepath.Join(appPath, "Contents", "Info.plist"), infoPlist)
	writeTextFile(
		t,
		filepath.Join(appPath, "Contents", "Frameworks", "Electron Framework.framework", "Versions", "A", "Resources", "Info.plist"),
		frameworkPlist,
	)
	writeASARFixture(t, filepath.Join(appPath, "Contents", "Resources", "app.asar"), map[string][]byte{
		"package.json": []byte(`{"name":"discord","productName":"Discord"}`),
		"dist/main.js": []byte(`const { app, safeStorage, session } = require("electron"); app.setPath("userData", "/tmp"); session.fromPartition("persist:discord");`),
	})
}

func writeTextFile(t *testing.T, path, contents string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatalf("MkdirAll() error = %v", err)
	}
	if err := os.WriteFile(path, []byte(contents), 0o644); err != nil {
		t.Fatalf("WriteFile() error = %v", err)
	}
}

func writeInspectCookieDB(t *testing.T, path, value string) {
	t.Helper()

	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatalf("MkdirAll() error = %v", err)
	}
	db, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatalf("sql.Open() error = %v", err)
	}
	defer func() { _ = db.Close() }()

	if _, err := db.Exec(`CREATE TABLE meta (key TEXT PRIMARY KEY, value TEXT)`); err != nil {
		t.Fatalf("create meta error = %v", err)
	}
	if _, err := db.Exec(`INSERT INTO meta(key, value) VALUES('version', '24')`); err != nil {
		t.Fatalf("insert meta error = %v", err)
	}
	if _, err := db.Exec(`CREATE TABLE cookies (host_key TEXT, path TEXT, is_secure INTEGER, expires_utc INTEGER, name TEXT, value TEXT, encrypted_value BLOB)`); err != nil {
		t.Fatalf("create cookies error = %v", err)
	}
	if _, err := db.Exec(`INSERT INTO cookies(host_key, path, is_secure, expires_utc, name, value, encrypted_value) VALUES('.example.com', '/', 1, 0, 'session', ?, X'')`, value); err != nil {
		t.Fatalf("insert cookie error = %v", err)
	}
}

func writeLevelDBFixture(t *testing.T, dir string) {
	t.Helper()

	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatalf("MkdirAll() error = %v", err)
	}
	for name := range map[string]string{
		"CURRENT":         "MANIFEST-000001\n",
		"LOCK":            "",
		"LOG":             "",
		"MANIFEST-000001": "",
		"000001.ldb":      "",
	} {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(name), 0o644); err != nil {
			t.Fatalf("WriteFile(%q) error = %v", name, err)
		}
	}
}

func hasLocation(locations []Location, kind, path string) bool {
	for _, location := range locations {
		if location.Kind == kind && strings.EqualFold(location.Path, path) && location.Status == "present" {
			return true
		}
	}
	return false
}

func hasSecretLocation(locations []Location, service, account string) bool {
	for _, location := range locations {
		if location.SecretRef == nil {
			continue
		}
		if location.SecretRef.Service == service && location.SecretRef.Account == account {
			return true
		}
	}
	return false
}

func hasSignal(signals []Signal, kind string) bool {
	for _, signal := range signals {
		if signal.Kind == kind {
			return true
		}
	}
	return false
}
