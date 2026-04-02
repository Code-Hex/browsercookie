//go:build darwin

package browsercookie

import (
	"database/sql"
	"net/http"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/Code-Hex/browsercookie/internal/secrets"
	_ "modernc.org/sqlite"
)

type testSecretProvider map[string][]byte

func (p testSecretProvider) GenericPassword(service, account string) ([]byte, error) {
	password, ok := p[service+"\x00"+account]
	if !ok {
		return []byte("unused"), nil
	}
	return append([]byte(nil), password...), nil
}

func TestElectronLoadsCookiesFromExplicitSessionRoots(t *testing.T) {
	restore := chromiumSecretProvider
	chromiumSecretProvider = func() secrets.Provider {
		return testSecretProvider{
			"TestApp Safe Storage\x00TestApp": []byte("secret"),
		}
	}
	t.Cleanup(func() {
		chromiumSecretProvider = restore
	})

	root := t.TempDir()
	cookieFile := filepath.Join(root, "Cookies")
	writePlainCookieDB(t, cookieFile, []http.Cookie{
		{Name: "session", Value: "from-root", Domain: ".example.com", Path: "/", Secure: true, Expires: time.Unix(1_700_000_000, 0).UTC()},
	})

	cookies, err := Electron("TestApp",
		WithElectronSessionRoots(root),
		WithElectronKeyringNames("TestApp"),
	)
	if err != nil {
		t.Fatalf("Electron() error = %v", err)
	}
	if len(cookies) != 1 || cookies[0].Name != "session" || cookies[0].Value != "from-root" {
		t.Fatalf("cookies = %#v", cookies)
	}
}

func TestElectronWithCookieFilesOverridesDiscovery(t *testing.T) {
	restore := chromiumSecretProvider
	chromiumSecretProvider = func() secrets.Provider {
		return testSecretProvider{
			"TestApp Safe Storage\x00TestApp": []byte("secret"),
		}
	}
	t.Cleanup(func() {
		chromiumSecretProvider = restore
	})

	cookieFile := filepath.Join(t.TempDir(), "Cookies")
	writePlainCookieDB(t, cookieFile, []http.Cookie{
		{Name: "session", Value: "from-override", Domain: ".example.com", Path: "/", Secure: true, Expires: time.Unix(1_700_000_000, 0).UTC()},
	})

	cookies, err := Electron("TestApp",
		WithElectronSessionRoots(filepath.Join(t.TempDir(), "missing-root")),
		WithElectronKeyringNames("TestApp"),
		WithCookieFiles(cookieFile),
	)
	if err != nil {
		t.Fatalf("Electron() error = %v", err)
	}
	if len(cookies) != 1 || cookies[0].Value != "from-override" {
		t.Fatalf("cookies = %#v", cookies)
	}
}

func TestElectronUsesBundlePathOverridesForMetadataDiscovery(t *testing.T) {
	restore := chromiumSecretProvider
	chromiumSecretProvider = func() secrets.Provider {
		return testSecretProvider{
			"Code Safe Storage\x00Code": []byte("secret"),
		}
	}
	t.Cleanup(func() {
		chromiumSecretProvider = restore
	})

	home := t.TempDir()
	t.Setenv("HOME", home)

	root := filepath.Join(home, "Library", "Application Support", "Code")
	writePlainCookieDB(t, filepath.Join(root, "Cookies"), []http.Cookie{
		{Name: "session", Value: "from-bundle", Domain: ".example.com", Path: "/", Secure: true, Expires: time.Unix(1_700_000_000, 0).UTC()},
	})

	appPath := filepath.Join(t.TempDir(), "Code.app")
	writeElectronAppFixtureWithNames(t, appPath, "com.microsoft.VSCode", "Code", "Code", "code", "Code")

	cookies, err := Electron("Visual Studio Code", WithElectronAppPaths(appPath))
	if err != nil {
		t.Fatalf("Electron() error = %v", err)
	}
	if len(cookies) != 1 || cookies[0].Value != "from-bundle" {
		t.Fatalf("cookies = %#v", cookies)
	}
}

func writePlainCookieDB(t *testing.T, path string, cookies []http.Cookie) {
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
	if _, err := db.Exec(`INSERT INTO meta(key, value) VALUES("version", 24)`); err != nil {
		t.Fatalf("insert meta error = %v", err)
	}
	if _, err := db.Exec(`CREATE TABLE cookies (
		host_key TEXT,
		path TEXT,
		is_secure INTEGER,
		expires_utc INTEGER,
		name TEXT,
		value TEXT,
		encrypted_value BLOB
	)`); err != nil {
		t.Fatalf("create cookies error = %v", err)
	}

	for _, cookie := range cookies {
		if _, err := db.Exec(`INSERT INTO cookies(host_key, path, is_secure, expires_utc, name, value, encrypted_value) VALUES(?, ?, ?, ?, ?, ?, ?)`,
			cookie.Domain, cookie.Path, boolToInt(cookie.Secure), chromiumCookieExpires(cookie.Expires), cookie.Name, cookie.Value, []byte{}); err != nil {
			t.Fatalf("insert cookie error = %v", err)
		}
	}
}

func chromiumCookieExpires(expiry time.Time) int64 {
	const unixToNTEpochOffsetMicr = int64(11644473600 * 1_000_000)
	return expiry.UnixMicro() + unixToNTEpochOffsetMicr
}

func boolToInt(value bool) int {
	if value {
		return 1
	}
	return 0
}

func writeElectronAppFixtureWithNames(t *testing.T, appPath, bundleID, bundleName, displayName, packageName, productName string) {
	t.Helper()

	infoPlist := `<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
	<key>CFBundleIdentifier</key><string>` + bundleID + `</string>
	<key>CFBundleName</key><string>` + bundleName + `</string>
	<key>CFBundleDisplayName</key><string>` + displayName + `</string>
</dict>
</plist>`
	packageJSON := `{"name":"` + packageName + `","productName":"` + productName + `"}`

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
