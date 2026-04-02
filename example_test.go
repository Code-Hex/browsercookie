package browsercookie_test

import (
	"database/sql"
	"fmt"
	"os"
	"path/filepath"

	"github.com/Code-Hex/browsercookie"
	_ "modernc.org/sqlite"
)

func ExampleInspectElectronAuthStorage() {
	root, err := os.MkdirTemp("", "browsercookie-example-*")
	if err != nil {
		panic(err)
	}
	defer func() { _ = os.RemoveAll(root) }()

	if err := writeExampleCookieDB(filepath.Join(root, "Cookies")); err != nil {
		panic(err)
	}

	report, err := browsercookie.InspectElectronAuthStorage(
		"DemoApp",
		browsercookie.WithElectronSessionRoots(root),
	)
	if err != nil {
		panic(err)
	}

	for _, location := range report.Locations {
		if location.Kind != "cookies" || location.Status != "present" {
			continue
		}
		fmt.Printf("%s %s %s %s\n", location.Kind, location.Status, location.Scope, location.Format)
	}

	// Output:
	// cookies present default sqlite
}

func writeExampleCookieDB(path string) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}

	db, err := sql.Open("sqlite", path)
	if err != nil {
		return err
	}
	defer func() { _ = db.Close() }()

	if _, err := db.Exec(`CREATE TABLE meta (key TEXT PRIMARY KEY, value TEXT)`); err != nil {
		return err
	}
	if _, err := db.Exec(`INSERT INTO meta(key, value) VALUES('version', '24')`); err != nil {
		return err
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
		return err
	}

	return nil
}
