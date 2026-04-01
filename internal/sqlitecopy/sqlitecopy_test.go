package sqlitecopy

import (
	"database/sql"
	"os"
	"testing"

	_ "modernc.org/sqlite"
)

func TestCopyPreservesWALSidecars(t *testing.T) {
	t.Parallel()

	path := t.TempDir() + "/cookies.sqlite"
	db, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatalf("sql.Open() error = %v", err)
	}
	defer func() { _ = db.Close() }()

	if _, err := db.Exec(`PRAGMA journal_mode=WAL`); err != nil {
		t.Fatalf("set WAL mode error = %v", err)
	}
	if _, err := db.Exec(`PRAGMA wal_autocheckpoint=0`); err != nil {
		t.Fatalf("disable WAL autocheckpoint error = %v", err)
	}
	if _, err := db.Exec(`CREATE TABLE cookies (name TEXT)`); err != nil {
		t.Fatalf("create table error = %v", err)
	}
	if _, err := db.Exec(`INSERT INTO cookies(name) VALUES('fresh')`); err != nil {
		t.Fatalf("insert cookie error = %v", err)
	}
	if _, err := os.Stat(path + "-wal"); err != nil {
		t.Fatalf("WAL sidecar missing: %v", err)
	}

	tmpPath, cleanup, err := Copy(path)
	if err != nil {
		t.Fatalf("Copy() error = %v", err)
	}
	defer func() {
		if err := cleanup(); err != nil {
			t.Fatalf("cleanup() error = %v", err)
		}
	}()

	if _, err := os.Stat(tmpPath + "-wal"); err != nil {
		t.Fatalf("copied WAL sidecar missing: %v", err)
	}

	copiedDB, err := sql.Open("sqlite", tmpPath)
	if err != nil {
		t.Fatalf("sql.Open(copied) error = %v", err)
	}
	defer func() { _ = copiedDB.Close() }()

	var got string
	if err := copiedDB.QueryRow(`SELECT name FROM cookies`).Scan(&got); err != nil {
		t.Fatalf("query copied db error = %v", err)
	}
	if got != "fresh" {
		t.Fatalf("copied row = %q, want %q", got, "fresh")
	}
}
