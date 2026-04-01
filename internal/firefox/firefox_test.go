package firefox

import (
	"database/sql"
	"encoding/json"
	"net/http"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/pierrec/lz4/v4"
	_ "modernc.org/sqlite"
)

func TestLoaderLoadResolvesDefaultProfileAndMergesSessionStore(t *testing.T) {
	t.Parallel()

	root := t.TempDir()
	profileDir := filepath.Join(root, "Profiles", "default-release")
	if err := os.MkdirAll(filepath.Join(profileDir, "sessionstore-backups"), 0o755); err != nil {
		t.Fatalf("MkdirAll() error = %v", err)
	}

	profilesINI := filepath.Join(root, "profiles.ini")
	if err := os.WriteFile(profilesINI, []byte(`
[Install123]
Default=Profiles/default-release

[Profile0]
Name=default-release
IsRelative=1
Path=Profiles/default-release
Default=1
`), 0o644); err != nil {
		t.Fatalf("WriteFile(profiles.ini) error = %v", err)
	}

	cookieFile := filepath.Join(profileDir, "cookies.sqlite")
	expires := time.Unix(1_700_000_000, 0).UTC()
	writeFirefoxDB(t, cookieFile, expires)

	sessionFile := filepath.Join(profileDir, "sessionstore-backups", "recovery.jsonlz4")
	writeSessionLZ4(t, sessionFile, sessionStore{
		Cookies: []sessionCookie{
			{
				Host:   ".session.test",
				Path:   "/",
				Name:   "session",
				Value:  "from-session",
				Secure: true,
			},
		},
	})

	loader := NewLoader()
	cookies, err := loader.Load(Browser{Name: "firefox", ProfilePatterns: []string{profilesINI}}, nil)
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}
	if len(cookies) != 2 {
		t.Fatalf("len(cookies) = %d, want 2", len(cookies))
	}

	persistent := findCookie(cookies, "persistent")
	if persistent == nil || persistent.Value != "from-sqlite" || !persistent.HttpOnly {
		t.Fatalf("persistent cookie = %#v", persistent)
	}
	if !persistent.Expires.Equal(expires) {
		t.Fatalf("persistent expiry = %v, want %v", persistent.Expires, expires)
	}
	session := findCookie(cookies, "session")
	if session == nil || session.Value != "from-session" || !session.Secure {
		t.Fatalf("session cookie = %#v", session)
	}
}

func TestParseProfileFallsBackToDefaultSection(t *testing.T) {
	t.Parallel()

	root := t.TempDir()
	profilesINI := filepath.Join(root, "profiles.ini")
	if err := os.WriteFile(profilesINI, []byte(`
[Profile0]
Name=default
IsRelative=1
Path=Profiles/default-release
Default=1
`), 0o644); err != nil {
		t.Fatalf("WriteFile() error = %v", err)
	}

	got, err := parseProfile(profilesINI)
	if err != nil {
		t.Fatalf("parseProfile() error = %v", err)
	}
	want := filepath.Join(root, "Profiles", "default-release")
	if got != want {
		t.Fatalf("parseProfile() = %q, want %q", got, want)
	}
}

func TestParseProfileAcceptsBrowserRootDirectory(t *testing.T) {
	t.Parallel()

	root := t.TempDir()
	profilesINI := filepath.Join(root, "profiles.ini")
	if err := os.WriteFile(profilesINI, []byte(`
[Profile0]
Name=default
IsRelative=1
Path=Profiles/default-release
Default=1
`), 0o644); err != nil {
		t.Fatalf("WriteFile() error = %v", err)
	}

	got, err := parseProfile(root)
	if err != nil {
		t.Fatalf("parseProfile() error = %v", err)
	}
	want := filepath.Join(root, "Profiles", "default-release")
	if got != want {
		t.Fatalf("parseProfile() = %q, want %q", got, want)
	}
}

func writeFirefoxDB(t *testing.T, path string, expiry time.Time) {
	t.Helper()

	db, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatalf("sql.Open() error = %v", err)
	}
	defer func() { _ = db.Close() }()

	if _, err := db.Exec(`CREATE TABLE moz_cookies (
		host TEXT,
		path TEXT,
		isSecure INTEGER,
		expiry INTEGER,
		name TEXT,
		value TEXT,
		isHttpOnly INTEGER
	)`); err != nil {
		t.Fatalf("create moz_cookies error = %v", err)
	}
	if _, err := db.Exec(`INSERT INTO moz_cookies(host, path, isSecure, expiry, name, value, isHttpOnly) VALUES(?, ?, ?, ?, ?, ?, ?)`,
		".sqlite.test", "/", 1, expiry.Unix(), "persistent", "from-sqlite", 1); err != nil {
		t.Fatalf("insert moz_cookies error = %v", err)
	}
}

func writeSessionLZ4(t *testing.T, path string, payload sessionStore) {
	t.Helper()

	raw, err := json.Marshal(payload)
	if err != nil {
		t.Fatalf("json.Marshal() error = %v", err)
	}
	dst := make([]byte, lz4.CompressBlockBound(len(raw)))
	n, err := lz4.CompressBlock(raw, dst, nil)
	if err != nil {
		t.Fatalf("CompressBlock() error = %v", err)
	}
	if n == 0 {
		t.Fatal("CompressBlock() produced an incompressible block")
	}
	content := append([]byte("mozLz40\x00"), dst[:n]...)
	if err := os.WriteFile(path, content, 0o644); err != nil {
		t.Fatalf("WriteFile(session) error = %v", err)
	}
}

func findCookie(cookies []*http.Cookie, name string) *http.Cookie {
	for _, cookie := range cookies {
		if cookie.Name == name {
			return cookie
		}
	}
	return nil
}
