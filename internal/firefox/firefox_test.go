package firefox

import (
	"database/sql"
	"encoding/json"
	"net/http"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/Code-Hex/browsercookie/internal/browsercfg"
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
	cookies, err := loader.Load(Browser{Name: "firefox", ProfilePatterns: []string{profilesINI}}, nil, nil)
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

func TestLoaderLoadFiltersSQLiteAndSessionDomains(t *testing.T) {
	t.Parallel()

	root := t.TempDir()
	profileDir := filepath.Join(root, "Profiles", "default-release")
	if err := os.MkdirAll(filepath.Join(profileDir, "sessionstore-backups"), 0o755); err != nil {
		t.Fatalf("MkdirAll() error = %v", err)
	}

	profilesINI := filepath.Join(root, "profiles.ini")
	if err := os.WriteFile(profilesINI, []byte(`
[Profile0]
Name=default-release
IsRelative=1
Path=Profiles/default-release
Default=1
`), 0o644); err != nil {
		t.Fatalf("WriteFile(profiles.ini) error = %v", err)
	}

	cookieFile := filepath.Join(profileDir, "cookies.sqlite")
	db, err := sql.Open("sqlite", cookieFile)
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
		".sqlite.test", "/", 1, time.Now().Add(time.Hour).Unix(), "sqlite", "wanted", 1); err != nil {
		t.Fatalf("insert moz_cookies wanted error = %v", err)
	}
	if _, err := db.Exec(`INSERT INTO moz_cookies(host, path, isSecure, expiry, name, value, isHttpOnly) VALUES(?, ?, ?, ?, ?, ?, ?)`,
		".other.test", "/", 1, time.Now().Add(time.Hour).Unix(), "other", "ignored", 1); err != nil {
		t.Fatalf("insert moz_cookies other error = %v", err)
	}

	sessionFile := filepath.Join(profileDir, "sessionstore-backups", "recovery.jsonlz4")
	writeSessionLZ4(t, sessionFile, sessionStore{
		Cookies: []sessionCookie{
			{
				Host:   ".sqlite.test",
				Path:   "/",
				Name:   "session",
				Value:  "wanted-session",
				Secure: true,
			},
			{
				Host:   ".other.test",
				Path:   "/",
				Name:   "other-session",
				Value:  "ignored",
				Secure: true,
			},
		},
	})

	loader := NewLoader()
	cookies, err := loader.Load(Browser{Name: "firefox", ProfilePatterns: []string{profilesINI}}, nil, []string{"SQLITE.test"})
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}
	if len(cookies) != 2 {
		t.Fatalf("len(cookies) = %d, want 2", len(cookies))
	}
	if findCookie(cookies, "other") != nil || findCookie(cookies, "other-session") != nil {
		t.Fatalf("cookies = %#v, want filtered result", cookies)
	}
}

func TestLoaderLoadTriesProfileCandidatesUntilOneWorks(t *testing.T) {
	t.Parallel()

	staleRoot := filepath.Join(t.TempDir(), "missing-profile-root")
	goodRoot := t.TempDir()
	profileDir := filepath.Join(goodRoot, "Profiles", "default-release")
	if err := os.MkdirAll(profileDir, 0o755); err != nil {
		t.Fatalf("MkdirAll() error = %v", err)
	}

	profilesINI := filepath.Join(goodRoot, "profiles.ini")
	if err := os.WriteFile(profilesINI, []byte(`
[Profile0]
Name=default
IsRelative=1
Path=Profiles/default-release
Default=1
`), 0o644); err != nil {
		t.Fatalf("WriteFile() error = %v", err)
	}

	expires := time.Unix(1_700_000_000, 0).UTC()
	writeFirefoxDB(t, filepath.Join(profileDir, "cookies.sqlite"), expires)

	loader := NewLoader()
	cookies, err := loader.Load(Browser{
		Name:            "firefox",
		ProfilePatterns: []string{staleRoot, profilesINI},
	}, nil, nil)
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}
	if findCookie(cookies, "persistent") == nil {
		t.Fatalf("cookies = %#v, want persistent cookie from second profile candidate", cookies)
	}
}

func TestLoaderLoadUsesSessionStoreWhenCookiesSQLiteIsMissing(t *testing.T) {
	t.Parallel()

	root := t.TempDir()
	profileDir := filepath.Join(root, "Profiles", "default-release")
	if err := os.MkdirAll(filepath.Join(profileDir, "sessionstore-backups"), 0o755); err != nil {
		t.Fatalf("MkdirAll() error = %v", err)
	}

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

	sessionFile := filepath.Join(profileDir, "sessionstore-backups", "recovery.jsonlz4")
	writeSessionLZ4(t, sessionFile, sessionStore{
		Cookies: []sessionCookie{
			{
				Host:   ".session-only.test",
				Path:   "/",
				Name:   "session-only",
				Value:  "from-session-store",
				Secure: true,
			},
		},
	})

	loader := NewLoader()
	cookies, err := loader.Load(Browser{
		Name:            "firefox",
		ProfilePatterns: []string{profilesINI},
	}, nil, nil)
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}

	cookie := findCookie(cookies, "session-only")
	if cookie == nil || cookie.Value != "from-session-store" {
		t.Fatalf("session-only cookie = %#v", cookie)
	}
}

func TestLoaderLoadTriesLaterSessionStoreCandidatesWithoutCookiesSQLite(t *testing.T) {
	t.Parallel()

	root := t.TempDir()
	profileDir := filepath.Join(root, "Profiles", "default-release")
	if err := os.MkdirAll(filepath.Join(profileDir, "sessionstore-backups"), 0o755); err != nil {
		t.Fatalf("MkdirAll() error = %v", err)
	}

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

	brokenSessionFile := filepath.Join(profileDir, "sessionstore-backups", "recovery.jsonlz4")
	if err := os.WriteFile(brokenSessionFile, []byte("mozLz40\x00definitely-not-lz4"), 0o644); err != nil {
		t.Fatalf("WriteFile() error = %v", err)
	}

	laterSessionFile := filepath.Join(profileDir, "sessionstore.jsonlz4")
	writeSessionLZ4(t, laterSessionFile, sessionStore{
		Cookies: []sessionCookie{
			{
				Host:   ".session-only.test",
				Path:   "/",
				Name:   "session-only",
				Value:  "from-later-session-store",
				Secure: true,
			},
		},
	})

	loader := NewLoader()
	cookies, err := loader.Load(Browser{
		Name:            "firefox",
		ProfilePatterns: []string{profilesINI},
	}, nil, nil)
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}

	cookie := findCookie(cookies, "session-only")
	if cookie == nil || cookie.Value != "from-later-session-store" {
		t.Fatalf("session-only cookie = %#v", cookie)
	}
}

func TestLoaderLoadIgnoresBrokenOptionalSessionStore(t *testing.T) {
	t.Parallel()

	root := t.TempDir()
	profileDir := filepath.Join(root, "Profiles", "default-release")
	if err := os.MkdirAll(filepath.Join(profileDir, "sessionstore-backups"), 0o755); err != nil {
		t.Fatalf("MkdirAll() error = %v", err)
	}

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

	expires := time.Unix(1_700_000_000, 0).UTC()
	writeFirefoxDB(t, filepath.Join(profileDir, "cookies.sqlite"), expires)

	sessionFile := filepath.Join(profileDir, "sessionstore-backups", "recovery.jsonlz4")
	if err := os.WriteFile(sessionFile, []byte("mozLz40\x00definitely-not-lz4"), 0o644); err != nil {
		t.Fatalf("WriteFile() error = %v", err)
	}

	loader := NewLoader()
	cookies, err := loader.Load(Browser{
		Name:            "firefox",
		ProfilePatterns: []string{profilesINI},
	}, nil, nil)
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}

	cookie := findCookie(cookies, "persistent")
	if cookie == nil || cookie.Value != "from-sqlite" {
		t.Fatalf("persistent cookie = %#v", cookie)
	}
}

func TestBrowserMetadataUsesFamilySpecificProfileRoots(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		spec string
		want string
	}{
		{name: "firefox", spec: "firefox", want: "%APPDATA%/Mozilla/Firefox"},
		{name: "librewolf", spec: "librewolf", want: "%LOCALAPPDATA%/librewolf"},
		{name: "zen", spec: "zen", want: "%APPDATA%/zen"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			patterns := browsercfg.MustMozilla(tt.spec).ProfilePatterns("windows")
			found := false
			for _, path := range patterns {
				if path == tt.want {
					found = true
					break
				}
			}
			if !found {
				t.Fatalf("ProfilePatterns() missing %q in %v", tt.want, patterns)
			}
		})
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
