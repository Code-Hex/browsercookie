//go:build windows

package chromium

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"database/sql"
	"os"
	"path/filepath"
	"testing"
	"time"

	_ "modernc.org/sqlite"
)

func TestLoadCookieFileReadsGCMCookiesOnWindows(t *testing.T) {
	t.Parallel()

	key := []byte("0123456789abcdef0123456789abcdef")
	cookieFile := filepath.Join(t.TempDir(), "Cookies")
	expires := time.Unix(1_700_000_000, 0).UTC()

	writeWindowsChromiumDB(t, cookieFile, 24, []windowsChromiumRow{
		{
			host:    ".example.com",
			path:    "/",
			secure:  1,
			expires: chromiumExpires(expires),
			name:    "session",
			enc:     encryptWindowsValue(t, "from-windows", key, true),
		},
	})

	cookies, err := loadCookieFile(cookieFile, key)
	if err != nil {
		t.Fatalf("loadCookieFile() error = %v", err)
	}
	if len(cookies) != 1 {
		t.Fatalf("len(cookies) = %d, want 1", len(cookies))
	}
	if cookies[0].Value != "from-windows" {
		t.Fatalf("cookie value = %q, want %q", cookies[0].Value, "from-windows")
	}
}

func TestLocalStatePathForCookieFilePrefersUserDataRoot(t *testing.T) {
	t.Parallel()

	root := t.TempDir()
	cookieFile := filepath.Join(root, "User Data", "Default", "Network", "Cookies")
	localState := filepath.Join(root, "User Data", "Local State")
	if err := os.MkdirAll(filepath.Dir(cookieFile), 0o755); err != nil {
		t.Fatalf("MkdirAll() error = %v", err)
	}
	if err := os.MkdirAll(filepath.Dir(localState), 0o755); err != nil {
		t.Fatalf("MkdirAll() error = %v", err)
	}
	if err := os.WriteFile(localState, []byte("{}"), 0o644); err != nil {
		t.Fatalf("WriteFile() error = %v", err)
	}

	got, err := localStatePathForCookieFile(cookieFile)
	if err != nil {
		t.Fatalf("localStatePathForCookieFile() error = %v", err)
	}
	if got != localState {
		t.Fatalf("localStatePathForCookieFile() = %q, want %q", got, localState)
	}
}

type windowsChromiumRow struct {
	host    string
	path    string
	secure  int
	expires int64
	name    string
	value   string
	enc     []byte
}

func writeWindowsChromiumDB(t *testing.T, path string, version int, rows []windowsChromiumRow) {
	t.Helper()

	db, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatalf("sql.Open() error = %v", err)
	}
	defer func() { _ = db.Close() }()

	if _, err := db.Exec(`CREATE TABLE meta (key TEXT PRIMARY KEY, value TEXT)`); err != nil {
		t.Fatalf("create meta error = %v", err)
	}
	if _, err := db.Exec(`INSERT INTO meta(key, value) VALUES('version', ?)`, version); err != nil {
		t.Fatalf("insert meta error = %v", err)
	}
	if _, err := db.Exec(`CREATE TABLE cookies (
		host_key TEXT,
		path TEXT,
		is_secure INTEGER,
		expires_utc INTEGER,
		name TEXT,
		value TEXT,
		encrypted_value BLOB,
		is_httponly INTEGER
	)`); err != nil {
		t.Fatalf("create cookies error = %v", err)
	}

	for _, row := range rows {
		if _, err := db.Exec(`INSERT INTO cookies(host_key, path, is_secure, expires_utc, name, value, encrypted_value, is_httponly) VALUES(?, ?, ?, ?, ?, ?, ?, 1)`,
			row.host, row.path, row.secure, row.expires, row.name, row.value, row.enc); err != nil {
			t.Fatalf("insert cookie error = %v", err)
		}
	}
}

func encryptWindowsValue(t *testing.T, value string, key []byte, withDomainHash bool) []byte {
	t.Helper()

	plaintext := []byte(value)
	if withDomainHash {
		plaintext = append(make([]byte, 32), plaintext...)
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		t.Fatalf("aes.NewCipher() error = %v", err)
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		t.Fatalf("cipher.NewGCM() error = %v", err)
	}
	nonce := make([]byte, aead.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		t.Fatalf("rand.Read() error = %v", err)
	}
	ciphertext := aead.Seal(nil, nonce, plaintext, nil)
	return append(append([]byte("v10"), nonce...), ciphertext...)
}

func chromiumExpires(expiry time.Time) int64 {
	return expiry.UnixMicro() + unixToNTEpochOffsetMicr
}
