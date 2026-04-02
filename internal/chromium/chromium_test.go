//go:build darwin

package chromium

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/sha1"
	"database/sql"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/Code-Hex/browsercookie/internal/browsercfg"
	"github.com/Code-Hex/browsercookie/internal/errdefs"
	"golang.org/x/crypto/pbkdf2"
	_ "modernc.org/sqlite"
)

type secretKey struct {
	service string
	account string
}

type fakeProvider struct {
	passwords map[secretKey][]byte
	errs      map[secretKey]error
}

func (f fakeProvider) GenericPassword(service, account string) ([]byte, error) {
	key := secretKey{service: service, account: account}
	if err, ok := f.errs[key]; ok {
		return nil, err
	}
	password, ok := f.passwords[key]
	if !ok {
		return nil, errdefs.ErrDecrypt
	}
	return append([]byte(nil), password...), nil
}

func TestLoaderLoadReadsPlaintextAndEncryptedCookies(t *testing.T) {
	t.Parallel()

	password := []byte("secret-for-tests")
	key := pbkdf2.Key(password, []byte(chromiumSalt), chromiumIterations, chromiumKeyLength, sha1.New)
	cookieFile := filepath.Join(t.TempDir(), "Cookies")
	expires := time.Unix(1_700_000_000, 0).UTC()

	writeChromiumDB(t, cookieFile, 24, false, []chromiumRow{
		{
			host:    ".example.com",
			path:    "/",
			secure:  1,
			expires: chromiumExpires(expires),
			name:    "plain",
			value:   "plain-value",
		},
		{
			host:    ".example.com",
			path:    "/secure",
			secure:  1,
			expires: chromiumExpires(expires.Add(10 * time.Second)),
			name:    "enc",
			enc:     encryptValue(t, "encrypted-value", key, true),
		},
	})

	loader := NewLoader(fakeProvider{
		passwords: map[secretKey][]byte{
			secretFor(ChromeBrowser): password,
		},
	})
	cookies, err := loader.Load(ChromeBrowser, []string{cookieFile}, nil)
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}
	if len(cookies) != 2 {
		t.Fatalf("len(cookies) = %d, want 2", len(cookies))
	}
	if cookies[0].Name != "plain" || cookies[0].Value != "plain-value" {
		t.Fatalf("plain cookie = %#v", cookies[0])
	}
	if cookies[1].Name != "enc" || cookies[1].Value != "encrypted-value" {
		t.Fatalf("encrypted cookie = %#v", cookies[1])
	}
}

func TestLoaderLoadSupportsLegacySecureColumn(t *testing.T) {
	t.Parallel()

	password := []byte("secret-for-tests")
	cookieFile := filepath.Join(t.TempDir(), "Cookies")
	expires := time.Unix(1_700_000_000, 0).UTC()

	writeChromiumDB(t, cookieFile, 9, true, []chromiumRow{
		{
			host:    ".legacy.test",
			path:    "/",
			secure:  0,
			expires: chromiumExpires(expires),
			name:    "legacy",
			value:   "value",
		},
	})

	loader := NewLoader(fakeProvider{
		passwords: map[secretKey][]byte{
			secretFor(ChromeBrowser): password,
		},
	})
	cookies, err := loader.Load(ChromeBrowser, []string{cookieFile}, nil)
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}
	if len(cookies) != 1 {
		t.Fatalf("len(cookies) = %d, want 1", len(cookies))
	}
	if cookies[0].Name != "legacy" || cookies[0].Value != "value" {
		t.Fatalf("legacy cookie = %#v", cookies[0])
	}
}

func TestLoaderLoadFallsBackToAlternateSecret(t *testing.T) {
	t.Parallel()

	wrongPassword := []byte("wrong-secret")
	rightPassword := []byte("right-secret")
	rightKey := pbkdf2.Key(rightPassword, []byte(chromiumSalt), chromiumIterations, chromiumKeyLength, sha1.New)
	cookieFile := filepath.Join(t.TempDir(), "Cookies")

	writeChromiumDB(t, cookieFile, 24, false, []chromiumRow{
		{
			host:    ".vivaldi.test",
			path:    "/",
			secure:  1,
			expires: chromiumExpires(time.Unix(1_700_000_000, 0).UTC()),
			name:    "session",
			enc:     encryptValue(t, "from-vivaldi", rightKey, true),
		},
	})

	loader := NewLoader(fakeProvider{
		passwords: map[secretKey][]byte{
			{service: "Vivaldi Safe Storage", account: "Vivaldi"}: wrongPassword,
			{service: "Chrome Safe Storage", account: "Chrome"}:   rightPassword,
		},
	})
	cookies, err := loader.Load(VivaldiBrowser, []string{cookieFile}, nil)
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}
	if len(cookies) != 1 {
		t.Fatalf("len(cookies) = %d, want 1", len(cookies))
	}
	if cookies[0].Value != "from-vivaldi" {
		t.Fatalf("cookie value = %q, want %q", cookies[0].Value, "from-vivaldi")
	}
}

func TestLoaderLoadDiscoversElectronPartitionCookies(t *testing.T) {
	t.Parallel()

	password := []byte("secret-for-tests")
	key := pbkdf2.Key(password, []byte(chromiumSalt), chromiumIterations, chromiumKeyLength, sha1.New)
	root := filepath.Join(t.TempDir(), "ElectronApp")
	rootCookieFile := filepath.Join(root, "Cookies")
	partitionCookieFile := filepath.Join(root, "Partitions", "persist:workspace", "Cookies")
	expires := time.Unix(1_700_000_000, 0).UTC()

	for _, path := range []string{rootCookieFile, partitionCookieFile} {
		if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
			t.Fatalf("MkdirAll(%q) error = %v", filepath.Dir(path), err)
		}
	}

	writeChromiumDB(t, rootCookieFile, 24, false, []chromiumRow{
		{
			host:    ".example.com",
			path:    "/",
			secure:  1,
			expires: chromiumExpires(expires),
			name:    "root",
			enc:     encryptValue(t, "from-root", key, true),
		},
	})
	writeChromiumDB(t, partitionCookieFile, 24, false, []chromiumRow{
		{
			host:    ".example.com",
			path:    "/workspace",
			secure:  1,
			expires: chromiumExpires(expires.Add(10 * time.Second)),
			name:    "partition",
			enc:     encryptValue(t, "from-partition", key, true),
		},
	})

	browser := BrowserFromSpec(browsercfg.ElectronSpec("TestApp", []string{root}, []string{"TestApp"}))
	loader := NewLoader(fakeProvider{
		passwords: map[secretKey][]byte{
			{service: "TestApp Safe Storage", account: "TestApp"}: password,
		},
	})
	cookies, err := loader.Load(browser, nil, nil)
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}
	if len(cookies) != 2 {
		t.Fatalf("len(cookies) = %d, want 2", len(cookies))
	}
	if cookies[0].Name != "root" || cookies[1].Name != "partition" {
		t.Fatalf("cookies = %#v", cookies)
	}
}

func TestBrowserMetadataUsesPerBrowserSecrets(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name           string
		browser        Browser
		wantService    string
		wantAccount    string
		wantCookiePath string
	}{
		{
			name:        "brave",
			browser:     BraveBrowser,
			wantService: "Brave Safe Storage",
			wantAccount: "Brave",
		},
		{
			name:           "chromium",
			browser:        ChromiumBrowser,
			wantService:    "Chromium Safe Storage",
			wantAccount:    "Chromium",
			wantCookiePath: "~/Library/Application Support/Chromium/Default/Cookies",
		},
		{
			name:        "vivaldi",
			browser:     VivaldiBrowser,
			wantService: "Vivaldi Safe Storage",
			wantAccount: "Vivaldi",
		},
		{
			name:        "edge",
			browser:     EdgeBrowser,
			wantService: "Microsoft Edge Safe Storage",
			wantAccount: "Microsoft Edge",
		},
		{
			name:        "edge dev",
			browser:     EdgeDevBrowser,
			wantService: "Microsoft Edge Dev Safe Storage",
			wantAccount: "Microsoft Edge Dev",
		},
		{
			name:        "opera",
			browser:     OperaBrowser,
			wantService: "Opera Safe Storage",
			wantAccount: "Opera",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if len(tt.browser.Secrets) == 0 {
				t.Fatal("browser.Secrets is empty")
			}
			if tt.browser.Secrets[0].Service != tt.wantService || tt.browser.Secrets[0].Account != tt.wantAccount {
				t.Fatalf("primary secret = %#v, want service=%q account=%q", tt.browser.Secrets[0], tt.wantService, tt.wantAccount)
			}
			if tt.wantCookiePath != "" && tt.browser.CookieFilePatterns[0] != tt.wantCookiePath {
				t.Fatalf("cookie path = %q, want %q", tt.browser.CookieFilePatterns[0], tt.wantCookiePath)
			}
		})
	}
}

func TestLoaderLoadReturnsSecretErrorsWhenAllCandidatesFail(t *testing.T) {
	t.Parallel()

	loader := NewLoader(fakeProvider{
		errs: map[secretKey]error{
			secretFor(ChromeBrowser): errors.New("missing keychain item"),
		},
	})
	_, err := loader.Load(ChromeBrowser, []string{filepath.Join(t.TempDir(), "Cookies")}, nil)
	if err == nil {
		t.Fatal("Load() error = nil, want failure")
	}
	if !errors.Is(err, errdefs.ErrDecrypt) && !strings.Contains(err.Error(), "missing keychain item") {
		t.Fatalf("Load() error = %v, want secret lookup failure", err)
	}
}

func TestLoaderLoadFiltersDomainsAtQueryLevel(t *testing.T) {
	t.Parallel()

	password := []byte("secret-for-tests")
	key := pbkdf2.Key(password, []byte(chromiumSalt), chromiumIterations, chromiumKeyLength, sha1.New)
	cookieFile := filepath.Join(t.TempDir(), "Cookies")
	expires := time.Unix(1_700_000_000, 0).UTC()

	writeChromiumDB(t, cookieFile, 24, false, []chromiumRow{
		{
			host:    ".example.com",
			path:    "/",
			secure:  1,
			expires: chromiumExpires(expires),
			name:    "wanted",
			enc:     encryptValue(t, "match", key, true),
		},
		{
			host:    ".example.org",
			path:    "/",
			secure:  1,
			expires: chromiumExpires(expires),
			name:    "other",
			enc:     encryptValue(t, "ignore", key, true),
		},
	})

	loader := NewLoader(fakeProvider{
		passwords: map[secretKey][]byte{
			secretFor(ChromeBrowser): password,
		},
	})
	cookies, err := loader.Load(ChromeBrowser, []string{cookieFile}, []string{"EXAMPLE.com"})
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}
	if len(cookies) != 1 {
		t.Fatalf("len(cookies) = %d, want 1", len(cookies))
	}
	if cookies[0].Name != "wanted" {
		t.Fatalf("cookie = %#v", cookies[0])
	}
}

func secretFor(browser Browser) secretKey {
	return secretKey{
		service: browser.Secrets[0].Service,
		account: browser.Secrets[0].Account,
	}
}

type chromiumRow struct {
	host    string
	path    string
	secure  int
	expires int64
	name    string
	value   string
	enc     []byte
}

func writeChromiumDB(t *testing.T, path string, version int, legacy bool, rows []chromiumRow) {
	t.Helper()

	db, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatalf("sql.Open() error = %v", err)
	}
	defer func() { _ = db.Close() }()

	if _, err := db.Exec(`CREATE TABLE meta (key TEXT PRIMARY KEY, value TEXT)`); err != nil {
		t.Fatalf("create meta error = %v", err)
	}
	if _, err := db.Exec(`INSERT INTO meta(key, value) VALUES("version", ?)`, version); err != nil {
		t.Fatalf("insert meta error = %v", err)
	}

	schema := `CREATE TABLE cookies (
		host_key TEXT,
		path TEXT,
		is_secure INTEGER,
		expires_utc INTEGER,
		name TEXT,
		value TEXT,
		encrypted_value BLOB
	)`
	insertSQL := `INSERT INTO cookies(host_key, path, is_secure, expires_utc, name, value, encrypted_value) VALUES(?, ?, ?, ?, ?, ?, ?)`
	if legacy {
		schema = `CREATE TABLE cookies (
			host_key TEXT,
			path TEXT,
			secure INTEGER,
			expires_utc INTEGER,
			name TEXT,
			value TEXT,
			encrypted_value BLOB
		)`
		insertSQL = `INSERT INTO cookies(host_key, path, secure, expires_utc, name, value, encrypted_value) VALUES(?, ?, ?, ?, ?, ?, ?)`
	}
	if _, err := db.Exec(schema); err != nil {
		t.Fatalf("create cookies error = %v", err)
	}
	for _, row := range rows {
		if _, err := db.Exec(insertSQL, row.host, row.path, row.secure, row.expires, row.name, row.value, row.enc); err != nil {
			t.Fatalf("insert cookie error = %v", err)
		}
	}
}

func encryptValue(t *testing.T, value string, key []byte, withDomainHash bool) []byte {
	t.Helper()

	plain := []byte(value)
	if withDomainHash {
		plain = append(make([]byte, 32), plain...)
	}
	plain = pkcs7Pad(plain, aes.BlockSize)
	block, err := aes.NewCipher(key)
	if err != nil {
		t.Fatalf("aes.NewCipher() error = %v", err)
	}
	encrypted := make([]byte, len(plain))
	cipher.NewCBCEncrypter(block, chromiumIV).CryptBlocks(encrypted, plain)
	return append([]byte("v10"), encrypted...)
}

func pkcs7Pad(data []byte, blockSize int) []byte {
	paddingLen := blockSize - (len(data) % blockSize)
	padding := make([]byte, paddingLen)
	for i := range padding {
		padding[i] = byte(paddingLen)
	}
	return append(data, padding...)
}

func chromiumExpires(t time.Time) int64 {
	return t.UnixMicro() + unixToNTEpochOffsetMicr
}
