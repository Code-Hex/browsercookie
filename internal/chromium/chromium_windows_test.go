//go:build windows

package chromium

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"database/sql"
	"encoding/base64"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"
	"unsafe"

	"github.com/Code-Hex/browsercookie/internal/browsercfg"
	"github.com/Code-Hex/browsercookie/internal/errdefs"
	"golang.org/x/sys/windows"
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

	cookies, err := loadCookieFile(cookieFile, windowsKeyMaterial{legacyKey: key}, nil)
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

	got, err := localStatePathForCookieFile(ChromeBrowser, cookieFile)
	if err != nil {
		t.Fatalf("localStatePathForCookieFile() error = %v", err)
	}
	if got != localState {
		t.Fatalf("localStatePathForCookieFile() = %q, want %q", got, localState)
	}
}

func TestResolveKeyMaterialTracksAppBoundKey(t *testing.T) {
	t.Parallel()

	material, err := resolveKeyMaterial(Browser{
		WindowsKeySources: []windowsKeySource{windowsAppBoundEncryptedKeySource},
	}, localState{
		OSCrypt: struct {
			EncryptedKey         string `json:"encrypted_key"`
			AppBoundEncryptedKey string `json:"app_bound_encrypted_key"`
		}{
			AppBoundEncryptedKey: "app-bound",
		},
	})
	if err != nil {
		t.Fatalf("resolveKeyMaterial() error = %v", err)
	}
	if material.appBoundEncryptedKey != "app-bound" {
		t.Fatalf("appBoundEncryptedKey = %q, want %q", material.appBoundEncryptedKey, "app-bound")
	}
}

func TestDecryptValueRejectsV20CookiesAsUnsupported(t *testing.T) {
	t.Parallel()

	encrypted := append([]byte("v20"), bytes.Repeat([]byte{0}, 32)...)
	_, err := decryptValue("", encrypted, windowsKeyMaterial{
		appBoundEncryptedKey: "app-bound",
	}, false)
	if !errors.Is(err, errdefs.ErrUnsupported) {
		t.Fatalf("decryptValue() error = %v, want ErrUnsupported", err)
	}
}

func TestLoaderLoadDiscoversElectronPartitionCookiesOnWindows(t *testing.T) {
	t.Parallel()

	key := []byte("0123456789abcdef0123456789abcdef")
	root := t.TempDir()
	localStatePath := filepath.Join(root, "Local State")
	rootCookieFile := filepath.Join(root, "Cookies")
	partitionCookieFile := filepath.Join(root, "Partitions", "persist-workspace", "Network", "Cookies")
	expires := time.Unix(1_700_000_000, 0).UTC()

	if err := os.MkdirAll(filepath.Dir(partitionCookieFile), 0o755); err != nil {
		t.Fatalf("MkdirAll() error = %v", err)
	}
	if err := os.WriteFile(localStatePath, []byte(fmt.Sprintf(`{"os_crypt":{"encrypted_key":%q}}`, encodeLegacyKeyForLocalState(t, key))), 0o644); err != nil {
		t.Fatalf("WriteFile(Local State) error = %v", err)
	}

	writeWindowsChromiumDB(t, rootCookieFile, 24, []windowsChromiumRow{
		{
			host:    ".example.com",
			path:    "/",
			secure:  1,
			expires: chromiumExpires(expires),
			name:    "root",
			enc:     encryptWindowsValue(t, "from-root", key, true),
		},
	})
	writeWindowsChromiumDB(t, partitionCookieFile, 24, []windowsChromiumRow{
		{
			host:    ".example.com",
			path:    "/workspace",
			secure:  1,
			expires: chromiumExpires(expires.Add(10 * time.Second)),
			name:    "partition",
			enc:     encryptWindowsValue(t, "from-partition", key, true),
		},
	})

	browser := BrowserFromSpec(browsercfg.ElectronSpec("TestApp", []string{root}, []string{"TestApp"}))
	cookies, err := NewLoader(nil).Load(browser, nil, nil)
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

func encodeLegacyKeyForLocalState(t *testing.T, key []byte) string {
	t.Helper()

	in := windows.DataBlob{
		Size: uint32(len(key)),
		Data: &key[0],
	}
	var out windows.DataBlob
	if err := windows.CryptProtectData(&in, nil, nil, 0, nil, 0, &out); err != nil {
		t.Fatalf("CryptProtectData() error = %v", err)
	}
	if out.Data == nil || out.Size == 0 {
		t.Fatal("CryptProtectData() returned empty output")
	}
	defer windows.LocalFree(windows.Handle(unsafe.Pointer(out.Data)))

	protected := unsafe.Slice(out.Data, out.Size)
	payload := append([]byte("DPAPI"), protected...)
	return base64.StdEncoding.EncodeToString(payload)
}
