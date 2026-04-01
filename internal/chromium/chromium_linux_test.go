//go:build linux

package chromium

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/sha1"
	"database/sql"
	"errors"
	"path/filepath"
	"testing"
	"time"

	"golang.org/x/crypto/pbkdf2"
	_ "modernc.org/sqlite"
)

func TestLoaderLoadFallsBackToPeanutsOnLinux(t *testing.T) {
	t.Parallel()

	key := pbkdf2.Key([]byte("peanuts"), []byte(chromiumSalt), chromiumIterations, chromiumKeyLength, sha1.New)
	cookieFile := filepath.Join(t.TempDir(), "Cookies")
	expires := time.Unix(1_700_000_000, 0).UTC()

	writeLinuxChromiumDB(t, cookieFile, 24, []linuxChromiumRow{
		{
			host:    ".example.com",
			path:    "/",
			secure:  1,
			expires: chromiumExpires(expires),
			name:    "session",
			enc:     encryptLinuxValue(t, "from-linux", key, true),
		},
	})

	loader := NewLoader(nil)
	cookies, err := loader.Load(Browser{Name: "chrome"}, []string{cookieFile}, nil)
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}
	if len(cookies) != 1 {
		t.Fatalf("len(cookies) = %d, want 1", len(cookies))
	}
	if cookies[0].Value != "from-linux" {
		t.Fatalf("cookie value = %q, want %q", cookies[0].Value, "from-linux")
	}
}

func TestLinuxPasswordsUsesConfiguredOrderAndDedupes(t *testing.T) {
	t.Parallel()

	original := newLinuxKeyringClient
	t.Cleanup(func() { newLinuxKeyringClient = original })

	newLinuxKeyringClient = func() (linuxKeyringClient, error) {
		return fakeLinuxKeyringClient{
			secretPasswords: map[string][]byte{
				"chrome_libsecret_os_crypt_password_v2|arc": []byte("first"),
				"chrome_libsecret_os_crypt_password_v1|arc": []byte("first"),
			},
			kwalletPasswords: map[string][]byte{
				"Arc Keys|Arc Safe Storage": []byte("second"),
			},
		}, nil
	}

	passwords := linuxPasswords(Browser{
		LinuxLibsecretRefs: []linuxLibsecretRef{
			{Schema: "chrome_libsecret_os_crypt_password_v2", Application: "arc"},
			{Schema: "chrome_libsecret_os_crypt_password_v1", Application: "arc"},
		},
		LinuxKWalletRefs: []linuxKWalletRef{
			{Folder: "Arc Keys", Key: "Arc Safe Storage"},
		},
	})

	if len(passwords) != 2 {
		t.Fatalf("len(passwords) = %d, want 2", len(passwords))
	}
	if string(passwords[0]) != "first" || string(passwords[1]) != "second" {
		t.Fatalf("passwords = %q, want first then second", passwords)
	}
}

type fakeLinuxKeyringClient struct {
	secretPasswords  map[string][]byte
	kwalletPasswords map[string][]byte
}

func (f fakeLinuxKeyringClient) SecretPassword(schema, application string) ([]byte, error) {
	password, ok := f.secretPasswords[schema+"|"+application]
	if !ok {
		return nil, errors.New("not found")
	}
	return append([]byte(nil), password...), nil
}

func (f fakeLinuxKeyringClient) KWalletPassword(folder, key string) ([]byte, error) {
	password, ok := f.kwalletPasswords[folder+"|"+key]
	if !ok {
		return nil, errors.New("not found")
	}
	return append([]byte(nil), password...), nil
}

type linuxChromiumRow struct {
	host    string
	path    string
	secure  int
	expires int64
	name    string
	value   string
	enc     []byte
}

func writeLinuxChromiumDB(t *testing.T, path string, version int, rows []linuxChromiumRow) {
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
		encrypted_value BLOB
	)`); err != nil {
		t.Fatalf("create cookies error = %v", err)
	}

	for _, row := range rows {
		if _, err := db.Exec(`INSERT INTO cookies(host_key, path, is_secure, expires_utc, name, value, encrypted_value) VALUES(?, ?, ?, ?, ?, ?, ?)`,
			row.host, row.path, row.secure, row.expires, row.name, row.value, row.enc); err != nil {
			t.Fatalf("insert cookie error = %v", err)
		}
	}
}

func encryptLinuxValue(t *testing.T, value string, key []byte, withDomainHash bool) []byte {
	t.Helper()

	plaintext := []byte(value)
	if withDomainHash {
		plaintext = append(make([]byte, 32), plaintext...)
	}
	padded := padLinuxPKCS7(plaintext, aes.BlockSize)
	block, err := aes.NewCipher(key)
	if err != nil {
		t.Fatalf("aes.NewCipher() error = %v", err)
	}
	encrypted := make([]byte, len(padded))
	cipher.NewCBCEncrypter(block, chromiumIV).CryptBlocks(encrypted, padded)
	return append([]byte("v10"), encrypted...)
}

func padLinuxPKCS7(data []byte, blockSize int) []byte {
	paddingLen := blockSize - len(data)%blockSize
	padded := make([]byte, len(data)+paddingLen)
	copy(padded, data)
	for i := len(data); i < len(padded); i++ {
		padded[i] = byte(paddingLen)
	}
	return padded
}

func chromiumExpires(expiry time.Time) int64 {
	return expiry.UnixMicro() + unixToNTEpochOffsetMicr
}
