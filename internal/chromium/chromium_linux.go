//go:build linux

package chromium

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/sha1"
	"database/sql"
	"errors"
	"fmt"
	"net/http"
	"os/exec"
	"strings"
	"time"

	"github.com/Code-Hex/browsercookie/internal/cookieutil"
	"github.com/Code-Hex/browsercookie/internal/errdefs"
	"github.com/Code-Hex/browsercookie/internal/pathutil"
	"github.com/Code-Hex/browsercookie/internal/sqlitecopy"
	"golang.org/x/crypto/pbkdf2"
)

const (
	chromiumSalt            = "saltysalt"
	chromiumIterations      = 1
	chromiumKeyLength       = 16
	unixToNTEpochOffsetMicr = int64(11644473600 * 1_000_000)
)

var chromiumIV = []byte("                ")

// Load reads cookies from the configured Chromium browser store paths.
func (l Loader) Load(browser Browser, cookieFiles []string) ([]*http.Cookie, error) {
	if len(cookieFiles) == 0 {
		cookieFiles = pathutil.Expand(browser.CookieFilePatterns)
	}
	if len(cookieFiles) == 0 {
		return nil, errdefs.ErrNotFound
	}
	keys := linuxKeys(browser)

	var cookies []*http.Cookie
	for _, cookieFile := range cookieFiles {
		loaded, err := loadCookieFileWithKeys(cookieFile, keys)
		if err != nil {
			return nil, err
		}
		cookies = append(cookies, loaded...)
	}
	cookieutil.SortByExpiry(cookies)
	return cookies, nil
}

func linuxKeys(browser Browser) [][]byte {
	keys := make([][]byte, 0, 4)
	seen := map[string]struct{}{}
	for _, password := range linuxPasswords(browser.LinuxPasswordApps) {
		addPBKDF2Key(&keys, seen, password)
	}
	addPBKDF2Key(&keys, seen, []byte("peanuts"))
	addPBKDF2Key(&keys, seen, nil)
	return keys
}

func addPBKDF2Key(keys *[][]byte, seen map[string]struct{}, password []byte) {
	key := pbkdf2.Key(password, []byte(chromiumSalt), chromiumIterations, chromiumKeyLength, sha1.New)
	fingerprint := string(key)
	if _, ok := seen[fingerprint]; ok {
		return
	}
	seen[fingerprint] = struct{}{}
	*keys = append(*keys, key)
}

func linuxPasswords(apps []string) [][]byte {
	passwords := make([][]byte, 0, len(apps)*3)
	seen := map[string]struct{}{}
	for _, app := range apps {
		for _, password := range [][]byte{
			lookupSecretToolPassword("chrome_libsecret_os_crypt_password_v2", app),
			lookupSecretToolPassword("chrome_libsecret_os_crypt_password_v1", app),
			lookupKWalletPassword(app),
		} {
			if len(password) == 0 {
				continue
			}
			fingerprint := string(password)
			if _, ok := seen[fingerprint]; ok {
				continue
			}
			seen[fingerprint] = struct{}{}
			passwords = append(passwords, password)
		}
	}
	return passwords
}

func lookupSecretToolPassword(schema, app string) []byte {
	cmd := exec.Command("secret-tool", "lookup", "xdg:schema", schema, "application", app)
	out, err := cmd.Output()
	if err != nil {
		return nil
	}
	return bytes.TrimSpace(out)
}

func lookupKWalletPassword(app string) []byte {
	folder := linuxCapitalize(app) + " Keys"
	key := linuxCapitalize(app) + " Safe Storage"

	cmd := exec.Command("kwallet-query", "-f", folder, "-r", key, "kdewallet")
	out, err := cmd.Output()
	if err != nil {
		return nil
	}
	return bytes.TrimSpace(out)
}

func linuxCapitalize(value string) string {
	if value == "" {
		return ""
	}
	return strings.ToUpper(value[:1]) + value[1:]
}

func loadCookieFileWithKeys(path string, keys [][]byte) ([]*http.Cookie, error) {
	var errs []error
	for _, key := range keys {
		cookies, err := loadCookieFile(path, key)
		if err == nil {
			return cookies, nil
		}
		if errors.Is(err, errdefs.ErrDecrypt) {
			errs = append(errs, err)
			continue
		}
		return nil, err
	}
	if len(errs) > 0 {
		return nil, errors.Join(errs...)
	}
	return nil, errdefs.ErrDecrypt
}

func loadCookieFile(path string, key []byte) ([]*http.Cookie, error) {
	db, cleanup, err := sqlitecopy.Open(path)
	if err != nil {
		return nil, err
	}
	defer func() { _ = cleanup() }()

	version, err := cookieStoreVersion(db)
	if err != nil {
		return nil, err
	}
	query := `SELECT host_key, path, is_secure, expires_utc, name, value, encrypted_value FROM cookies`
	if version < 10 {
		query = `SELECT host_key, path, secure, expires_utc, name, value, encrypted_value FROM cookies`
	}
	rows, err := db.Query(query)
	if err != nil {
		if strings.Contains(err.Error(), "no such table") || strings.Contains(err.Error(), "no such column") {
			return nil, errdefs.ErrInvalidStore
		}
		return nil, err
	}
	defer func() { _ = rows.Close() }()

	var cookies []*http.Cookie
	for rows.Next() {
		var (
			host    string
			path    string
			secure  int64
			expires int64
			name    string
			value   string
			enc     []byte
		)
		if err := rows.Scan(&host, &path, &secure, &expires, &name, &value, &enc); err != nil {
			return nil, err
		}
		decrypted, err := decryptValue(value, enc, key, version >= 24)
		if err != nil {
			return nil, err
		}
		cookies = append(cookies, &http.Cookie{
			Name:    name,
			Value:   decrypted,
			Domain:  host,
			Path:    normalizePath(path),
			Secure:  secure != 0,
			Expires: chromiumExpiry(expires),
		})
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return cookies, nil
}

func cookieStoreVersion(db *sql.DB) (int, error) {
	var raw string
	err := db.QueryRow(`SELECT value FROM meta WHERE key = "version"`).Scan(&raw)
	if err == sql.ErrNoRows {
		return 0, nil
	}
	if err != nil {
		if strings.Contains(err.Error(), "no such table") {
			return 0, errdefs.ErrInvalidStore
		}
		return 0, err
	}
	var version int
	if _, err := fmt.Sscanf(raw, "%d", &version); err != nil {
		return 0, errdefs.ErrInvalidStore
	}
	return version, nil
}

func chromiumExpiry(value int64) time.Time {
	if value <= 0 {
		return time.Time{}
	}
	return time.UnixMicro(value - unixToNTEpochOffsetMicr).UTC()
}

func decryptValue(plain string, encrypted []byte, key []byte, hasDomainHash bool) (string, error) {
	if plain != "" || len(encrypted) < 3 {
		return plain, nil
	}
	prefix := string(encrypted[:3])
	if prefix != "v10" && prefix != "v11" && prefix != "v20" {
		return plain, nil
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return "", err
	}
	ciphertext := encrypted[3:]
	if len(ciphertext) == 0 || len(ciphertext)%block.BlockSize() != 0 {
		return "", errdefs.ErrDecrypt
	}
	plaintext := make([]byte, len(ciphertext))
	cipher.NewCBCDecrypter(block, chromiumIV).CryptBlocks(plaintext, ciphertext)
	plaintext, err = pkcs7Unpad(plaintext, block.BlockSize())
	if err != nil {
		return "", err
	}
	if hasDomainHash && len(plaintext) >= 32 {
		plaintext = plaintext[32:]
	}
	return string(plaintext), nil
}

func pkcs7Unpad(data []byte, blockSize int) ([]byte, error) {
	if len(data) == 0 {
		return nil, errdefs.ErrDecrypt
	}
	paddingLen := int(data[len(data)-1])
	if paddingLen == 0 || paddingLen > blockSize || paddingLen > len(data) {
		return nil, errdefs.ErrDecrypt
	}
	for _, b := range data[len(data)-paddingLen:] {
		if int(b) != paddingLen {
			return nil, errdefs.ErrDecrypt
		}
	}
	return data[:len(data)-paddingLen], nil
}

func normalizePath(path string) string {
	if path == "" {
		return "/"
	}
	return path
}
