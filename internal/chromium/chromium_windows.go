//go:build windows

package chromium

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"
	"unsafe"

	"github.com/Code-Hex/browsercookie/internal/cookieutil"
	"github.com/Code-Hex/browsercookie/internal/errdefs"
	"github.com/Code-Hex/browsercookie/internal/pathutil"
	"github.com/Code-Hex/browsercookie/internal/sqlitecopy"
	"golang.org/x/sys/windows"
)

const unixToNTEpochOffsetMicr = int64(11644473600 * 1_000_000)

type localState struct {
	OSCrypt struct {
		EncryptedKey string `json:"encrypted_key"`
	} `json:"os_crypt"`
}

// Load reads cookies from the configured Chromium browser store paths.
func (l Loader) Load(browser Browser, cookieFiles []string) ([]*http.Cookie, error) {
	if len(cookieFiles) == 0 {
		cookieFiles = pathutil.Expand(browser.CookieFilePatterns)
	}
	if len(cookieFiles) == 0 {
		return nil, errdefs.ErrNotFound
	}

	var cookies []*http.Cookie
	for _, cookieFile := range cookieFiles {
		key, err := loadMasterKey(cookieFile)
		if err != nil {
			return nil, err
		}
		loaded, err := loadCookieFile(cookieFile, key)
		if err != nil {
			return nil, err
		}
		cookies = append(cookies, loaded...)
	}
	cookieutil.SortByExpiry(cookies)
	return cookies, nil
}

func loadMasterKey(cookieFile string) ([]byte, error) {
	localStatePath, err := localStatePathForCookieFile(cookieFile)
	if err != nil {
		return nil, err
	}
	raw, err := os.ReadFile(localStatePath)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil, errdefs.ErrNotFound
		}
		return nil, err
	}

	var state localState
	if err := json.Unmarshal(raw, &state); err != nil {
		return nil, fmt.Errorf("%w: %v", errdefs.ErrInvalidStore, err)
	}
	if state.OSCrypt.EncryptedKey == "" {
		return nil, errdefs.ErrDecrypt
	}

	encryptedKey, err := base64.StdEncoding.DecodeString(state.OSCrypt.EncryptedKey)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", errdefs.ErrDecrypt, err)
	}
	if bytes.HasPrefix(encryptedKey, []byte("DPAPI")) {
		encryptedKey = encryptedKey[5:]
	}
	if len(encryptedKey) == 0 {
		return nil, errdefs.ErrDecrypt
	}
	return decryptDPAPI(encryptedKey)
}

func localStatePathForCookieFile(cookieFile string) (string, error) {
	parent := filepath.Dir(cookieFile)
	candidates := []string{
		filepath.Join(parent, "..", "..", "Local State"),
		filepath.Join(parent, "..", "Local State"),
		filepath.Join(parent, "Local State"),
	}
	for _, candidate := range candidates {
		if _, err := os.Stat(candidate); err == nil {
			return filepath.Clean(candidate), nil
		}
	}
	return filepath.Clean(candidates[0]), nil
}

func decryptDPAPI(data []byte) ([]byte, error) {
	if len(data) == 0 {
		return nil, errdefs.ErrDecrypt
	}

	in := windows.DataBlob{
		Size: uint32(len(data)),
		Data: &data[0],
	}
	var out windows.DataBlob
	if err := windows.CryptUnprotectData(&in, nil, nil, 0, nil, 0, &out); err != nil {
		return nil, fmt.Errorf("%w: %v", errdefs.ErrDecrypt, err)
	}
	if out.Data == nil || out.Size == 0 {
		return nil, errdefs.ErrDecrypt
	}
	defer windows.LocalFree(windows.Handle(unsafe.Pointer(out.Data)))

	plaintext := unsafe.Slice(out.Data, out.Size)
	return append([]byte(nil), plaintext...), nil
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
	query := `SELECT host_key, path, is_secure, expires_utc, name, value, encrypted_value, is_httponly FROM cookies`
	if version < 10 {
		query = `SELECT host_key, path, secure, expires_utc, name, value, encrypted_value, is_httponly FROM cookies`
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
			host     string
			path     string
			secure   int64
			expires  int64
			name     string
			value    string
			enc      []byte
			httpOnly int64
		)
		if err := rows.Scan(&host, &path, &secure, &expires, &name, &value, &enc, &httpOnly); err != nil {
			return nil, err
		}
		decrypted, err := decryptValue(value, enc, key, version >= 24)
		if err != nil {
			return nil, err
		}
		cookies = append(cookies, &http.Cookie{
			Name:     name,
			Value:    decrypted,
			Domain:   host,
			Path:     normalizePath(path),
			Secure:   secure != 0,
			HttpOnly: httpOnly != 0,
			Expires:  chromiumExpiry(expires),
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
	if len(key) == 0 {
		return "", errdefs.ErrDecrypt
	}

	payload := encrypted[3:]
	if len(payload) < 12+16 {
		return "", errdefs.ErrDecrypt
	}
	nonce := payload[:12]
	ciphertext := payload[12:]

	block, err := aes.NewCipher(key)
	if err != nil {
		return "", err
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return "", err
	}
	plaintext, err := aead.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return "", errdefs.ErrDecrypt
	}
	if (hasDomainHash || prefix == "v20") && len(plaintext) >= 32 {
		plaintext = plaintext[32:]
	}
	return string(plaintext), nil
}

func normalizePath(path string) string {
	if path == "" {
		return "/"
	}
	return path
}
