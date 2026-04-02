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

const (
	windowsEncryptedKeySource         windowsKeySource = "encrypted_key"
	windowsAppBoundEncryptedKeySource windowsKeySource = "app_bound_encrypted_key"
)

type localState struct {
	OSCrypt struct {
		EncryptedKey         string `json:"encrypted_key"`
		AppBoundEncryptedKey string `json:"app_bound_encrypted_key"`
	} `json:"os_crypt"`
}

type windowsKeyMaterial struct {
	legacyKey            []byte
	appBoundEncryptedKey string
}

// Load reads cookies from the configured Chromium browser store paths.
func (l Loader) Load(browser Browser, cookieFiles, domains []string) ([]*http.Cookie, error) {
	if len(cookieFiles) == 0 {
		cookieFiles = pathutil.Expand(browser.CookieFilePatterns)
	}
	cookieFiles = dedupeCookieFiles(cookieFiles)
	if len(cookieFiles) == 0 {
		return nil, errdefs.ErrNotFound
	}

	var cookies []*http.Cookie
	for _, cookieFile := range cookieFiles {
		keys, err := loadKeyMaterial(browser, cookieFile)
		if err != nil {
			return nil, err
		}
		loaded, err := loadCookieFile(cookieFile, keys, domains)
		if err != nil {
			return nil, err
		}
		cookies = append(cookies, loaded...)
	}
	if len(cookies) == 0 {
		return nil, errdefs.ErrNotFound
	}
	cookieutil.SortByExpiry(cookies)
	return cookies, nil
}

func loadKeyMaterial(browser Browser, cookieFile string) (windowsKeyMaterial, error) {
	localStatePath, err := localStatePathForCookieFile(browser, cookieFile)
	if err != nil {
		return windowsKeyMaterial{}, err
	}
	state, err := parseLocalState(localStatePath)
	if err != nil {
		return windowsKeyMaterial{}, err
	}
	return resolveKeyMaterial(browser, state)
}

func parseLocalState(path string) (localState, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return localState{}, errdefs.ErrNotFound
		}
		return localState{}, err
	}

	var state localState
	if err := json.Unmarshal(raw, &state); err != nil {
		return localState{}, fmt.Errorf("%w: %v", errdefs.ErrInvalidStore, err)
	}
	return state, nil
}

func resolveKeyMaterial(browser Browser, state localState) (windowsKeyMaterial, error) {
	keySources := browser.WindowsKeySources
	if len(keySources) == 0 {
		keySources = []windowsKeySource{
			windowsEncryptedKeySource,
			windowsAppBoundEncryptedKeySource,
		}
	}

	var material windowsKeyMaterial
	for _, source := range keySources {
		switch source {
		case windowsEncryptedKeySource:
			if state.OSCrypt.EncryptedKey == "" {
				continue
			}
			key, err := decodeLegacyMasterKey(state.OSCrypt.EncryptedKey)
			if err != nil {
				return windowsKeyMaterial{}, err
			}
			material.legacyKey = key
		case windowsAppBoundEncryptedKeySource:
			if state.OSCrypt.AppBoundEncryptedKey != "" {
				material.appBoundEncryptedKey = state.OSCrypt.AppBoundEncryptedKey
			}
		}
	}

	if len(material.legacyKey) == 0 && material.appBoundEncryptedKey == "" {
		return windowsKeyMaterial{}, errdefs.ErrDecrypt
	}
	return material, nil
}

func decodeLegacyMasterKey(encoded string) ([]byte, error) {
	encryptedKey, err := base64.StdEncoding.DecodeString(encoded)
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

func localStatePathForCookieFile(browser Browser, cookieFile string) (string, error) {
	parent := filepath.Dir(cookieFile)
	candidates := make([]string, 0, len(browser.LocalStatePaths))
	for _, path := range browser.LocalStatePaths {
		candidate := filepath.Clean(filepath.Join(parent, filepath.FromSlash(path)))
		candidates = append(candidates, candidate)
		if _, err := os.Stat(candidate); err == nil {
			return candidate, nil
		}
	}
	if len(candidates) == 0 {
		return "", errdefs.ErrNotFound
	}
	return candidates[0], nil
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

func loadCookieFile(path string, keys windowsKeyMaterial, domains []string) ([]*http.Cookie, error) {
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
	query, args := cookieutil.SQLiteWhere(query, "host_key", domains)
	rows, err := db.Query(query, args...)
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
		decrypted, err := decryptValue(value, enc, keys, version >= 24)
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

func decryptValue(plain string, encrypted []byte, keys windowsKeyMaterial, hasDomainHash bool) (string, error) {
	if plain != "" || len(encrypted) < 3 {
		return plain, nil
	}

	prefix := string(encrypted[:3])
	if prefix != "v10" && prefix != "v11" && prefix != "v20" {
		return plain, nil
	}
	if prefix == "v20" {
		return "", appBoundUnsupportedError(keys)
	}
	if len(keys.legacyKey) == 0 {
		return "", errdefs.ErrDecrypt
	}

	payload := encrypted[3:]
	if len(payload) < 12+16 {
		return "", errdefs.ErrDecrypt
	}
	nonce := payload[:12]
	ciphertext := payload[12:]

	block, err := aes.NewCipher(keys.legacyKey)
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
	if hasDomainHash {
		if len(plaintext) < 32 {
			return "", errdefs.ErrDecrypt
		}
		plaintext = plaintext[32:]
	}
	return string(plaintext), nil
}

func appBoundUnsupportedError(keys windowsKeyMaterial) error {
	if keys.appBoundEncryptedKey != "" {
		return fmt.Errorf("%w: chromium v20 cookies require app-bound decryption via the browser elevation service", errdefs.ErrUnsupported)
	}
	return fmt.Errorf("%w: chromium v20 cookies are app-bound encrypted and no supported key material is available", errdefs.ErrUnsupported)
}

func normalizePath(path string) string {
	if path == "" {
		return "/"
	}
	return path
}
