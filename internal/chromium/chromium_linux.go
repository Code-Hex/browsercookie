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
	"strings"
	"time"

	"github.com/Code-Hex/browsercookie/internal/cookieutil"
	"github.com/Code-Hex/browsercookie/internal/errdefs"
	"github.com/Code-Hex/browsercookie/internal/pathutil"
	"github.com/Code-Hex/browsercookie/internal/sqlitecopy"
	"github.com/godbus/dbus/v5"
	"golang.org/x/crypto/pbkdf2"
)

const (
	chromiumSalt            = "saltysalt"
	chromiumIterations      = 1
	chromiumKeyLength       = 16
	unixToNTEpochOffsetMicr = int64(11644473600 * 1_000_000)
	linuxDBusAppID          = "browsercookie"
)

var (
	chromiumIV = []byte("                ")

	newLinuxKeyringClient = func() (linuxKeyringClient, error) {
		conn, err := dbus.SessionBus()
		if err != nil {
			return nil, err
		}
		return &linuxDBusClient{conn: conn}, nil
	}
)

type linuxKeyringClient interface {
	SecretPassword(schema, application string) ([]byte, error)
	KWalletPassword(folder, key string) ([]byte, error)
}

type linuxDBusClient struct {
	conn *dbus.Conn
}

type secretServiceSecret struct {
	Session     dbus.ObjectPath
	Parameters  []byte
	Value       []byte
	ContentType string
}

type kwalletEndpoint struct {
	service string
	path    dbus.ObjectPath
}

var kwalletEndpoints = []kwalletEndpoint{
	{service: "org.kde.kwalletd6", path: "/modules/kwalletd6"},
	{service: "org.kde.kwalletd5", path: "/modules/kwalletd5"},
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
	keys := linuxKeys(browser)

	var cookies []*http.Cookie
	for _, cookieFile := range cookieFiles {
		loaded, err := loadCookieFileWithKeys(cookieFile, keys, domains)
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

func linuxKeys(browser Browser) [][]byte {
	keys := make([][]byte, 0, 4)
	seen := map[string]struct{}{}
	for _, password := range linuxPasswords(browser) {
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

func linuxPasswords(browser Browser) [][]byte {
	client, err := newLinuxKeyringClient()
	if err != nil {
		return nil
	}

	passwords := make([][]byte, 0, len(browser.LinuxLibsecretRefs)+len(browser.LinuxKWalletRefs))
	seen := map[string]struct{}{}
	for _, ref := range browser.LinuxLibsecretRefs {
		password, err := client.SecretPassword(ref.Schema, ref.Application)
		if err != nil || len(password) == 0 {
			continue
		}
		fingerprint := string(password)
		if _, ok := seen[fingerprint]; ok {
			continue
		}
		seen[fingerprint] = struct{}{}
		passwords = append(passwords, append([]byte(nil), password...))
	}
	for _, ref := range browser.LinuxKWalletRefs {
		password, err := client.KWalletPassword(ref.Folder, ref.Key)
		if err != nil || len(password) == 0 {
			continue
		}
		fingerprint := string(password)
		if _, ok := seen[fingerprint]; ok {
			continue
		}
		seen[fingerprint] = struct{}{}
		passwords = append(passwords, append([]byte(nil), password...))
	}
	return passwords
}

func (c *linuxDBusClient) SecretPassword(schema, application string) ([]byte, error) {
	attrs := map[string]string{
		"xdg:schema":  schema,
		"application": application,
	}

	service := c.conn.Object("org.freedesktop.secrets", "/org/freedesktop/secrets")
	var unlocked []dbus.ObjectPath
	var locked []dbus.ObjectPath
	if err := service.Call("org.freedesktop.Secret.Service.SearchItems", 0, attrs).Store(&unlocked, &locked); err != nil {
		return nil, err
	}

	item := firstObjectPath(unlocked)
	if item == "" {
		var prompt dbus.ObjectPath
		if err := service.Call("org.freedesktop.Secret.Service.Unlock", 0, locked).Store(&unlocked, &prompt); err != nil {
			return nil, err
		}
		item = firstObjectPath(unlocked)
	}
	if item == "" {
		return nil, errors.New("secret item not found")
	}

	var output dbus.Variant
	var session dbus.ObjectPath
	if err := service.Call("org.freedesktop.Secret.Service.OpenSession", 0, "plain", dbus.MakeVariant("")).Store(&output, &session); err != nil {
		return nil, err
	}

	var secrets map[dbus.ObjectPath]secretServiceSecret
	if err := service.Call("org.freedesktop.Secret.Service.GetSecrets", 0, []dbus.ObjectPath{item}, session).Store(&secrets); err != nil {
		return nil, err
	}
	secret, ok := secrets[item]
	if !ok {
		return nil, errors.New("secret payload not found")
	}
	return bytes.TrimSpace(secret.Value), nil
}

func (c *linuxDBusClient) KWalletPassword(folder, key string) ([]byte, error) {
	for _, endpoint := range kwalletEndpoints {
		obj := c.conn.Object(endpoint.service, endpoint.path)

		var wallet string
		if err := obj.Call("org.kde.KWallet.networkWallet", 0).Store(&wallet); err != nil {
			continue
		}

		var handle int32
		if err := obj.Call("org.kde.KWallet.open", 0, wallet, int64(0), linuxDBusAppID).Store(&handle); err != nil {
			continue
		}
		if handle < 0 {
			continue
		}

		var password string
		if err := obj.Call("org.kde.KWallet.readPassword", 0, handle, folder, key, linuxDBusAppID).Store(&password); err != nil {
			_ = obj.Call("org.kde.KWallet.close", 0, wallet, false)
			continue
		}
		_ = obj.Call("org.kde.KWallet.close", 0, wallet, false)
		return bytes.TrimSpace([]byte(password)), nil
	}
	return nil, errors.New("kwallet password not found")
}

func firstObjectPath(paths []dbus.ObjectPath) dbus.ObjectPath {
	if len(paths) == 0 {
		return ""
	}
	return paths[0]
}

func loadCookieFileWithKeys(path string, keys [][]byte, domains []string) ([]*http.Cookie, error) {
	var errs []error
	for _, key := range keys {
		cookies, err := loadCookieFile(path, key, domains)
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

func loadCookieFile(path string, key []byte, domains []string) ([]*http.Cookie, error) {
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
