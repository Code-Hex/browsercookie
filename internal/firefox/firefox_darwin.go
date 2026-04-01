//go:build darwin

package firefox

import (
	"bufio"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/Code-Hex/browsercookie/internal/cookieutil"
	"github.com/Code-Hex/browsercookie/internal/errdefs"
	"github.com/Code-Hex/browsercookie/internal/pathutil"
	"github.com/Code-Hex/browsercookie/internal/sqlitecopy"
	"github.com/pierrec/lz4/v4"
)

// Load reads cookies from the configured Firefox profile.
func (Loader) Load(browser Browser, cookieFiles []string) ([]*http.Cookie, error) {
	files := append([]string(nil), cookieFiles...)
	if len(files) == 0 {
		profiles := pathutil.Expand(browser.ProfilePatterns)
		if len(profiles) == 0 {
			return nil, errdefs.ErrNotFound
		}
		profilePath, err := parseProfile(profiles[0])
		if err != nil {
			return nil, err
		}
		files, err = defaultCookieFiles(profilePath)
		if err != nil {
			return nil, err
		}
	}

	var cookies []*http.Cookie
	for _, file := range files {
		loaded, err := loadCookieSource(file)
		if err != nil {
			return nil, err
		}
		cookies = append(cookies, loaded...)
	}
	cookieutil.SortByExpiry(cookies)
	return cookies, nil
}

type iniSection struct {
	name   string
	values map[string]string
}

func parseProfile(profile string) (string, error) {
	file, err := os.Open(profile)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return "", errdefs.ErrNotFound
		}
		return "", err
	}
	defer func() { _ = file.Close() }()

	sections, err := parseINI(file)
	if err != nil {
		return "", err
	}
	profileDir := filepath.Dir(profile)

	for _, section := range sections {
		if strings.HasPrefix(section.name, "Install") {
			if value, ok := section.values["Default"]; ok && value != "" {
				return expandProfilePath(profileDir, value), nil
			}
		}
	}

	var selected string
	for _, section := range sections {
		pathValue, ok := section.values["Path"]
		if !ok || pathValue == "" {
			continue
		}
		candidate := pathValue
		if section.values["IsRelative"] == "1" {
			candidate = filepath.Join(profileDir, pathValue)
		}
		if selected == "" {
			selected = candidate
		}
		if section.values["Default"] == "1" {
			selected = candidate
		}
	}
	if selected == "" {
		return "", errdefs.ErrNotFound
	}
	return expandProfilePath("", selected), nil
}

func parseINI(file *os.File) ([]iniSection, error) {
	scanner := bufio.NewScanner(file)
	var sections []iniSection
	var current *iniSection
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, ";") || strings.HasPrefix(line, "#") {
			continue
		}
		if strings.HasPrefix(line, "[") && strings.HasSuffix(line, "]") {
			sections = append(sections, iniSection{
				name:   strings.TrimSuffix(strings.TrimPrefix(line, "["), "]"),
				values: map[string]string{},
			})
			current = &sections[len(sections)-1]
			continue
		}
		if current == nil {
			continue
		}
		key, value, ok := strings.Cut(line, "=")
		if !ok {
			continue
		}
		current.values[strings.TrimSpace(key)] = strings.TrimSpace(value)
	}
	return sections, scanner.Err()
}

func expandProfilePath(profileDir, path string) string {
	if strings.HasPrefix(path, "~") {
		return filepath.Clean(pathutil.ExpandUser(path))
	}
	if filepath.IsAbs(path) || profileDir == "" {
		return filepath.Clean(path)
	}
	return filepath.Clean(filepath.Join(profileDir, path))
}

func defaultCookieFiles(profilePath string) ([]string, error) {
	if profilePath == "" {
		return nil, errdefs.ErrNotFound
	}
	cookieFile := filepath.Join(profilePath, "cookies.sqlite")
	if _, err := os.Stat(cookieFile); err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil, errdefs.ErrNotFound
		}
		return nil, err
	}
	files := []string{}
	for _, candidate := range []string{
		filepath.Join(profilePath, "sessionstore-backups", "recovery.js"),
		filepath.Join(profilePath, "sessionstore-backups", "recovery.json"),
		filepath.Join(profilePath, "sessionstore-backups", "recovery.jsonlz4"),
		filepath.Join(profilePath, "sessionstore.js"),
		filepath.Join(profilePath, "sessionstore.json"),
		filepath.Join(profilePath, "sessionstore.jsonlz4"),
	} {
		if _, err := os.Stat(candidate); err == nil {
			files = append(files, candidate)
		}
	}
	files = append(files, cookieFile)
	return files, nil
}

func loadCookieSource(path string) ([]*http.Cookie, error) {
	if filepath.Ext(path) == ".sqlite" {
		return loadSQLiteCookies(path)
	}
	return loadSessionCookies(path)
}

func loadSQLiteCookies(path string) ([]*http.Cookie, error) {
	db, cleanup, err := sqlitecopy.Open(path)
	if err != nil {
		return nil, err
	}
	defer func() { _ = cleanup() }()

	query := `SELECT host, path, isSecure, expiry, name, value, isHttpOnly FROM moz_cookies`
	rows, err := db.Query(query)
	if err != nil {
		if strings.Contains(err.Error(), "no such column") {
			rows, err = db.Query(`SELECT host, path, isSecure, expiry, name, value FROM moz_cookies`)
		}
	}
	if err != nil {
		if strings.Contains(err.Error(), "no such table") {
			return nil, errdefs.ErrInvalidStore
		}
		return nil, err
	}
	defer func() { _ = rows.Close() }()

	withHTTPOnly := true
	cols, err := rows.Columns()
	if err == nil && len(cols) == 6 {
		withHTTPOnly = false
	}

	var cookies []*http.Cookie
	for rows.Next() {
		var (
			host     string
			path     string
			secure   int64
			expiryMS int64
			name     string
			value    string
			httpOnly int64
		)
		if withHTTPOnly {
			if err := rows.Scan(&host, &path, &secure, &expiryMS, &name, &value, &httpOnly); err != nil {
				return nil, err
			}
		} else {
			if err := rows.Scan(&host, &path, &secure, &expiryMS, &name, &value); err != nil {
				return nil, err
			}
		}
		cookies = append(cookies, &http.Cookie{
			Name:     name,
			Value:    value,
			Domain:   host,
			Path:     normalizePath(path),
			Secure:   secure != 0,
			HttpOnly: httpOnly != 0,
			Expires:  firefoxExpiry(expiryMS),
		})
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return cookies, nil
}

func loadSessionCookies(path string) ([]*http.Cookie, error) {
	tmpPath, cleanup, err := sqlitecopy.Copy(path)
	if err != nil {
		return nil, err
	}
	defer func() { _ = cleanup() }()

	data, err := os.ReadFile(tmpPath)
	if err != nil {
		return nil, err
	}
	if strings.HasSuffix(path, ".jsonlz4") {
		if len(data) < 8 {
			return nil, errdefs.ErrInvalidStore
		}
		data, err = decompressMozillaLZ4(data[8:])
		if err != nil {
			return nil, err
		}
	}

	var payload sessionStore
	if err := json.Unmarshal(data, &payload); err != nil {
		return nil, fmt.Errorf("%w: %v", errdefs.ErrInvalidStore, err)
	}

	var cookies []*http.Cookie
	for _, cookie := range payload.Cookies {
		cookies = append(cookies, sessionCookieToHTTPCookie(cookie))
	}
	for _, window := range payload.Windows {
		for _, cookie := range window.Cookies {
			cookies = append(cookies, sessionCookieToHTTPCookie(cookie))
		}
	}
	return cookies, nil
}

type sessionStore struct {
	Windows []sessionWindow `json:"windows"`
	Cookies []sessionCookie `json:"cookies"`
}

type sessionWindow struct {
	Cookies []sessionCookie `json:"cookies"`
}

type sessionCookie struct {
	Host      string `json:"host"`
	Path      string `json:"path"`
	Name      string `json:"name"`
	Value     string `json:"value"`
	Secure    bool   `json:"secure"`
	HTTPOnly  bool   `json:"httponly"`
	HTTPOnly2 bool   `json:"httpOnly"`
	Expiry    int64  `json:"expiry"`
}

func sessionCookieToHTTPCookie(cookie sessionCookie) *http.Cookie {
	return &http.Cookie{
		Name:     cookie.Name,
		Value:    cookie.Value,
		Domain:   cookie.Host,
		Path:     normalizePath(cookie.Path),
		Secure:   cookie.Secure,
		HttpOnly: cookie.HTTPOnly || cookie.HTTPOnly2,
		Expires:  sessionExpiry(cookie.Expiry),
	}
}

func sessionExpiry(value int64) time.Time {
	if value <= 0 {
		return time.Time{}
	}
	return time.Unix(value, 0).UTC()
}

func firefoxExpiry(value int64) time.Time {
	if value <= 0 {
		return time.Time{}
	}
	return time.Unix(value, 0).UTC()
}

func normalizePath(path string) string {
	if path == "" {
		return "/"
	}
	return path
}

func decompressMozillaLZ4(src []byte) ([]byte, error) {
	if len(src) == 0 {
		return nil, errdefs.ErrInvalidStore
	}
	size := len(src) * 4
	if size < 256 {
		size = 256
	}
	for size <= 64*1024*1024 {
		dst := make([]byte, size)
		n, err := lz4.UncompressBlock(src, dst)
		if err == nil {
			return dst[:n], nil
		}
		if !strings.Contains(err.Error(), "short buffer") {
			return nil, fmt.Errorf("%w: %v", errdefs.ErrInvalidStore, err)
		}
		size *= 2
	}
	return nil, errdefs.ErrInvalidStore
}
