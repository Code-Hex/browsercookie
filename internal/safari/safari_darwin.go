//go:build darwin

package safari

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"math"
	"net/http"
	"os"
	"path/filepath"
	"time"

	"github.com/Code-Hex/browsercookie/internal/cookieutil"
	"github.com/Code-Hex/browsercookie/internal/errdefs"
	"github.com/Code-Hex/browsercookie/internal/pathutil"
)

const appleToUnixTime = int64(978307200)

// Load reads cookies from Safari binary cookie stores.
func (Loader) Load(browser Browser, cookieFiles []string) ([]*http.Cookie, error) {
	files := append([]string(nil), cookieFiles...)
	if len(files) == 0 {
		files = pathutil.Expand(browser.CookieFilePatterns)
	}
	if len(files) == 0 {
		return nil, errdefs.ErrNotFound
	}

	var cookies []*http.Cookie
	for _, file := range files {
		loaded, err := parseBinaryCookies(file)
		if err != nil {
			return nil, err
		}
		cookies = append(cookies, loaded...)
	}
	cookieutil.SortByExpiry(cookies)
	return cookies, nil
}

func parseBinaryCookies(path string) ([]*http.Cookie, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil, errdefs.ErrNotFound
		}
		return nil, err
	}
	if len(data) < 8 || string(data[:4]) != "cook" {
		return nil, errdefs.ErrInvalidStore
	}
	pageCount := int(binary.BigEndian.Uint32(data[4:8]))
	if len(data) < 8+pageCount*4 {
		return nil, errdefs.ErrInvalidStore
	}
	offset := 8
	pageSizes := make([]int, 0, pageCount)
	for i := 0; i < pageCount; i++ {
		size := int(binary.BigEndian.Uint32(data[offset : offset+4]))
		offset += 4
		pageSizes = append(pageSizes, size)
	}

	var cookies []*http.Cookie
	for _, size := range pageSizes {
		if offset+size > len(data) {
			return nil, errdefs.ErrInvalidStore
		}
		pageCookies, err := parsePage(data[offset : offset+size])
		if err != nil {
			return nil, err
		}
		cookies = append(cookies, pageCookies...)
		offset += size
	}
	return cookies, nil
}

func parsePage(page []byte) ([]*http.Cookie, error) {
	if len(page) < 12 || !bytes.Equal(page[:4], []byte{0x00, 0x00, 0x01, 0x00}) {
		return nil, errdefs.ErrInvalidStore
	}
	count := int(binary.LittleEndian.Uint32(page[4:8]))
	if len(page) < 8+count*4+4 {
		return nil, errdefs.ErrInvalidStore
	}
	offset := 8
	cookieOffsets := make([]int, 0, count)
	for i := 0; i < count; i++ {
		cookieOffsets = append(cookieOffsets, int(binary.LittleEndian.Uint32(page[offset:offset+4])))
		offset += 4
	}

	var cookies []*http.Cookie
	for _, cookieOffset := range cookieOffsets {
		cookie, err := parseCookie(page, cookieOffset)
		if err != nil {
			return nil, err
		}
		cookies = append(cookies, cookie)
	}
	return cookies, nil
}

func parseCookie(page []byte, offset int) (*http.Cookie, error) {
	if offset+48 > len(page) {
		return nil, errdefs.ErrInvalidStore
	}
	cookieSize := int(binary.LittleEndian.Uint32(page[offset : offset+4]))
	if offset+cookieSize > len(page) {
		return nil, errdefs.ErrInvalidStore
	}
	record := page[offset : offset+cookieSize]
	flags := binary.LittleEndian.Uint32(record[8:12])
	hostOffset := int(binary.LittleEndian.Uint32(record[16:20]))
	nameOffset := int(binary.LittleEndian.Uint32(record[20:24]))
	pathOffset := int(binary.LittleEndian.Uint32(record[24:28]))
	valueOffset := int(binary.LittleEndian.Uint32(record[28:32]))
	commentOffset := int(binary.LittleEndian.Uint32(record[32:36]))

	expiry, err := readSafariFloat64(record[40:48])
	if err != nil {
		return nil, err
	}
	host, err := readCString(record, hostOffset)
	if err != nil {
		return nil, err
	}
	name, err := readCString(record, nameOffset)
	if err != nil {
		return nil, err
	}
	path, err := readCString(record, pathOffset)
	if err != nil {
		return nil, err
	}
	value, err := readCString(record, valueOffset)
	if err != nil {
		return nil, err
	}
	if commentOffset != 0 {
		if _, err := readCString(record, commentOffset); err != nil {
			return nil, err
		}
	}

	return &http.Cookie{
		Name:     name,
		Value:    value,
		Domain:   host,
		Path:     normalizePath(path),
		Secure:   flags&0x1 != 0,
		HttpOnly: flags&0x4 != 0,
		Expires:  time.Unix(int64(expiry)+appleToUnixTime, 0).UTC(),
	}, nil
}

func readSafariFloat64(raw []byte) (float64, error) {
	if len(raw) != 8 {
		return 0, errdefs.ErrInvalidStore
	}
	return math.Float64frombits(binary.LittleEndian.Uint64(raw)), nil
}

func readCString(record []byte, offset int) (string, error) {
	if offset < 0 || offset >= len(record) {
		return "", errdefs.ErrInvalidStore
	}
	for end := offset; end < len(record); end++ {
		if record[end] == 0 {
			return string(record[offset:end]), nil
		}
	}
	return "", fmt.Errorf("%w: unterminated string in %s", errdefs.ErrInvalidStore, filepath.Base("Cookies.binarycookies"))
}

func normalizePath(path string) string {
	if path == "" {
		return "/"
	}
	return path
}
