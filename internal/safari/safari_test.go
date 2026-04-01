package safari

import (
	"encoding/binary"
	"math"
	"net/http"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestLoaderLoadParsesBinaryCookiesAcrossPages(t *testing.T) {
	t.Parallel()

	file := filepath.Join(t.TempDir(), "Cookies.binarycookies")
	content := buildBinaryCookies(
		buildPage(
			buildCookieRecord(".example.com", "a", "/", "one", 0x1, time.Unix(1_700_000_000, 0).UTC()),
		),
		buildPage(
			buildCookieRecord(".example.com", "b", "/secure", "two", 0x5, time.Unix(1_700_000_100, 0).UTC()),
		),
	)
	if err := os.WriteFile(file, content, 0o644); err != nil {
		t.Fatalf("WriteFile() error = %v", err)
	}

	loader := NewLoader()
	cookies, err := loader.Load(SafariBrowser, []string{file})
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}
	if len(cookies) != 2 {
		t.Fatalf("len(cookies) = %d, want 2", len(cookies))
	}

	first := cookieByName(cookies, "a")
	second := cookieByName(cookies, "b")
	if first == nil || first.Value != "one" || !first.Secure || first.HttpOnly {
		t.Fatalf("first cookie = %#v", first)
	}
	if second == nil || second.Value != "two" || !second.Secure || !second.HttpOnly {
		t.Fatalf("second cookie = %#v", second)
	}
}

func buildBinaryCookies(pages ...[]byte) []byte {
	total := 8 + len(pages)*4
	for _, page := range pages {
		total += len(page)
	}
	out := make([]byte, total)
	copy(out[:4], []byte("cook"))
	binary.BigEndian.PutUint32(out[4:8], uint32(len(pages)))

	offset := 8
	for _, page := range pages {
		binary.BigEndian.PutUint32(out[offset:offset+4], uint32(len(page)))
		offset += 4
	}
	for _, page := range pages {
		copy(out[offset:], page)
		offset += len(page)
	}
	return out
}

func buildPage(records ...[]byte) []byte {
	headerSize := 8 + len(records)*4 + 4
	size := headerSize
	for _, record := range records {
		size += len(record)
	}
	page := make([]byte, size)
	copy(page[:4], []byte{0x00, 0x00, 0x01, 0x00})
	binary.LittleEndian.PutUint32(page[4:8], uint32(len(records)))

	offset := 8
	recordOffset := headerSize
	for _, record := range records {
		binary.LittleEndian.PutUint32(page[offset:offset+4], uint32(recordOffset))
		offset += 4
		copy(page[recordOffset:], record)
		recordOffset += len(record)
	}
	return page
}

func buildCookieRecord(host, name, path, value string, flags uint32, expiry time.Time) []byte {
	headerSize := 56
	hostOffset := headerSize
	nameOffset := hostOffset + len(host) + 1
	pathOffset := nameOffset + len(name) + 1
	valueOffset := pathOffset + len(path) + 1
	totalSize := valueOffset + len(value) + 1
	record := make([]byte, totalSize)

	binary.LittleEndian.PutUint32(record[0:4], uint32(totalSize))
	binary.LittleEndian.PutUint32(record[8:12], flags)
	binary.LittleEndian.PutUint32(record[16:20], uint32(hostOffset))
	binary.LittleEndian.PutUint32(record[20:24], uint32(nameOffset))
	binary.LittleEndian.PutUint32(record[24:28], uint32(pathOffset))
	binary.LittleEndian.PutUint32(record[28:32], uint32(valueOffset))
	binary.LittleEndian.PutUint64(record[40:48], math.Float64bits(float64(expiry.Unix()-appleToUnixTime)))
	binary.LittleEndian.PutUint64(record[48:56], math.Float64bits(float64(expiry.Unix()-appleToUnixTime)))

	copy(record[hostOffset:], []byte(host))
	record[nameOffset-1] = 0
	copy(record[nameOffset:], []byte(name))
	record[pathOffset-1] = 0
	copy(record[pathOffset:], []byte(path))
	record[valueOffset-1] = 0
	copy(record[valueOffset:], []byte(value))
	record[totalSize-1] = 0

	return record
}

func cookieByName(cookies []*http.Cookie, name string) *http.Cookie {
	for _, cookie := range cookies {
		if cookie.Name == name {
			return cookie
		}
	}
	return nil
}
