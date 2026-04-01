package browsercookie

import (
	"errors"
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"
)

func TestLoadSkipsNotFoundAndReturnsSortedCookies(t *testing.T) {
	original := loadOrder
	t.Cleanup(func() { loadOrder = original })

	loadOrder = []browserLoadCall{
		{
			name: "missing",
			load: func(options) ([]*http.Cookie, error) {
				return nil, ErrNotFound
			},
		},
		{
			name: "present",
			load: func(options) ([]*http.Cookie, error) {
				return []*http.Cookie{
					{Name: "late", Domain: "example.com", Path: "/", Expires: time.Unix(20, 0).UTC()},
					{Name: "early", Domain: "example.com", Path: "/", Expires: time.Unix(10, 0).UTC()},
				}, nil
			},
		},
	}

	cookies, err := Load()
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}
	if len(cookies) != 2 {
		t.Fatalf("len(cookies) = %d, want 2", len(cookies))
	}
	if cookies[0].Name != "early" || cookies[1].Name != "late" {
		t.Fatalf("cookies order = %q, %q", cookies[0].Name, cookies[1].Name)
	}
}

func TestLoadReturnsNotFoundWhenEverythingIsMissing(t *testing.T) {
	original := loadOrder
	t.Cleanup(func() { loadOrder = original })

	loadOrder = []browserLoadCall{
		{name: "missing-a", load: func(options) ([]*http.Cookie, error) { return nil, ErrNotFound }},
		{name: "missing-b", load: func(options) ([]*http.Cookie, error) { return nil, ErrUnsupported }},
	}

	_, err := Load()
	if !errors.Is(err, ErrNotFound) {
		t.Fatalf("Load() error = %v, want ErrNotFound", err)
	}
}

func TestLoadReturnsUnsupportedWhenEverythingIsUnsupported(t *testing.T) {
	original := loadOrder
	t.Cleanup(func() { loadOrder = original })

	loadOrder = []browserLoadCall{
		{name: "unsupported-a", load: func(options) ([]*http.Cookie, error) { return nil, ErrUnsupported }},
		{name: "unsupported-b", load: func(options) ([]*http.Cookie, error) { return nil, ErrUnsupported }},
	}

	_, err := Load()
	if !errors.Is(err, ErrUnsupported) {
		t.Fatalf("Load() error = %v, want ErrUnsupported", err)
	}
}

func TestLoadReturnsJoinedErrorsWhenNothingSucceeds(t *testing.T) {
	original := loadOrder
	t.Cleanup(func() { loadOrder = original })

	loadOrder = []browserLoadCall{
		{name: "broken-a", load: func(options) ([]*http.Cookie, error) { return nil, errors.New("broken-a") }},
		{name: "broken-b", load: func(options) ([]*http.Cookie, error) { return nil, errors.New("broken-b") }},
	}

	_, err := Load()
	if err == nil {
		t.Fatal("Load() error = nil, want joined error")
	}
	if !strings.Contains(err.Error(), "broken-a") || !strings.Contains(err.Error(), "broken-b") {
		t.Fatalf("Load() error = %q, want both failures", err.Error())
	}
}

func TestJarKeepsDeterministicOverwriteOrder(t *testing.T) {
	expires := time.Now().Add(24 * time.Hour).UTC()
	jar, err := Jar([]*http.Cookie{
		{Name: "session", Value: "old", Domain: ".example.com", Path: "/", Expires: expires},
		{Name: "session", Value: "new", Domain: ".example.com", Path: "/", Expires: expires},
	})
	if err != nil {
		t.Fatalf("Jar() error = %v", err)
	}
	u, err := url.Parse("https://example.com/")
	if err != nil {
		t.Fatalf("url.Parse() error = %v", err)
	}
	cookies := jar.Cookies(u)
	if len(cookies) != 1 {
		t.Fatalf("len(jar cookies) = %d, want 1", len(cookies))
	}
	if cookies[0].Value != "new" {
		t.Fatalf("cookie value = %q, want %q", cookies[0].Value, "new")
	}
}
