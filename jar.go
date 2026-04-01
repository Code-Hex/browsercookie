package browsercookie

import (
	"fmt"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"strings"
)

// Jar converts cookies into a net/http cookie jar.
func Jar(cookies []*http.Cookie) (*cookiejar.Jar, error) {
	jar, err := cookiejar.New(nil)
	if err != nil {
		return nil, err
	}
	for _, cookie := range cookies {
		if cookie == nil {
			continue
		}
		u, err := urlForCookie(cookie)
		if err != nil {
			return nil, err
		}
		jar.SetCookies(u, []*http.Cookie{cookie})
	}
	return jar, nil
}

func urlForCookie(cookie *http.Cookie) (*url.URL, error) {
	host := strings.TrimPrefix(cookie.Domain, ".")
	if host == "" {
		return nil, fmt.Errorf("cookie %q: %w", cookie.Name, ErrInvalidStore)
	}
	scheme := "http"
	if cookie.Secure {
		scheme = "https"
	}
	path := cookie.Path
	if path == "" {
		path = "/"
	}
	return &url.URL{
		Scheme: scheme,
		Host:   host,
		Path:   path,
	}, nil
}
