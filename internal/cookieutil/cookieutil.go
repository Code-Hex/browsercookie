package cookieutil

import (
	"math"
	"net/http"
	"sort"
	"strings"
)

// SortByExpiry sorts cookies in ascending expiry order while preserving ties.
func SortByExpiry(cookies []*http.Cookie) {
	sort.SliceStable(cookies, func(i, j int) bool {
		return expiryKey(cookies[i]) < expiryKey(cookies[j])
	})
}

func expiryKey(cookie *http.Cookie) int64 {
	if cookie == nil || cookie.Expires.IsZero() {
		return math.MinInt64
	}
	return cookie.Expires.Unix()
}

// FilterByDomains returns cookies that match one of the requested domains.
func FilterByDomains(cookies []*http.Cookie, domains []string) []*http.Cookie {
	matchers := normalizeDomains(domains)
	if len(matchers) == 0 {
		return append([]*http.Cookie(nil), cookies...)
	}

	filtered := make([]*http.Cookie, 0, len(cookies))
	for _, cookie := range cookies {
		if cookie == nil {
			continue
		}
		if domainMatches(cookie.Domain, matchers) {
			filtered = append(filtered, cookie)
		}
	}
	return filtered
}

func normalizeDomains(domains []string) []string {
	seen := map[string]struct{}{}
	normalized := make([]string, 0, len(domains))
	for _, domain := range domains {
		domain = strings.ToLower(strings.TrimSpace(strings.TrimPrefix(domain, ".")))
		if domain == "" {
			continue
		}
		if _, ok := seen[domain]; ok {
			continue
		}
		seen[domain] = struct{}{}
		normalized = append(normalized, domain)
	}
	return normalized
}

func domainMatches(cookieDomain string, wanted []string) bool {
	cookieDomain = strings.ToLower(strings.TrimSpace(strings.TrimPrefix(cookieDomain, ".")))
	if cookieDomain == "" {
		return false
	}
	for _, domain := range wanted {
		if cookieDomain == domain || strings.HasSuffix(cookieDomain, "."+domain) {
			return true
		}
	}
	return false
}
