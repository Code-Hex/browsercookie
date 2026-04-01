package cookieutil

import (
	"math"
	"net/http"
	"sort"
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
