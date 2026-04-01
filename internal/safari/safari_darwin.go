//go:build darwin

package safari

import (
	"net/http"

	"github.com/Code-Hex/browsercookie/internal/errdefs"
	"github.com/Code-Hex/browsercookie/internal/pathutil"
)

// Load reads cookies from Safari binary cookie stores.
func (Loader) Load(browser Browser, cookieFiles, domains []string) ([]*http.Cookie, error) {
	files := append([]string(nil), cookieFiles...)
	if len(files) == 0 {
		files = pathutil.Expand(browser.CookieFilePatterns)
	}
	if len(files) == 0 {
		return nil, errdefs.ErrNotFound
	}
	return loadBinaryCookieFiles(files, domains)
}
