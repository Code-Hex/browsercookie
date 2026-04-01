//go:build !darwin

package chromium

import (
	"net/http"

	"github.com/Code-Hex/browsercookie/internal/errdefs"
)

func (l Loader) Load(browser Browser, cookieFiles []string) ([]*http.Cookie, error) {
	return nil, errdefs.ErrUnsupported
}
