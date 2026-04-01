//go:build !darwin && !linux && !windows

package firefox

import (
	"net/http"

	"github.com/Code-Hex/browsercookie/internal/errdefs"
)

func (Loader) Load(browser Browser, cookieFiles, domains []string) ([]*http.Cookie, error) {
	return nil, errdefs.ErrUnsupported
}
