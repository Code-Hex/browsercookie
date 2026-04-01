package safari

import "github.com/Code-Hex/browsercookie/internal/browsercfg"

// Browser describes Safari cookie store locations.
type Browser struct {
	Name               string
	CookieFilePatterns []string
}

// Loader reads Safari binary cookie stores.
type Loader struct{}

// NewLoader builds a Safari loader.
func NewLoader() Loader {
	return Loader{}
}

// SafariBrowser describes Safari.
var SafariBrowser = Browser{
	Name:               browsercfg.MustSafari("safari").Name,
	CookieFilePatterns: browsercfg.MustSafari("safari").CurrentCookiePatterns(),
}
