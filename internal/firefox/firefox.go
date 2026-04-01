package firefox

import "github.com/Code-Hex/browsercookie/internal/browsercfg"

// Browser describes a Firefox-family browser.
type Browser struct {
	Name            string
	ProfilePatterns []string
}

// Loader reads Firefox cookie stores.
type Loader struct{}

// NewLoader builds a Firefox loader.
func NewLoader() Loader {
	return Loader{}
}

var (
	// FirefoxBrowser describes Firefox.
	FirefoxBrowser = browserFromSpec(browsercfg.MustMozilla("firefox"))
	// LibreWolfBrowser describes LibreWolf.
	LibreWolfBrowser = browserFromSpec(browsercfg.MustMozilla("librewolf"))
	// ZenBrowser describes Zen.
	ZenBrowser = browserFromSpec(browsercfg.MustMozilla("zen"))
)

func browserFromSpec(spec browsercfg.MozillaSpec) Browser {
	return Browser{
		Name:            spec.Name,
		ProfilePatterns: spec.CurrentProfilePatterns(),
	}
}
