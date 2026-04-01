package firefox

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

// FirefoxBrowser describes Firefox.
var FirefoxBrowser = Browser{
	Name: "firefox",
	ProfilePatterns: []string{
		"~/Library/Application Support/Firefox/profiles.ini",
	},
}
