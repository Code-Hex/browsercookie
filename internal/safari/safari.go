package safari

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
	Name: "safari",
	CookieFilePatterns: []string{
		"~/Library/Containers/com.apple.Safari/Data/Library/Cookies/Cookies.binarycookies",
		"~/Library/Cookies/Cookies.binarycookies",
	},
}
