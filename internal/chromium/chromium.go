package chromium

import "github.com/Code-Hex/browsercookie/internal/secrets"

type secretRef struct {
	Service string
	Account string
}

// Browser describes a Chromium-based browser family.
type Browser struct {
	Name               string
	CookieFilePatterns []string
	Secrets            []secretRef
}

// Loader reads Chromium cookie databases.
type Loader struct {
	secretProvider secrets.Provider
}

// NewLoader builds a Chromium loader with the given secret provider.
func NewLoader(secretProvider secrets.Provider) Loader {
	return Loader{secretProvider: secretProvider}
}

var (
	// ChromeBrowser describes Google Chrome.
	ChromeBrowser = Browser{
		Name: "chrome",
		CookieFilePatterns: []string{
			"~/Library/Application Support/Google/Chrome/Default/Cookies",
			"~/Library/Application Support/Google/Chrome/Profile */Cookies",
		},
		Secrets: []secretRef{
			{Service: "Chrome Safe Storage", Account: "Chrome"},
		},
	}
	// BraveBrowser describes Brave.
	BraveBrowser = Browser{
		Name: "brave",
		CookieFilePatterns: []string{
			"~/Library/Application Support/BraveSoftware/Brave-Browser/Default/Cookies",
			"~/Library/Application Support/BraveSoftware/Brave-Browser/Profile */Cookies",
		},
		Secrets: []secretRef{
			{Service: "Brave Safe Storage", Account: "Brave"},
		},
	}
	// ChromiumBrowser describes Chromium.
	ChromiumBrowser = Browser{
		Name: "chromium",
		CookieFilePatterns: []string{
			"~/Library/Application Support/Chromium/Default/Cookies",
			"~/Library/Application Support/Chromium/Profile */Cookies",
		},
		Secrets: []secretRef{
			{Service: "Chromium Safe Storage", Account: "Chromium"},
			{Service: "Chrome Safe Storage", Account: "Chrome"},
		},
	}
	// VivaldiBrowser describes Vivaldi.
	VivaldiBrowser = Browser{
		Name: "vivaldi",
		CookieFilePatterns: []string{
			"~/Library/Application Support/Vivaldi/Default/Cookies",
			"~/Library/Application Support/Vivaldi/Profile */Cookies",
		},
		Secrets: []secretRef{
			{Service: "Vivaldi Safe Storage", Account: "Vivaldi"},
			{Service: "Chrome Safe Storage", Account: "Chrome"},
		},
	}
	// EdgeBrowser describes Microsoft Edge.
	EdgeBrowser = Browser{
		Name: "edge",
		CookieFilePatterns: []string{
			"~/Library/Application Support/Microsoft/Edge/Default/Cookies",
			"~/Library/Application Support/Microsoft/Edge/Profile */Cookies",
		},
		Secrets: []secretRef{
			{Service: "Microsoft Edge Safe Storage", Account: "Microsoft Edge"},
		},
	}
	// EdgeDevBrowser describes Microsoft Edge Dev.
	EdgeDevBrowser = Browser{
		Name: "edge-dev",
		CookieFilePatterns: []string{
			"~/Library/Application Support/Microsoft/Edge Dev/Default/Cookies",
			"~/Library/Application Support/Microsoft/Edge Dev/Profile */Cookies",
		},
		Secrets: []secretRef{
			{Service: "Microsoft Edge Dev Safe Storage", Account: "Microsoft Edge Dev"},
			{Service: "Microsoft Edge Safe Storage", Account: "Microsoft Edge"},
		},
	}
)
