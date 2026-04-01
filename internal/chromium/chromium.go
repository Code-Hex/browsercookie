package chromium

import (
	"github.com/Code-Hex/browsercookie/internal/browsercfg"
	"github.com/Code-Hex/browsercookie/internal/secrets"
)

type secretRef struct {
	Service string
	Account string
}

// Browser describes a Chromium-based browser family.
type Browser struct {
	Name               string
	CookieFilePatterns []string
	Secrets            []secretRef
	LinuxPasswordApps  []string
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
	ChromeBrowser = browserFromSpec(browsercfg.MustChromium("chrome"))
	// BraveBrowser describes Brave.
	BraveBrowser = browserFromSpec(browsercfg.MustChromium("brave"))
	// ChromiumBrowser describes Chromium.
	ChromiumBrowser = browserFromSpec(browsercfg.MustChromium("chromium"))
	// VivaldiBrowser describes Vivaldi.
	VivaldiBrowser = browserFromSpec(browsercfg.MustChromium("vivaldi"))
	// EdgeBrowser describes Microsoft Edge.
	EdgeBrowser = browserFromSpec(browsercfg.MustChromium("edge"))
	// EdgeDevBrowser describes Microsoft Edge Dev.
	EdgeDevBrowser = browserFromSpec(browsercfg.MustChromium("edge-dev"))
	// OperaBrowser describes Opera.
	OperaBrowser = browserFromSpec(browsercfg.MustChromium("opera"))
	// OperaGXBrowser describes Opera GX.
	OperaGXBrowser = browserFromSpec(browsercfg.MustChromium("opera-gx"))
	// ArcBrowser describes Arc.
	ArcBrowser = browserFromSpec(browsercfg.MustChromium("arc"))
)

func browserFromSpec(spec browsercfg.ChromiumSpec) Browser {
	browser := Browser{
		Name:               spec.Name,
		CookieFilePatterns: spec.CurrentCookiePatterns(),
		LinuxPasswordApps:  spec.CurrentLinuxPasswordApps(),
	}
	secrets := spec.CurrentSecrets()
	if len(secrets) == 0 {
		return browser
	}
	browser.Secrets = make([]secretRef, 0, len(secrets))
	for _, secret := range secrets {
		browser.Secrets = append(browser.Secrets, secretRef{
			Service: secret.Service,
			Account: secret.Account,
		})
	}
	return browser
}
