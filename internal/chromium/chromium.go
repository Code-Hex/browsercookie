package chromium

import (
	"os"

	"github.com/Code-Hex/browsercookie/internal/browsercfg"
	"github.com/Code-Hex/browsercookie/internal/secrets"
)

type secretRef struct {
	Service string
	Account string
}

type linuxLibsecretRef struct {
	Schema      string
	Application string
}

type linuxKWalletRef struct {
	Folder string
	Key    string
}

type windowsKeySource string

// Browser describes a Chromium-based browser family.
type Browser struct {
	Name               string
	CookieFilePatterns []string
	Secrets            []secretRef
	LinuxLibsecretRefs []linuxLibsecretRef
	LinuxKWalletRefs   []linuxKWalletRef
	LocalStatePaths    []string
	WindowsKeySources  []windowsKeySource
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

// BrowserFromSpec builds a Chromium browser definition from config metadata.
func BrowserFromSpec(spec browsercfg.ChromiumSpec) Browser {
	return browserFromSpec(spec)
}

func browserFromSpec(spec browsercfg.ChromiumSpec) Browser {
	browser := Browser{
		Name:               spec.Name,
		CookieFilePatterns: spec.CurrentCookiePatterns(),
		LocalStatePaths:    spec.CurrentLocalStatePaths(),
	}
	secrets := spec.CurrentSecrets()
	if len(secrets) > 0 {
		browser.Secrets = make([]secretRef, 0, len(secrets))
		for _, secret := range secrets {
			browser.Secrets = append(browser.Secrets, secretRef{
				Service: secret.Service,
				Account: secret.Account,
			})
		}
	}
	libsecretRefs := spec.CurrentLinuxLibsecretRefs()
	if len(libsecretRefs) > 0 {
		browser.LinuxLibsecretRefs = make([]linuxLibsecretRef, 0, len(libsecretRefs))
		for _, ref := range libsecretRefs {
			browser.LinuxLibsecretRefs = append(browser.LinuxLibsecretRefs, linuxLibsecretRef{
				Schema:      ref.Schema,
				Application: ref.Application,
			})
		}
	}
	kwalletRefs := spec.CurrentLinuxKWalletRefs()
	if len(kwalletRefs) > 0 {
		browser.LinuxKWalletRefs = make([]linuxKWalletRef, 0, len(kwalletRefs))
		for _, ref := range kwalletRefs {
			browser.LinuxKWalletRefs = append(browser.LinuxKWalletRefs, linuxKWalletRef{
				Folder: ref.Folder,
				Key:    ref.Key,
			})
		}
	}
	keySources := spec.CurrentWindowsKeySources()
	if len(keySources) > 0 {
		browser.WindowsKeySources = make([]windowsKeySource, 0, len(keySources))
		for _, source := range keySources {
			browser.WindowsKeySources = append(browser.WindowsKeySources, windowsKeySource(source))
		}
	}
	return browser
}

func dedupeCookieFiles(paths []string) []string {
	seenPaths := map[string]struct{}{}
	seenInfos := make([]os.FileInfo, 0, len(paths))
	out := make([]string, 0, len(paths))
	for _, path := range paths {
		if _, ok := seenPaths[path]; ok {
			continue
		}
		info, err := os.Stat(path)
		if err == nil {
			duplicate := false
			for _, seenInfo := range seenInfos {
				if os.SameFile(info, seenInfo) {
					duplicate = true
					break
				}
			}
			if duplicate {
				continue
			}
			seenInfos = append(seenInfos, info)
		}
		seenPaths[path] = struct{}{}
		out = append(out, path)
	}
	return out
}
