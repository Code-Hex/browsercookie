package browsercookie

import (
	"errors"
	"fmt"
	"net/http"

	chromiumloader "github.com/Code-Hex/browsercookie/internal/chromium"
	"github.com/Code-Hex/browsercookie/internal/cookieutil"
	"github.com/Code-Hex/browsercookie/internal/firefox"
	"github.com/Code-Hex/browsercookie/internal/safari"
	"github.com/Code-Hex/browsercookie/internal/secrets"
)

type browserLoadCall struct {
	name string
	load func(options) ([]*http.Cookie, error)
}

var chromiumSecretProvider = secrets.Default

var loadOrder = []browserLoadCall{
	{name: chromiumloader.BraveBrowser.Name, load: loadBrave},
	{name: chromiumloader.ChromeBrowser.Name, load: loadChrome},
	{name: chromiumloader.ChromiumBrowser.Name, load: loadChromium},
	{name: chromiumloader.VivaldiBrowser.Name, load: loadVivaldi},
	{name: chromiumloader.EdgeBrowser.Name, load: loadEdge},
	{name: chromiumloader.EdgeDevBrowser.Name, load: loadEdgeDev},
	{name: firefox.FirefoxBrowser.Name, load: loadFirefox},
	{name: safari.SafariBrowser.Name, load: loadSafari},
}

// Brave loads cookies from Brave.
func Brave(opts ...Option) ([]*http.Cookie, error) {
	return loadBrave(collectOptions(opts...))
}

// Chrome loads cookies from Google Chrome.
func Chrome(opts ...Option) ([]*http.Cookie, error) {
	return loadChrome(collectOptions(opts...))
}

// Chromium loads cookies from Chromium.
func Chromium(opts ...Option) ([]*http.Cookie, error) {
	return loadChromium(collectOptions(opts...))
}

// Vivaldi loads cookies from Vivaldi.
func Vivaldi(opts ...Option) ([]*http.Cookie, error) {
	return loadVivaldi(collectOptions(opts...))
}

// Edge loads cookies from Microsoft Edge.
func Edge(opts ...Option) ([]*http.Cookie, error) {
	return loadEdge(collectOptions(opts...))
}

// EdgeDev loads cookies from Microsoft Edge Dev.
func EdgeDev(opts ...Option) ([]*http.Cookie, error) {
	return loadEdgeDev(collectOptions(opts...))
}

// Firefox loads cookies from Firefox.
func Firefox(opts ...Option) ([]*http.Cookie, error) {
	return loadFirefox(collectOptions(opts...))
}

// Safari loads cookies from Safari.
func Safari(opts ...Option) ([]*http.Cookie, error) {
	return loadSafari(collectOptions(opts...))
}

// Load tries every supported browser in a fixed order and returns merged cookies.
func Load(opts ...Option) ([]*http.Cookie, error) {
	cfg := collectOptions(opts...)
	var cookies []*http.Cookie
	var errs []error
	var sawNotFound bool
	var sawUnsupported bool
	for _, loader := range loadOrder {
		loaded, err := loader.load(cfg)
		if err != nil {
			switch {
			case errors.Is(err, ErrNotFound):
				sawNotFound = true
				continue
			case errors.Is(err, ErrUnsupported):
				sawUnsupported = true
				continue
			default:
				errs = append(errs, err)
				continue
			}
		}
		cookies = append(cookies, loaded...)
	}
	if len(cookies) > 0 {
		cookieutil.SortByExpiry(cookies)
		return cookies, nil
	}
	if len(errs) > 0 {
		return nil, errors.Join(errs...)
	}
	if sawNotFound {
		return nil, ErrNotFound
	}
	if sawUnsupported {
		return nil, ErrUnsupported
	}
	return nil, ErrNotFound
}

func loadBrave(cfg options) ([]*http.Cookie, error) {
	return loadChromiumBrowser(chromiumloader.BraveBrowser, cfg)
}

func loadChrome(cfg options) ([]*http.Cookie, error) {
	return loadChromiumBrowser(chromiumloader.ChromeBrowser, cfg)
}

func loadChromium(cfg options) ([]*http.Cookie, error) {
	return loadChromiumBrowser(chromiumloader.ChromiumBrowser, cfg)
}

func loadVivaldi(cfg options) ([]*http.Cookie, error) {
	return loadChromiumBrowser(chromiumloader.VivaldiBrowser, cfg)
}

func loadEdge(cfg options) ([]*http.Cookie, error) {
	return loadChromiumBrowser(chromiumloader.EdgeBrowser, cfg)
}

func loadEdgeDev(cfg options) ([]*http.Cookie, error) {
	return loadChromiumBrowser(chromiumloader.EdgeDevBrowser, cfg)
}

func loadFirefox(cfg options) ([]*http.Cookie, error) {
	loader := firefox.NewLoader()
	cookies, err := loader.Load(firefox.FirefoxBrowser, cfg.cookieFilesCopy())
	if err != nil {
		return nil, fmt.Errorf("%s: %w", firefox.FirefoxBrowser.Name, err)
	}
	return cookies, nil
}

func loadSafari(cfg options) ([]*http.Cookie, error) {
	loader := safari.NewLoader()
	cookies, err := loader.Load(safari.SafariBrowser, cfg.cookieFilesCopy())
	if err != nil {
		return nil, fmt.Errorf("%s: %w", safari.SafariBrowser.Name, err)
	}
	return cookies, nil
}

func loadChromiumBrowser(browser chromiumloader.Browser, cfg options) ([]*http.Cookie, error) {
	loader := chromiumloader.NewLoader(chromiumSecretProvider())
	cookies, err := loader.Load(browser, cfg.cookieFilesCopy())
	if err != nil {
		return nil, fmt.Errorf("%s: %w", browser.Name, err)
	}
	return cookies, nil
}
