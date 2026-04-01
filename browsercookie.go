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
	{name: chromiumloader.ArcBrowser.Name, load: loadArc},
	{name: chromiumloader.OperaBrowser.Name, load: loadOpera},
	{name: chromiumloader.OperaGXBrowser.Name, load: loadOperaGX},
	{name: firefox.FirefoxBrowser.Name, load: loadFirefox},
	{name: firefox.LibreWolfBrowser.Name, load: loadLibreWolf},
	{name: firefox.ZenBrowser.Name, load: loadZen},
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

// Arc loads cookies from Arc.
func Arc(opts ...Option) ([]*http.Cookie, error) {
	return loadArc(collectOptions(opts...))
}

// Opera loads cookies from Opera.
func Opera(opts ...Option) ([]*http.Cookie, error) {
	return loadOpera(collectOptions(opts...))
}

// OperaGX loads cookies from Opera GX.
func OperaGX(opts ...Option) ([]*http.Cookie, error) {
	return loadOperaGX(collectOptions(opts...))
}

// Firefox loads cookies from Firefox.
func Firefox(opts ...Option) ([]*http.Cookie, error) {
	return loadFirefox(collectOptions(opts...))
}

// LibreWolf loads cookies from LibreWolf.
func LibreWolf(opts ...Option) ([]*http.Cookie, error) {
	return loadLibreWolf(collectOptions(opts...))
}

// Zen loads cookies from Zen.
func Zen(opts ...Option) ([]*http.Cookie, error) {
	return loadZen(collectOptions(opts...))
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

func loadArc(cfg options) ([]*http.Cookie, error) {
	return loadChromiumBrowser(chromiumloader.ArcBrowser, cfg)
}

func loadOpera(cfg options) ([]*http.Cookie, error) {
	return loadChromiumBrowser(chromiumloader.OperaBrowser, cfg)
}

func loadOperaGX(cfg options) ([]*http.Cookie, error) {
	return loadChromiumBrowser(chromiumloader.OperaGXBrowser, cfg)
}

func loadFirefox(cfg options) ([]*http.Cookie, error) {
	loader := firefox.NewLoader()
	cookies, err := loader.Load(firefox.FirefoxBrowser, cfg.cookieFilesCopy())
	if err != nil {
		return nil, fmt.Errorf("%s: %w", firefox.FirefoxBrowser.Name, err)
	}
	return filterCookies(cookies, cfg.domainsCopy())
}

func loadLibreWolf(cfg options) ([]*http.Cookie, error) {
	loader := firefox.NewLoader()
	cookies, err := loader.Load(firefox.LibreWolfBrowser, cfg.cookieFilesCopy())
	if err != nil {
		return nil, fmt.Errorf("%s: %w", firefox.LibreWolfBrowser.Name, err)
	}
	return filterCookies(cookies, cfg.domainsCopy())
}

func loadZen(cfg options) ([]*http.Cookie, error) {
	loader := firefox.NewLoader()
	cookies, err := loader.Load(firefox.ZenBrowser, cfg.cookieFilesCopy())
	if err != nil {
		return nil, fmt.Errorf("%s: %w", firefox.ZenBrowser.Name, err)
	}
	return filterCookies(cookies, cfg.domainsCopy())
}

func loadSafari(cfg options) ([]*http.Cookie, error) {
	loader := safari.NewLoader()
	cookies, err := loader.Load(safari.SafariBrowser, cfg.cookieFilesCopy())
	if err != nil {
		return nil, fmt.Errorf("%s: %w", safari.SafariBrowser.Name, err)
	}
	return filterCookies(cookies, cfg.domainsCopy())
}

func loadChromiumBrowser(browser chromiumloader.Browser, cfg options) ([]*http.Cookie, error) {
	loader := chromiumloader.NewLoader(chromiumSecretProvider())
	cookies, err := loader.Load(browser, cfg.cookieFilesCopy())
	if err != nil {
		return nil, fmt.Errorf("%s: %w", browser.Name, err)
	}
	return filterCookies(cookies, cfg.domainsCopy())
}

func filterCookies(cookies []*http.Cookie, domains []string) ([]*http.Cookie, error) {
	filtered := cookieutil.FilterByDomains(cookies, domains)
	if len(filtered) == 0 {
		return nil, ErrNotFound
	}
	return filtered, nil
}
