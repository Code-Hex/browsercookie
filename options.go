package browsercookie

// Option mutates loader configuration.
type Option func(*options)

type options struct {
	cookieFiles          []string
	domains              []string
	electronAppPaths     []string
	electronSessionRoots []string
	electronKeyringNames []string
}

// WithCookieFiles overrides the auto-discovered cookie store paths.
func WithCookieFiles(paths ...string) Option {
	copied := append([]string(nil), paths...)
	return func(opts *options) {
		opts.cookieFiles = copied
	}
}

// WithDomains filters cookies to domains that match exactly or by subdomain suffix.
func WithDomains(domains ...string) Option {
	copied := append([]string(nil), domains...)
	return func(opts *options) {
		opts.domains = copied
	}
}

// WithElectronSessionRoots overrides Electron session root discovery.
func WithElectronSessionRoots(paths ...string) Option {
	copied := append([]string(nil), paths...)
	return func(opts *options) {
		opts.electronSessionRoots = copied
	}
}

// WithElectronAppPaths overrides Electron bundle or install-root discovery.
func WithElectronAppPaths(paths ...string) Option {
	copied := append([]string(nil), paths...)
	return func(opts *options) {
		opts.electronAppPaths = copied
	}
}

// WithElectronKeyringNames overrides Electron keyring/keychain name discovery.
func WithElectronKeyringNames(names ...string) Option {
	copied := append([]string(nil), names...)
	return func(opts *options) {
		opts.electronKeyringNames = copied
	}
}

func collectOptions(opts ...Option) options {
	var cfg options
	for _, opt := range opts {
		if opt == nil {
			continue
		}
		opt(&cfg)
	}
	return cfg
}

func (o options) cookieFilesCopy() []string {
	return append([]string(nil), o.cookieFiles...)
}

func (o options) domainsCopy() []string {
	return append([]string(nil), o.domains...)
}

func (o options) electronAppPathsCopy() []string {
	return append([]string(nil), o.electronAppPaths...)
}

func (o options) electronSessionRootsCopy() []string {
	return append([]string(nil), o.electronSessionRoots...)
}

func (o options) electronKeyringNamesCopy() []string {
	return append([]string(nil), o.electronKeyringNames...)
}
