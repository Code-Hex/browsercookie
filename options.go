package browsercookie

// Option mutates loader configuration.
type Option func(*options)

type options struct {
	cookieFiles []string
}

// WithCookieFiles overrides the auto-discovered cookie store paths.
func WithCookieFiles(paths ...string) Option {
	copied := append([]string(nil), paths...)
	return func(opts *options) {
		opts.cookieFiles = copied
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
