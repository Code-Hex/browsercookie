//go:build !darwin

package secrets

import "github.com/Code-Hex/browsercookie/internal/errdefs"

type unsupportedProvider struct{}

func Default() Provider {
	return unsupportedProvider{}
}

func (unsupportedProvider) GenericPassword(service, account string) ([]byte, error) {
	return nil, errdefs.ErrUnsupported
}
