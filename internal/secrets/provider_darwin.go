//go:build darwin

package secrets

import (
	"bytes"
	"fmt"
	"os/exec"

	"github.com/Code-Hex/browsercookie/internal/errdefs"
)

type macOSProvider struct{}

// Default returns the default secret provider for macOS.
func Default() Provider {
	return macOSProvider{}
}

func (macOSProvider) GenericPassword(service, account string) ([]byte, error) {
	cmd := exec.Command("/usr/bin/security", "-q", "find-generic-password", "-w", "-a", account, "-s", service)
	out, err := cmd.Output()
	if err != nil {
		return nil, fmt.Errorf("%w: %v", errdefs.ErrDecrypt, err)
	}
	return bytes.TrimSpace(out), nil
}
