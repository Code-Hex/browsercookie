//go:build darwin

package electroninspect

import (
	"bytes"
	"errors"
	"os/exec"

	"github.com/Code-Hex/browsercookie/internal/browsercfg"
)

type darwinGenericPasswordProber interface {
	HasGenericPassword(service, account string) (bool, error)
}

var newDarwinGenericPasswordProber = func() darwinGenericPasswordProber {
	return darwinSecurityProber{}
}

type darwinSecurityProber struct{}

func probeSecretLocations(spec browsercfg.ChromiumSpec, _ []string) []Location {
	prober := newDarwinGenericPasswordProber()
	if prober == nil {
		return nil
	}

	var locations []Location
	for _, secret := range spec.Secrets("darwin") {
		ok, err := prober.HasGenericPassword(secret.Service, secret.Account)
		if err != nil || !ok {
			continue
		}
		locations = append(locations, Location{
			Kind:   "safe_storage",
			Status: "present",
			Scope:  "app",
			Path:   secret.Service + "/" + secret.Account,
			Format: "secret_ref",
			SecretRef: &SecretRef{
				Service: secret.Service,
				Account: secret.Account,
			},
			Evidence: []string{"keychain item exists"},
		})
	}
	return locations
}

func (darwinSecurityProber) HasGenericPassword(service, account string) (bool, error) {
	cmd := exec.Command(
		"/usr/bin/security",
		"-q",
		"find-generic-password",
		"-a",
		account,
		"-s",
		service,
	)
	output, err := cmd.CombinedOutput()
	if err == nil {
		return true, nil
	}
	if bytes.Contains(bytes.ToLower(output), []byte("could not be found")) {
		return false, nil
	}
	var exitErr *exec.ExitError
	if errors.As(err, &exitErr) {
		return false, nil
	}
	return false, err
}
