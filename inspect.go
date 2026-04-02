package browsercookie

import "github.com/Code-Hex/browsercookie/internal/electroninspect"

// ElectronAuthReport describes the persisted auth-related storage discovered for one Electron app.
type ElectronAuthReport = electroninspect.Report

// ElectronBundle describes one discovered Electron bundle.
type ElectronBundle = electroninspect.Bundle

// ElectronAuthLocation describes one discovered auth-related storage location or reference.
type ElectronAuthLocation = electroninspect.Location

// ElectronAuthSignal describes one static-analysis hint discovered from an Electron bundle.
type ElectronAuthSignal = electroninspect.Signal

// ElectronSecretRef identifies one secret-store reference without returning the secret value.
type ElectronSecretRef = electroninspect.SecretRef

// InspectElectronAuthStorage inspects where an Electron app keeps auth-related
// state on disk without returning the stored secret values.
//
// Use it when you need to debug why Electron(app) cannot read cookies, work out
// the right WithElectronAppPaths, WithElectronSessionRoots, or
// WithElectronKeyringNames overrides, or check whether an app persists auth in
// cookies, partition stores, IndexedDB, Local Storage, Session Storage, keytar,
// or safeStorage.
func InspectElectronAuthStorage(app string, opts ...Option) (*ElectronAuthReport, error) {
	cfg := collectOptions(opts...)
	return electroninspect.Inspect(app, electroninspect.Config{
		AppPaths:     cfg.electronAppPathsCopy(),
		SessionRoots: cfg.electronSessionRootsCopy(),
		KeyringNames: cfg.electronKeyringNamesCopy(),
	})
}
