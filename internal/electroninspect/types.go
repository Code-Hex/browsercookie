package electroninspect

// Report describes the persisted auth storage that was discovered for one Electron app.
type Report struct {
	App             string
	Bundles         []Bundle
	Locations       []Location
	Signals         []Signal
	ElectronVersion string
	ChromiumVersion string
}

// Bundle describes one discovered Electron bundle or install root.
type Bundle struct {
	Path            string
	BundleID        string
	Name            string
	DisplayName     string
	PackageName     string
	ProductName     string
	ElectronVersion string
}

// Location describes one auth-related storage location or reference.
type Location struct {
	Kind      string
	Status    string
	Scope     string
	Path      string
	Format    string
	SecretRef *SecretRef
	Evidence  []string
}

// Signal describes one implementation hint discovered from static bundle analysis.
type Signal struct {
	Kind   string
	Detail string
	Path   string
}

// SecretRef identifies one secret-store reference without returning the secret value.
type SecretRef struct {
	Service string
	Account string
	Schema  string
	Name    string
	Folder  string
	Key     string
	Source  string
}

// Config controls Electron inspection.
type Config struct {
	AppPaths     []string
	SessionRoots []string
	KeyringNames []string
}
