package secrets

// Provider resolves browser decryption secrets.
type Provider interface {
	GenericPassword(service, account string) ([]byte, error)
}
