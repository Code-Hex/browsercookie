package browsercookie

import "github.com/Code-Hex/browsercookie/internal/errdefs"

var (
	// ErrNotFound reports that no readable cookie store was found.
	ErrNotFound = errdefs.ErrNotFound
	// ErrUnsupported reports that the current OS is not implemented yet.
	ErrUnsupported = errdefs.ErrUnsupported
	// ErrInvalidStore reports that a cookie store exists but cannot be parsed.
	ErrInvalidStore = errdefs.ErrInvalidStore
	// ErrDecrypt reports that an encrypted cookie value could not be decrypted.
	ErrDecrypt = errdefs.ErrDecrypt
)
