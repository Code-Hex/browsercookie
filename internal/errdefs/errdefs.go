package errdefs

import "errors"

var (
	// ErrNotFound reports that no cookie store was found.
	ErrNotFound = errors.New("cookie store not found")
	// ErrUnsupported reports that the current operating system is not supported.
	ErrUnsupported = errors.New("unsupported operating system")
	// ErrInvalidStore reports that a cookie store could not be parsed safely.
	ErrInvalidStore = errors.New("invalid cookie store")
	// ErrDecrypt reports that an encrypted cookie value could not be decrypted.
	ErrDecrypt = errors.New("failed to decrypt cookie value")
)
