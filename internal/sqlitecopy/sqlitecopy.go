package sqlitecopy

import (
	"database/sql"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"

	"github.com/Code-Hex/browsercookie/internal/errdefs"
	// Register the pure Go SQLite driver used by copied cookie stores.
	_ "modernc.org/sqlite"
)

var sqliteSidecarSuffixes = []string{"-wal", "-shm", "-journal"}

// Copy duplicates a cookie store into a temporary file.
func Copy(path string) (string, func() error, error) {
	if path == "" {
		return "", nil, errdefs.ErrNotFound
	}
	src, err := os.Open(path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return "", nil, errdefs.ErrNotFound
		}
		return "", nil, err
	}
	defer func() { _ = src.Close() }()

	tmp, err := os.CreateTemp("", "browsercookie-*"+filepath.Ext(path))
	if err != nil {
		return "", nil, err
	}
	tmpPath := tmp.Name()
	cleanup := func() error {
		return removeCopiedFiles(tmpPath)
	}

	if _, err := io.Copy(tmp, src); err != nil {
		_ = tmp.Close()
		_ = cleanup()
		return "", nil, err
	}
	if err := tmp.Close(); err != nil {
		_ = cleanup()
		return "", nil, err
	}
	for _, suffix := range sqliteSidecarSuffixes {
		if err := copyIfExists(path+suffix, tmpPath+suffix); err != nil {
			_ = cleanup()
			return "", nil, err
		}
	}
	return tmpPath, cleanup, nil
}

func copyIfExists(srcPath, dstPath string) error {
	src, err := os.Open(srcPath)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil
		}
		return err
	}
	defer func() { _ = src.Close() }()

	dst, err := os.Create(dstPath)
	if err != nil {
		return err
	}
	if _, err := io.Copy(dst, src); err != nil {
		_ = dst.Close()
		_ = os.Remove(dstPath)
		return err
	}
	if err := dst.Close(); err != nil {
		_ = os.Remove(dstPath)
		return err
	}
	return nil
}

func removeCopiedFiles(path string) error {
	var errs []error
	for _, candidate := range append([]string{path}, sidecarPaths(path)...) {
		if err := os.Remove(candidate); err != nil && !errors.Is(err, os.ErrNotExist) {
			errs = append(errs, err)
		}
	}
	return errors.Join(errs...)
}

func sidecarPaths(path string) []string {
	paths := make([]string, 0, len(sqliteSidecarSuffixes))
	for _, suffix := range sqliteSidecarSuffixes {
		paths = append(paths, path+suffix)
	}
	return paths
}

// Open copies a SQLite store and opens the temporary database.
func Open(path string) (*sql.DB, func() error, error) {
	tmpPath, cleanup, err := Copy(path)
	if err != nil {
		return nil, nil, err
	}
	db, err := sql.Open("sqlite", tmpPath)
	if err != nil {
		_ = cleanup()
		return nil, nil, err
	}
	if err := db.Ping(); err != nil {
		_ = db.Close()
		_ = cleanup()
		return nil, nil, fmt.Errorf("%w: %v", errdefs.ErrInvalidStore, err)
	}
	return db, func() error {
		closeErr := db.Close()
		removeErr := cleanup()
		return errors.Join(closeErr, removeErr)
	}, nil
}
