package electroninspect

import (
	"encoding/binary"
	"encoding/json"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"testing"
)

type asarFixtureEntry struct {
	offset int64
	size   int64
	files  map[string]*asarFixtureEntry
}

func TestOpenASARReadsEntriesAndContents(t *testing.T) {
	t.Parallel()

	archivePath := filepath.Join(t.TempDir(), "app.asar")
	writeASARFixture(t, archivePath, map[string][]byte{
		"package.json": []byte(`{"name":"discord","productName":"Discord"}`),
		"dist/main.js": []byte(`const { safeStorage } = require("electron")`),
	})

	archive, err := openASAR(archivePath)
	if err != nil {
		t.Fatalf("openASAR() error = %v", err)
	}
	defer func() { _ = archive.Close() }()

	if len(archive.entries) != 2 {
		t.Fatalf("len(entries) = %d, want 2", len(archive.entries))
	}

	entry := archive.entries[0]
	if entry.Path != "dist/main.js" && entry.Path != "package.json" {
		t.Fatalf("unexpected first entry path = %q", entry.Path)
	}

	var pkgEntry asarEntry
	for _, candidate := range archive.entries {
		if candidate.Path == "package.json" {
			pkgEntry = candidate
			break
		}
	}
	data, err := archive.ReadFile(pkgEntry)
	if err != nil {
		t.Fatalf("ReadFile() error = %v", err)
	}
	if string(data) != `{"name":"discord","productName":"Discord"}` {
		t.Fatalf("package.json = %q", data)
	}
}

func TestChromiumVersionForElectronUsesEmbeddedSnapshot(t *testing.T) {
	t.Parallel()

	if got := chromiumVersionForElectron("37.6.0"); got != "138" {
		t.Fatalf("chromiumVersionForElectron() = %q, want %q", got, "138")
	}
}

func writeASARFixture(t *testing.T, archivePath string, files map[string][]byte) {
	t.Helper()

	root := &asarFixtureEntry{files: map[string]*asarFixtureEntry{}}
	paths := make([]string, 0, len(files))
	for name := range files {
		paths = append(paths, filepath.ToSlash(name))
	}
	sort.Strings(paths)

	var offset int64
	for _, name := range paths {
		parts := strings.Split(name, "/")
		current := root
		for i, part := range parts {
			if current.files == nil {
				current.files = map[string]*asarFixtureEntry{}
			}
			child, ok := current.files[part]
			if !ok {
				child = &asarFixtureEntry{}
				current.files[part] = child
			}
			if i == len(parts)-1 {
				child.offset = offset
				child.size = int64(len(files[name]))
			} else if child.files == nil {
				child.files = map[string]*asarFixtureEntry{}
			}
			current = child
		}
		offset += int64(len(files[name]))
	}

	header := map[string]any{"files": marshalASAREntries(root.files)}
	headerJSON, err := json.Marshal(header)
	if err != nil {
		t.Fatalf("json.Marshal() error = %v", err)
	}

	if err := os.MkdirAll(filepath.Dir(archivePath), 0o755); err != nil {
		t.Fatalf("MkdirAll() error = %v", err)
	}

	file, err := os.Create(archivePath)
	if err != nil {
		t.Fatalf("os.Create() error = %v", err)
	}
	defer func() { _ = file.Close() }()

	var prefix [16]byte
	binary.LittleEndian.PutUint32(prefix[0:4], 4)
	binary.LittleEndian.PutUint32(prefix[4:8], uint32(len(headerJSON)+8))
	binary.LittleEndian.PutUint32(prefix[8:12], uint32(len(headerJSON)+4))
	binary.LittleEndian.PutUint32(prefix[12:16], uint32(len(headerJSON)))
	if _, err := file.Write(prefix[:]); err != nil {
		t.Fatalf("Write(prefix) error = %v", err)
	}
	if _, err := file.Write(headerJSON); err != nil {
		t.Fatalf("Write(header) error = %v", err)
	}
	for _, name := range paths {
		if _, err := file.Write(files[name]); err != nil {
			t.Fatalf("Write(%q) error = %v", name, err)
		}
	}
}

func marshalASAREntries(entries map[string]*asarFixtureEntry) map[string]any {
	out := map[string]any{}
	for name, node := range entries {
		if len(node.files) > 0 {
			out[name] = map[string]any{
				"files": marshalASAREntries(node.files),
			}
			continue
		}
		out[name] = map[string]any{
			"offset": strconvFormatInt(node.offset),
			"size":   node.size,
		}
	}
	return out
}

func strconvFormatInt(value int64) string {
	return strconv.FormatInt(value, 10)
}
