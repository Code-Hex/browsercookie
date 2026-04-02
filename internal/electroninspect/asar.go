// Package electroninspect inspects persisted Electron auth storage.
package electroninspect

import (
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path"
	"sort"
	"strconv"
	"strings"

	"github.com/Code-Hex/browsercookie/internal/errdefs"
)

type asarArchive struct {
	file       *os.File
	dataOffset int64
	entries    []asarEntry
}

type asarEntry struct {
	Path     string
	Offset   int64
	Size     int64
	Unpacked bool
}

type asarHeader struct {
	Files map[string]asarNode `json:"files"`
}

type asarNode struct {
	Files    map[string]asarNode `json:"files"`
	Offset   string              `json:"offset"`
	Size     int64               `json:"size"`
	Unpacked bool                `json:"unpacked"`
}

func openASAR(archivePath string) (*asarArchive, error) {
	file, err := os.Open(archivePath)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, errdefs.ErrNotFound
		}
		return nil, err
	}

	header, dataOffset, err := readASARHeader(file)
	if err != nil {
		_ = file.Close()
		return nil, err
	}

	entries := make([]asarEntry, 0, 64)
	walkASARFiles(header.Files, "", dataOffset, &entries)
	return &asarArchive{
		file:       file,
		dataOffset: dataOffset,
		entries:    entries,
	}, nil
}

func (a *asarArchive) Close() error {
	if a == nil || a.file == nil {
		return nil
	}
	return a.file.Close()
}

func (a *asarArchive) ReadFile(entry asarEntry) ([]byte, error) {
	if a == nil || a.file == nil {
		return nil, errdefs.ErrInvalidStore
	}
	if entry.Unpacked {
		return nil, errdefs.ErrNotFound
	}

	reader := io.NewSectionReader(a.file, entry.Offset, entry.Size)
	data := make([]byte, entry.Size)
	if _, err := io.ReadFull(reader, data); err != nil {
		return nil, fmt.Errorf("%w: %v", errdefs.ErrInvalidStore, err)
	}
	return data, nil
}

func readASARHeader(file *os.File) (asarHeader, int64, error) {
	var prefix [16]byte
	if _, err := io.ReadFull(file, prefix[:]); err != nil {
		return asarHeader{}, 0, fmt.Errorf("%w: %v", errdefs.ErrInvalidStore, err)
	}

	headerPickleSize := int64(binary.LittleEndian.Uint32(prefix[4:8]))
	headerJSONSize := int64(binary.LittleEndian.Uint32(prefix[12:16]))
	if headerPickleSize <= 0 || headerJSONSize <= 0 {
		return asarHeader{}, 0, errdefs.ErrInvalidStore
	}

	headerLimit := int64(8) + headerPickleSize
	headerStart := int64(16)
	headerEnd := headerStart + headerJSONSize
	if headerEnd > headerLimit {
		return asarHeader{}, 0, errdefs.ErrInvalidStore
	}

	headerBytes := make([]byte, headerJSONSize)
	if _, err := file.ReadAt(headerBytes, headerStart); err != nil {
		return asarHeader{}, 0, fmt.Errorf("%w: %v", errdefs.ErrInvalidStore, err)
	}

	var header asarHeader
	if err := json.Unmarshal(headerBytes, &header); err != nil {
		return asarHeader{}, 0, fmt.Errorf("%w: %v", errdefs.ErrInvalidStore, err)
	}
	return header, headerLimit, nil
}

func walkASARFiles(nodes map[string]asarNode, base string, dataOffset int64, entries *[]asarEntry) {
	names := make([]string, 0, len(nodes))
	for name := range nodes {
		names = append(names, name)
	}
	sort.Strings(names)
	for _, name := range names {
		node := nodes[name]
		fullPath := path.Join(base, name)
		if len(node.Files) > 0 {
			walkASARFiles(node.Files, fullPath, dataOffset, entries)
			continue
		}
		offset, err := parseASAROffset(node.Offset)
		if err != nil {
			continue
		}
		*entries = append(*entries, asarEntry{
			Path:     fullPath,
			Offset:   dataOffset + offset,
			Size:     node.Size,
			Unpacked: node.Unpacked,
		})
	}
}

func parseASAROffset(raw string) (int64, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return 0, errdefs.ErrInvalidStore
	}
	value, err := strconv.ParseInt(raw, 10, 64)
	if err != nil || value < 0 {
		return 0, errdefs.ErrInvalidStore
	}
	return value, nil
}
