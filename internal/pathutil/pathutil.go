package pathutil

import (
	"os"
	"path/filepath"
	"sort"
	"strings"
)

// Expand resolves glob patterns after expanding a leading home directory marker.
func Expand(patterns []string) []string {
	var results []string
	seen := map[string]struct{}{}
	for _, pattern := range patterns {
		expanded := ExpandUser(pattern)
		matches, err := filepath.Glob(expanded)
		if err != nil {
			continue
		}
		sort.Strings(matches)
		for _, match := range matches {
			if _, ok := seen[match]; ok {
				continue
			}
			seen[match] = struct{}{}
			results = append(results, match)
		}
	}
	return results
}

// ExpandUser expands "~" to the current user's home directory when possible.
func ExpandUser(path string) string {
	if path == "~" {
		home, err := os.UserHomeDir()
		if err == nil {
			return home
		}
		return path
	}
	if !strings.HasPrefix(path, "~/") {
		return path
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return path
	}
	return filepath.Join(home, path[2:])
}
