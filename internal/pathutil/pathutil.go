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
		expanded := filepath.FromSlash(ExpandPath(pattern))
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

// ExpandPath resolves "~", $VAR, and %VAR% placeholders.
func ExpandPath(path string) string {
	return expandPercentEnv(ExpandUser(os.ExpandEnv(path)))
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

func expandPercentEnv(path string) string {
	if !strings.Contains(path, "%") {
		return path
	}

	var builder strings.Builder
	builder.Grow(len(path))
	for i := 0; i < len(path); {
		if path[i] != '%' {
			builder.WriteByte(path[i])
			i++
			continue
		}

		end := strings.IndexByte(path[i+1:], '%')
		if end < 0 {
			builder.WriteByte(path[i])
			i++
			continue
		}
		end += i + 1

		name := path[i+1 : end]
		if name == "" {
			builder.WriteString("%%")
			i = end + 1
			continue
		}
		if value, ok := os.LookupEnv(name); ok {
			builder.WriteString(value)
		} else {
			builder.WriteString(path[i : end+1])
		}
		i = end + 1
	}
	return builder.String()
}
