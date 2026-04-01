package pathutil

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestExpandPathExpandsShellAndPercentEnv(t *testing.T) {
	t.Setenv("BROWSERCOOKIE_TEST_HOME", filepath.Join("tmp", "browsercookie-home"))
	t.Setenv("BROWSERCOOKIE_TEST_DATA", filepath.Join("tmp", "browsercookie-data"))

	expanded := ExpandPath("$BROWSERCOOKIE_TEST_HOME/%BROWSERCOOKIE_TEST_DATA%/Cookies")
	if !strings.Contains(expanded, filepath.Join("tmp", "browsercookie-home")) {
		t.Fatalf("ExpandPath() = %q, want shell env expansion", expanded)
	}
	if !strings.Contains(expanded, filepath.Join("tmp", "browsercookie-data")) {
		t.Fatalf("ExpandPath() = %q, want percent env expansion", expanded)
	}
}

func TestExpandDeduplicatesMatches(t *testing.T) {
	t.Parallel()

	root := t.TempDir()
	first := filepath.Join(root, "first.txt")
	second := filepath.Join(root, "second.txt")
	for _, path := range []string{first, second} {
		if err := os.WriteFile(path, []byte("ok"), 0o644); err != nil {
			t.Fatalf("WriteFile(%q) error = %v", path, err)
		}
	}

	got := Expand([]string{
		filepath.Join(root, "*.txt"),
		filepath.Join(root, "first.txt"),
	})
	if len(got) != 2 {
		t.Fatalf("len(Expand()) = %d, want 2", len(got))
	}
	if got[0] != first || got[1] != second {
		t.Fatalf("Expand() = %v, want [%q %q]", got, first, second)
	}
}
