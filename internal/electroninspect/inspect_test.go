package electroninspect

import (
	"os"
	"path/filepath"
	"testing"
)

func TestScanBundlePrefersTopLevelPackageManifest(t *testing.T) {
	t.Parallel()

	root := t.TempDir()
	writeInspectAsset(t, filepath.Join(root, "0pkg", "package.json"), `{"name":"wrong","productName":"Wrong App"}`)
	writeInspectAsset(t, filepath.Join(root, "package.json"), `{"name":"correct","productName":"Correct App"}`)

	bundle := discoveredBundle{
		Bundle:     Bundle{Path: root},
		appDirPath: root,
	}
	scanBundle(&bundle)

	if bundle.PackageName != "correct" {
		t.Fatalf("PackageName = %q, want %q", bundle.PackageName, "correct")
	}
	if bundle.ProductName != "Correct App" {
		t.Fatalf("ProductName = %q, want %q", bundle.ProductName, "Correct App")
	}
}

func writeInspectAsset(t *testing.T, path, contents string) {
	t.Helper()

	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatalf("MkdirAll() error = %v", err)
	}
	if err := os.WriteFile(path, []byte(contents), 0o644); err != nil {
		t.Fatalf("WriteFile() error = %v", err)
	}
}
