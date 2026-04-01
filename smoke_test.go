package browsercookie

import (
	"errors"
	"net/http"
	"os"
	"runtime"
	"testing"
)

func TestSmokeMacOS(t *testing.T) {
	if runtime.GOOS != "darwin" || os.Getenv("BROWSERCOOKIE_SMOKE_MACOS") != "1" {
		t.Skip("opt-in smoke test")
	}

	loaders := []struct {
		name string
		fn   func(...Option) ([]*http.Cookie, error)
	}{
		{name: "Brave", fn: Brave},
		{name: "Chrome", fn: Chrome},
		{name: "Chromium", fn: Chromium},
		{name: "Vivaldi", fn: Vivaldi},
		{name: "Edge", fn: Edge},
		{name: "EdgeDev", fn: EdgeDev},
		{name: "Arc", fn: Arc},
		{name: "Opera", fn: Opera},
		{name: "OperaGX", fn: OperaGX},
		{name: "Firefox", fn: Firefox},
		{name: "LibreWolf", fn: LibreWolf},
		{name: "Zen", fn: Zen},
		{name: "Safari", fn: Safari},
	}

	for _, loader := range loaders {
		if _, err := loader.fn(); err != nil && !errors.Is(err, ErrNotFound) {
			t.Fatalf("%s() error = %v", loader.name, err)
		}
	}
}
