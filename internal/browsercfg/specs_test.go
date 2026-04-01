package browsercfg

import "testing"

func TestChromiumSpecCookiePatternsExpandChannels(t *testing.T) {
	t.Parallel()

	spec := MustChromium("chrome")
	got := spec.CookiePatterns("darwin")
	if len(got) < 4 {
		t.Fatalf("len(patterns) = %d, want at least 4", len(got))
	}
	want := []string{
		"~/Library/Application Support/Google/Chrome/Default/Cookies",
		"~/Library/Application Support/Google/Chrome-beta/Default/Cookies",
		"~/Library/Application Support/Google/Chrome-dev/Default/Cookies",
		"~/Library/Application Support/Google/Chrome-nightly/Default/Cookies",
	}
	for _, path := range want {
		if !containsString(got, path) {
			t.Fatalf("CookiePatterns() missing %q in %v", path, got)
		}
	}
}

func TestChromiumSpecAliasOverridesDarwinSecrets(t *testing.T) {
	t.Parallel()

	secrets := MustChromium("edge-dev").Secrets("darwin")
	if len(secrets) < 2 {
		t.Fatalf("len(secrets) = %d, want at least 2", len(secrets))
	}
	if secrets[0].Service != "Microsoft Edge Dev Safe Storage" || secrets[0].Account != "Microsoft Edge Dev" {
		t.Fatalf("primary secret = %#v", secrets[0])
	}
	if secrets[1].Service != "Microsoft Edge Safe Storage" || secrets[1].Account != "Microsoft Edge" {
		t.Fatalf("fallback secret = %#v", secrets[1])
	}
}

func TestMozillaSpecUsesProfileRoots(t *testing.T) {
	t.Parallel()

	got := MustMozilla("firefox").ProfilePatterns("windows")
	want := []string{
		"%APPDATA%/Mozilla/Firefox",
		"%LOCALAPPDATA%/Mozilla/Firefox",
	}
	for _, path := range want {
		if !containsString(got, path) {
			t.Fatalf("ProfilePatterns() missing %q in %v", path, got)
		}
	}
}

func containsString(values []string, want string) bool {
	for _, value := range values {
		if value == want {
			return true
		}
	}
	return false
}
