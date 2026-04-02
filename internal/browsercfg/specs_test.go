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

func TestChromiumSpecExposesBackendMetadata(t *testing.T) {
	t.Parallel()

	edgeDev := MustChromium("edge-dev")
	if len(edgeDev.LinuxLibsecretRefs("linux")) == 0 {
		t.Fatal("LinuxLibsecretRefs(linux) is empty")
	}
	if len(edgeDev.LinuxKWalletRefs("linux")) == 0 {
		t.Fatal("LinuxKWalletRefs(linux) is empty")
	}
	if len(edgeDev.LocalStatePaths("windows")) == 0 {
		t.Fatal("LocalStatePaths(windows) is empty")
	}
	if len(edgeDev.WindowsKeySources("windows")) != 2 {
		t.Fatalf("len(WindowsKeySources(windows)) = %d, want 2", len(edgeDev.WindowsKeySources("windows")))
	}
}

func TestElectronSpecAddsDefaultAndPartitionCookiePaths(t *testing.T) {
	t.Parallel()

	spec := ElectronSpec("Code", nil, nil)
	got := spec.CookiePatterns("darwin")
	want := []string{
		"~/Library/Application Support/Code/Cookies",
		"~/Library/Application Support/Code/Network/Cookies",
		"~/Library/Application Support/Code/Partitions/*/Cookies",
		"~/Library/Application Support/Code/Partitions/*/Network/Cookies",
	}
	for _, path := range want {
		if !containsString(got, path) {
			t.Fatalf("CookiePatterns() missing %q in %v", path, got)
		}
	}
}

func TestElectronSpecAddsMacSecretFallbacks(t *testing.T) {
	t.Parallel()

	secrets := ElectronSpec("Code", nil, nil).Secrets("darwin")
	if len(secrets) < 3 {
		t.Fatalf("len(secrets) = %d, want at least 3", len(secrets))
	}
	want := []Secret{
		{Service: "Code Safe Storage", Account: "Code"},
		{Service: "Chrome Safe Storage", Account: "Chrome"},
		{Service: "Chromium Safe Storage", Account: "Chromium"},
	}
	for i, secret := range want {
		if secrets[i] != secret {
			t.Fatalf("secrets[%d] = %#v, want %#v", i, secrets[i], secret)
		}
	}
}

func TestElectronSpecAddsLinuxKeyringFallbacks(t *testing.T) {
	t.Parallel()

	spec := ElectronSpec("My App", nil, []string{"Code", "My App"})
	libsecretRefs := spec.LinuxLibsecretRefs("linux")
	kwalletRefs := spec.LinuxKWalletRefs("linux")

	wantLibsecret := []LinuxLibsecretRef{
		{Schema: "chrome_libsecret_os_crypt_password_v2", Application: "Code"},
		{Schema: "chrome_libsecret_os_crypt_password_v1", Application: "Code"},
		{Schema: "chrome_libsecret_os_crypt_password_v2", Application: "code"},
		{Schema: "chrome_libsecret_os_crypt_password_v1", Application: "code"},
		{Schema: "chrome_libsecret_os_crypt_password_v2", Application: "My App"},
		{Schema: "chrome_libsecret_os_crypt_password_v1", Application: "My App"},
		{Schema: "chrome_libsecret_os_crypt_password_v2", Application: "my-app"},
		{Schema: "chrome_libsecret_os_crypt_password_v1", Application: "my-app"},
		{Schema: "chrome_libsecret_os_crypt_password_v2", Application: "chrome"},
		{Schema: "chrome_libsecret_os_crypt_password_v1", Application: "chrome"},
		{Schema: "chrome_libsecret_os_crypt_password_v2", Application: "chromium"},
		{Schema: "chrome_libsecret_os_crypt_password_v1", Application: "chromium"},
	}
	for i, ref := range wantLibsecret {
		if libsecretRefs[i] != ref {
			t.Fatalf("libsecretRefs[%d] = %#v, want %#v", i, libsecretRefs[i], ref)
		}
	}

	wantKWallet := []LinuxKWalletRef{
		{Folder: "Code Keys", Key: "Code Safe Storage"},
		{Folder: "My App Keys", Key: "My App Safe Storage"},
		{Folder: "Chrome Keys", Key: "Chrome Safe Storage"},
		{Folder: "Chromium Keys", Key: "Chromium Safe Storage"},
	}
	for i, ref := range wantKWallet {
		if kwalletRefs[i] != ref {
			t.Fatalf("kwalletRefs[%d] = %#v, want %#v", i, kwalletRefs[i], ref)
		}
	}
}

func TestElectronSpecUsesExplicitSessionRoots(t *testing.T) {
	t.Parallel()

	spec := ElectronSpec("Code", []string{"/tmp/electron-root"}, nil)
	got := spec.CookiePatterns("windows")
	want := []string{
		"/tmp/electron-root/Cookies",
		"/tmp/electron-root/Network/Cookies",
		"/tmp/electron-root/Partitions/*/Cookies",
		"/tmp/electron-root/Partitions/*/Network/Cookies",
	}
	if len(got) != len(want) {
		t.Fatalf("len(got) = %d, want %d (%v)", len(got), len(want), got)
	}
	for _, path := range want {
		if !containsString(got, path) {
			t.Fatalf("CookiePatterns() missing %q in %v", path, got)
		}
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
