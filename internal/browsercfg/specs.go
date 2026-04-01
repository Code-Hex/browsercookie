// Package browsercfg defines browser discovery metadata shared by the loaders.
package browsercfg

import (
	"runtime"
	"strings"
)

// Secret identifies a browser decryption secret.
type Secret struct {
	Service string
	Account string
}

// LinuxLibsecretRef identifies one libsecret lookup target.
type LinuxLibsecretRef struct {
	Schema      string
	Application string
}

// LinuxKWalletRef identifies one KWallet lookup target.
type LinuxKWalletRef struct {
	Folder string
	Key    string
}

// WindowsKeySource identifies which Local State key entry can decrypt cookies.
type WindowsKeySource string

const (
	// WindowsEncryptedKey is the classic DPAPI-protected key.
	WindowsEncryptedKey WindowsKeySource = "encrypted_key"
	// WindowsAppBoundEncryptedKey is the app-bound elevation-service key.
	WindowsAppBoundEncryptedKey WindowsKeySource = "app_bound_encrypted_key"
)

// ChromiumPlatform defines Chromium-family paths and secrets for one OS.
type ChromiumPlatform struct {
	CookiePathTemplates []string
	Channels            []string
	Secrets             []Secret
	LinuxLibsecretRefs  []LinuxLibsecretRef
	LinuxKWalletRefs    []LinuxKWalletRef
	LocalStatePaths     []string
	WindowsKeySources   []WindowsKeySource
}

// ChromiumSpec describes one Chromium-family browser across supported OSes.
type ChromiumSpec struct {
	Name      string
	Platforms map[string]ChromiumPlatform
}

// MozillaPlatform defines Firefox-family profile roots for one OS.
type MozillaPlatform struct {
	ProfilePathTemplates []string
	Channels             []string
}

// MozillaSpec describes one Firefox-family browser across supported OSes.
type MozillaSpec struct {
	Name      string
	Platforms map[string]MozillaPlatform
}

// SafariPlatform defines Safari cookie paths for one OS.
type SafariPlatform struct {
	CookiePathTemplates []string
}

// SafariSpec describes Safari-family browser metadata across supported OSes.
type SafariSpec struct {
	Name      string
	Platforms map[string]SafariPlatform
}

// MustChromium returns a Chromium spec and panics when the name is unknown.
func MustChromium(name string) ChromiumSpec {
	spec, ok := chromiumSpecs[name]
	if !ok {
		panic("unknown chromium browser spec: " + name)
	}
	return spec
}

// MustMozilla returns a Mozilla spec and panics when the name is unknown.
func MustMozilla(name string) MozillaSpec {
	spec, ok := mozillaSpecs[name]
	if !ok {
		panic("unknown mozilla browser spec: " + name)
	}
	return spec
}

// MustSafari returns a Safari spec and panics when the name is unknown.
func MustSafari(name string) SafariSpec {
	spec, ok := safariSpecs[name]
	if !ok {
		panic("unknown safari browser spec: " + name)
	}
	return spec
}

// CookiePatterns returns the expanded cookie DB globs for the requested OS.
func (s ChromiumSpec) CookiePatterns(goos string) []string {
	platform, ok := s.Platforms[goos]
	if !ok {
		return nil
	}
	return expandChannelTemplates(platform.CookiePathTemplates, platform.Channels)
}

// CurrentCookiePatterns returns the expanded cookie DB globs for the current OS.
func (s ChromiumSpec) CurrentCookiePatterns() []string {
	return s.CookiePatterns(runtime.GOOS)
}

// Secrets returns the decryption secrets for the requested OS.
func (s ChromiumSpec) Secrets(goos string) []Secret {
	platform, ok := s.Platforms[goos]
	if !ok {
		return nil
	}
	return append([]Secret(nil), platform.Secrets...)
}

// CurrentSecrets returns the decryption secrets for the current OS.
func (s ChromiumSpec) CurrentSecrets() []Secret {
	return s.Secrets(runtime.GOOS)
}

// LinuxLibsecretRefs returns Linux libsecret lookups for the requested OS.
func (s ChromiumSpec) LinuxLibsecretRefs(goos string) []LinuxLibsecretRef {
	platform, ok := s.Platforms[goos]
	if !ok {
		return nil
	}
	return append([]LinuxLibsecretRef(nil), platform.LinuxLibsecretRefs...)
}

// CurrentLinuxLibsecretRefs returns Linux libsecret lookups for the current OS.
func (s ChromiumSpec) CurrentLinuxLibsecretRefs() []LinuxLibsecretRef {
	return s.LinuxLibsecretRefs(runtime.GOOS)
}

// LinuxKWalletRefs returns Linux KWallet lookups for the requested OS.
func (s ChromiumSpec) LinuxKWalletRefs(goos string) []LinuxKWalletRef {
	platform, ok := s.Platforms[goos]
	if !ok {
		return nil
	}
	return append([]LinuxKWalletRef(nil), platform.LinuxKWalletRefs...)
}

// CurrentLinuxKWalletRefs returns Linux KWallet lookups for the current OS.
func (s ChromiumSpec) CurrentLinuxKWalletRefs() []LinuxKWalletRef {
	return s.LinuxKWalletRefs(runtime.GOOS)
}

// LocalStatePaths returns Local State resolution hints for the requested OS.
func (s ChromiumSpec) LocalStatePaths(goos string) []string {
	platform, ok := s.Platforms[goos]
	if !ok {
		return nil
	}
	return append([]string(nil), platform.LocalStatePaths...)
}

// CurrentLocalStatePaths returns Local State resolution hints for the current OS.
func (s ChromiumSpec) CurrentLocalStatePaths() []string {
	return s.LocalStatePaths(runtime.GOOS)
}

// WindowsKeySources returns allowed Local State key sources for the requested OS.
func (s ChromiumSpec) WindowsKeySources(goos string) []WindowsKeySource {
	platform, ok := s.Platforms[goos]
	if !ok {
		return nil
	}
	return append([]WindowsKeySource(nil), platform.WindowsKeySources...)
}

// CurrentWindowsKeySources returns allowed Local State key sources for the current OS.
func (s ChromiumSpec) CurrentWindowsKeySources() []WindowsKeySource {
	return s.WindowsKeySources(runtime.GOOS)
}

// ProfilePatterns returns the expanded Firefox profile roots for the requested OS.
func (s MozillaSpec) ProfilePatterns(goos string) []string {
	platform, ok := s.Platforms[goos]
	if !ok {
		return nil
	}
	return expandChannelTemplates(platform.ProfilePathTemplates, platform.Channels)
}

// CurrentProfilePatterns returns the Firefox profile roots for the current OS.
func (s MozillaSpec) CurrentProfilePatterns() []string {
	return s.ProfilePatterns(runtime.GOOS)
}

// CookiePatterns returns the Safari cookie-store globs for the requested OS.
func (s SafariSpec) CookiePatterns(goos string) []string {
	platform, ok := s.Platforms[goos]
	if !ok {
		return nil
	}
	return append([]string(nil), platform.CookiePathTemplates...)
}

// CurrentCookiePatterns returns the Safari cookie-store globs for the current OS.
func (s SafariSpec) CurrentCookiePatterns() []string {
	return s.CookiePatterns(runtime.GOOS)
}

func expandChannelTemplates(templates, channels []string) []string {
	if len(templates) == 0 {
		return nil
	}
	if len(channels) == 0 {
		channels = []string{""}
	}

	seen := map[string]struct{}{}
	out := make([]string, 0, len(templates)*len(channels))
	for _, tmpl := range templates {
		if !strings.Contains(tmpl, "{channel}") {
			if _, ok := seen[tmpl]; ok {
				continue
			}
			seen[tmpl] = struct{}{}
			out = append(out, tmpl)
			continue
		}
		for _, channel := range channels {
			path := replaceChannel(tmpl, channel)
			if _, ok := seen[path]; ok {
				continue
			}
			seen[path] = struct{}{}
			out = append(out, path)
		}
	}
	return out
}

func replaceChannel(template, channel string) string {
	return strings.ReplaceAll(template, "{channel}", channel)
}

func defaultLocalStatePaths() []string {
	return []string{
		"../../Local State",
		"../Local State",
		"Local State",
	}
}

func defaultWindowsKeySources() []WindowsKeySource {
	return []WindowsKeySource{
		WindowsEncryptedKey,
		WindowsAppBoundEncryptedKey,
	}
}

var chromiumSpecs = func() map[string]ChromiumSpec {
	specs := map[string]ChromiumSpec{
		"chrome": {
			Name: "chrome",
			Platforms: map[string]ChromiumPlatform{
				"darwin": {
					CookiePathTemplates: []string{
						"~/Library/Application Support/Google/Chrome{channel}/Default/Cookies",
						"~/Library/Application Support/Google/Chrome{channel}/Profile */Cookies",
					},
					Channels: []string{"", "-beta", "-dev", "-nightly"},
					Secrets: []Secret{
						{Service: "Chrome Safe Storage", Account: "Chrome"},
					},
				},
				"linux": {
					CookiePathTemplates: []string{
						"~/.config/google-chrome{channel}/Default/Cookies",
						"~/.config/google-chrome{channel}/Profile */Cookies",
						"~/.var/app/com.google.Chrome/config/google-chrome{channel}/Default/Cookies",
						"~/.var/app/com.google.Chrome/config/google-chrome{channel}/Profile */Cookies",
					},
					Channels: []string{"", "-beta", "-dev", "-nightly"},
					LinuxLibsecretRefs: []LinuxLibsecretRef{
						{Schema: "chrome_libsecret_os_crypt_password_v2", Application: "chrome"},
						{Schema: "chrome_libsecret_os_crypt_password_v1", Application: "chrome"},
					},
					LinuxKWalletRefs: []LinuxKWalletRef{
						{Folder: "Chrome Keys", Key: "Chrome Safe Storage"},
					},
				},
				"windows": {
					CookiePathTemplates: []string{
						"%LOCALAPPDATA%/Google/Chrome{channel}/User Data/Default/Cookies",
						"%LOCALAPPDATA%/Google/Chrome{channel}/User Data/Default/Network/Cookies",
						"%LOCALAPPDATA%/Google/Chrome{channel}/User Data/Profile */Cookies",
						"%LOCALAPPDATA%/Google/Chrome{channel}/User Data/Profile */Network/Cookies",
						"%APPDATA%/Google/Chrome{channel}/User Data/Default/Cookies",
						"%APPDATA%/Google/Chrome{channel}/User Data/Default/Network/Cookies",
						"%APPDATA%/Google/Chrome{channel}/User Data/Profile */Cookies",
						"%APPDATA%/Google/Chrome{channel}/User Data/Profile */Network/Cookies",
					},
					Channels:          []string{"", "-beta", "-dev", "-nightly"},
					LocalStatePaths:   defaultLocalStatePaths(),
					WindowsKeySources: defaultWindowsKeySources(),
				},
			},
		},
		"brave": {
			Name: "brave",
			Platforms: map[string]ChromiumPlatform{
				"darwin": {
					CookiePathTemplates: []string{
						"~/Library/Application Support/BraveSoftware/Brave-Browser{channel}/Default/Cookies",
						"~/Library/Application Support/BraveSoftware/Brave-Browser{channel}/Profile */Cookies",
					},
					Channels: []string{"", "-beta", "-dev", "-nightly"},
					Secrets: []Secret{
						{Service: "Brave Safe Storage", Account: "Brave"},
					},
				},
				"linux": {
					CookiePathTemplates: []string{
						"~/snap/brave/*/.config/BraveSoftware/Brave-Browser/Default/Cookies",
						"~/.config/BraveSoftware/Brave-Browser{channel}/Default/Cookies",
						"~/.config/BraveSoftware/Brave-Browser{channel}/Profile */Cookies",
						"~/.var/app/com.brave.Browser/config/BraveSoftware/Brave-Browser{channel}/Default/Cookies",
						"~/.var/app/com.brave.Browser/config/BraveSoftware/Brave-Browser{channel}/Profile */Cookies",
					},
					Channels: []string{"", "-beta", "-dev", "-nightly"},
					LinuxLibsecretRefs: []LinuxLibsecretRef{
						{Schema: "chrome_libsecret_os_crypt_password_v2", Application: "brave"},
						{Schema: "chrome_libsecret_os_crypt_password_v1", Application: "brave"},
					},
					LinuxKWalletRefs: []LinuxKWalletRef{
						{Folder: "Brave Keys", Key: "Brave Safe Storage"},
					},
				},
				"windows": {
					CookiePathTemplates: []string{
						"%LOCALAPPDATA%/BraveSoftware/Brave-Browser{channel}/User Data/Default/Cookies",
						"%LOCALAPPDATA%/BraveSoftware/Brave-Browser{channel}/User Data/Default/Network/Cookies",
						"%LOCALAPPDATA%/BraveSoftware/Brave-Browser{channel}/User Data/Profile */Cookies",
						"%LOCALAPPDATA%/BraveSoftware/Brave-Browser{channel}/User Data/Profile */Network/Cookies",
						"%APPDATA%/BraveSoftware/Brave-Browser{channel}/User Data/Default/Cookies",
						"%APPDATA%/BraveSoftware/Brave-Browser{channel}/User Data/Default/Network/Cookies",
						"%APPDATA%/BraveSoftware/Brave-Browser{channel}/User Data/Profile */Cookies",
						"%APPDATA%/BraveSoftware/Brave-Browser{channel}/User Data/Profile */Network/Cookies",
					},
					Channels:          []string{"", "-beta", "-dev", "-nightly"},
					LocalStatePaths:   defaultLocalStatePaths(),
					WindowsKeySources: defaultWindowsKeySources(),
				},
			},
		},
		"chromium": {
			Name: "chromium",
			Platforms: map[string]ChromiumPlatform{
				"darwin": {
					CookiePathTemplates: []string{
						"~/Library/Application Support/Chromium/Default/Cookies",
						"~/Library/Application Support/Chromium/Profile */Cookies",
					},
					Secrets: []Secret{
						{Service: "Chromium Safe Storage", Account: "Chromium"},
						{Service: "Chrome Safe Storage", Account: "Chrome"},
					},
				},
				"linux": {
					CookiePathTemplates: []string{
						"~/snap/chromium/common/chromium/Default/Cookies",
						"~/.config/chromium/Default/Cookies",
						"~/.config/chromium/Profile */Cookies",
						"~/.var/app/org.chromium.Chromium/config/chromium/Default/Cookies",
						"~/.var/app/org.chromium.Chromium/config/chromium/Profile */Cookies",
					},
					LinuxLibsecretRefs: []LinuxLibsecretRef{
						{Schema: "chrome_libsecret_os_crypt_password_v2", Application: "chromium"},
						{Schema: "chrome_libsecret_os_crypt_password_v1", Application: "chromium"},
					},
					LinuxKWalletRefs: []LinuxKWalletRef{
						{Folder: "Chromium Keys", Key: "Chromium Safe Storage"},
					},
				},
				"windows": {
					CookiePathTemplates: []string{
						"%LOCALAPPDATA%/Chromium/User Data/Default/Cookies",
						"%LOCALAPPDATA%/Chromium/User Data/Default/Network/Cookies",
						"%LOCALAPPDATA%/Chromium/User Data/Profile */Cookies",
						"%LOCALAPPDATA%/Chromium/User Data/Profile */Network/Cookies",
						"%APPDATA%/Chromium/User Data/Default/Cookies",
						"%APPDATA%/Chromium/User Data/Default/Network/Cookies",
						"%APPDATA%/Chromium/User Data/Profile */Cookies",
						"%APPDATA%/Chromium/User Data/Profile */Network/Cookies",
					},
					LocalStatePaths:   defaultLocalStatePaths(),
					WindowsKeySources: defaultWindowsKeySources(),
				},
			},
		},
		"vivaldi": {
			Name: "vivaldi",
			Platforms: map[string]ChromiumPlatform{
				"darwin": {
					CookiePathTemplates: []string{
						"~/Library/Application Support/Vivaldi/Default/Cookies",
						"~/Library/Application Support/Vivaldi/Profile */Cookies",
					},
					Secrets: []Secret{
						{Service: "Vivaldi Safe Storage", Account: "Vivaldi"},
						{Service: "Chrome Safe Storage", Account: "Chrome"},
					},
				},
				"linux": {
					CookiePathTemplates: []string{
						"~/.config/vivaldi/Default/Cookies",
						"~/.config/vivaldi/Profile */Cookies",
						"~/.config/vivaldi-snapshot/Default/Cookies",
						"~/.config/vivaldi-snapshot/Profile */Cookies",
						"~/.var/app/com.vivaldi.Vivaldi/config/vivaldi/Default/Cookies",
						"~/.var/app/com.vivaldi.Vivaldi/config/vivaldi/Profile */Cookies",
					},
					LinuxLibsecretRefs: []LinuxLibsecretRef{
						{Schema: "chrome_libsecret_os_crypt_password_v2", Application: "chrome"},
						{Schema: "chrome_libsecret_os_crypt_password_v1", Application: "chrome"},
					},
					LinuxKWalletRefs: []LinuxKWalletRef{
						{Folder: "Chrome Keys", Key: "Chrome Safe Storage"},
					},
				},
				"windows": {
					CookiePathTemplates: []string{
						"%LOCALAPPDATA%/Vivaldi/User Data/Default/Cookies",
						"%LOCALAPPDATA%/Vivaldi/User Data/Default/Network/Cookies",
						"%LOCALAPPDATA%/Vivaldi/User Data/Profile */Cookies",
						"%LOCALAPPDATA%/Vivaldi/User Data/Profile */Network/Cookies",
						"%APPDATA%/Vivaldi/User Data/Default/Cookies",
						"%APPDATA%/Vivaldi/User Data/Default/Network/Cookies",
						"%APPDATA%/Vivaldi/User Data/Profile */Cookies",
						"%APPDATA%/Vivaldi/User Data/Profile */Network/Cookies",
					},
					LocalStatePaths:   defaultLocalStatePaths(),
					WindowsKeySources: defaultWindowsKeySources(),
				},
			},
		},
		"edge": {
			Name: "edge",
			Platforms: map[string]ChromiumPlatform{
				"darwin": {
					CookiePathTemplates: []string{
						"~/Library/Application Support/Microsoft Edge{channel}/Default/Cookies",
						"~/Library/Application Support/Microsoft Edge{channel}/Profile */Cookies",
					},
					Channels: []string{"", " Beta", " Dev", " Canary"},
					Secrets: []Secret{
						{Service: "Microsoft Edge Safe Storage", Account: "Microsoft Edge"},
					},
				},
				"linux": {
					CookiePathTemplates: []string{
						"~/.config/microsoft-edge{channel}/Default/Cookies",
						"~/.config/microsoft-edge{channel}/Profile */Cookies",
						"~/.var/app/com.microsoft.Edge/config/microsoft-edge{channel}/Default/Cookies",
						"~/.var/app/com.microsoft.Edge/config/microsoft-edge{channel}/Profile */Cookies",
					},
					Channels: []string{"", "-beta", "-dev", "-nightly"},
					LinuxLibsecretRefs: []LinuxLibsecretRef{
						{Schema: "chrome_libsecret_os_crypt_password_v2", Application: "chromium"},
						{Schema: "chrome_libsecret_os_crypt_password_v1", Application: "chromium"},
					},
					LinuxKWalletRefs: []LinuxKWalletRef{
						{Folder: "Chromium Keys", Key: "Chromium Safe Storage"},
					},
				},
				"windows": {
					CookiePathTemplates: []string{
						"%LOCALAPPDATA%/Microsoft/Edge{channel}/User Data/Default/Cookies",
						"%LOCALAPPDATA%/Microsoft/Edge{channel}/User Data/Default/Network/Cookies",
						"%LOCALAPPDATA%/Microsoft/Edge{channel}/User Data/Profile */Cookies",
						"%LOCALAPPDATA%/Microsoft/Edge{channel}/User Data/Profile */Network/Cookies",
						"%APPDATA%/Microsoft/Edge{channel}/User Data/Default/Cookies",
						"%APPDATA%/Microsoft/Edge{channel}/User Data/Default/Network/Cookies",
						"%APPDATA%/Microsoft/Edge{channel}/User Data/Profile */Cookies",
						"%APPDATA%/Microsoft/Edge{channel}/User Data/Profile */Network/Cookies",
					},
					Channels:          []string{"", "-beta", "-dev", "-nightly"},
					LocalStatePaths:   defaultLocalStatePaths(),
					WindowsKeySources: defaultWindowsKeySources(),
				},
			},
		},
		"opera": {
			Name: "opera",
			Platforms: map[string]ChromiumPlatform{
				"darwin": {
					CookiePathTemplates: []string{
						"~/Library/Application Support/com.operasoftware.Opera/Cookies",
						"~/Library/Application Support/com.operasoftware.OperaNext/Cookies",
						"~/Library/Application Support/com.operasoftware.OperaDeveloper/Cookies",
					},
					Secrets: []Secret{
						{Service: "Opera Safe Storage", Account: "Opera"},
					},
				},
				"linux": {
					CookiePathTemplates: []string{
						"~/snap/opera/*/.config/opera/Default/Cookies",
						"~/snap/opera/*/.config/opera/Cookies",
						"~/.config/opera/Default/Cookies",
						"~/.config/opera/Cookies",
						"~/.var/app/com.opera.Opera/config/opera/Default/Cookies",
						"~/.var/app/com.opera.Opera/config/opera/Cookies",
						"~/snap/opera-beta/*/.config/opera/Default/Cookies",
						"~/snap/opera-beta/*/.config/opera/Cookies",
						"~/.config/opera-beta/Default/Cookies",
						"~/.config/opera-beta/Cookies",
						"~/.var/app/com.opera.Opera/config/opera-beta/Default/Cookies",
						"~/.var/app/com.opera.Opera/config/opera-beta/Cookies",
						"~/snap/opera-developer/*/.config/opera/Default/Cookies",
						"~/snap/opera-developer/*/.config/opera/Cookies",
						"~/.config/opera-developer/Default/Cookies",
						"~/.config/opera-developer/Cookies",
						"~/.var/app/com.opera.Opera/config/opera-developer/Default/Cookies",
						"~/.var/app/com.opera.Opera/config/opera-developer/Cookies",
					},
					LinuxLibsecretRefs: []LinuxLibsecretRef{
						{Schema: "chrome_libsecret_os_crypt_password_v2", Application: "chromium"},
						{Schema: "chrome_libsecret_os_crypt_password_v1", Application: "chromium"},
					},
					LinuxKWalletRefs: []LinuxKWalletRef{
						{Folder: "Chromium Keys", Key: "Chromium Safe Storage"},
					},
				},
				"windows": {
					CookiePathTemplates: []string{
						"%LOCALAPPDATA%/Opera Software/Opera {channel}/Cookies",
						"%LOCALAPPDATA%/Opera Software/Opera {channel}/Network/Cookies",
						"%APPDATA%/Opera Software/Opera {channel}/Cookies",
						"%APPDATA%/Opera Software/Opera {channel}/Network/Cookies",
					},
					Channels:          []string{"Stable", "Next", "Developer"},
					LocalStatePaths:   defaultLocalStatePaths(),
					WindowsKeySources: defaultWindowsKeySources(),
				},
			},
		},
		"opera-gx": {
			Name: "opera-gx",
			Platforms: map[string]ChromiumPlatform{
				"darwin": {
					CookiePathTemplates: []string{
						"~/Library/Application Support/com.operasoftware.OperaGX/Cookies",
					},
					Secrets: []Secret{
						{Service: "Opera Safe Storage", Account: "Opera"},
					},
				},
				"linux": {
					CookiePathTemplates: nil,
					LinuxLibsecretRefs: []LinuxLibsecretRef{
						{Schema: "chrome_libsecret_os_crypt_password_v2", Application: "chromium"},
						{Schema: "chrome_libsecret_os_crypt_password_v1", Application: "chromium"},
					},
					LinuxKWalletRefs: []LinuxKWalletRef{
						{Folder: "Chromium Keys", Key: "Chromium Safe Storage"},
					},
				},
				"windows": {
					CookiePathTemplates: []string{
						"%LOCALAPPDATA%/Opera Software/Opera GX {channel}/Cookies",
						"%LOCALAPPDATA%/Opera Software/Opera GX {channel}/Network/Cookies",
						"%APPDATA%/Opera Software/Opera GX {channel}/Cookies",
						"%APPDATA%/Opera Software/Opera GX {channel}/Network/Cookies",
					},
					Channels:          []string{"Stable", ""},
					LocalStatePaths:   defaultLocalStatePaths(),
					WindowsKeySources: defaultWindowsKeySources(),
				},
			},
		},
		"arc": {
			Name: "arc",
			Platforms: map[string]ChromiumPlatform{
				"darwin": {
					CookiePathTemplates: []string{
						"~/Library/Application Support/Arc/User Data/Default/Cookies",
						"~/Library/Application Support/Arc/User Data/Profile */Cookies",
					},
					Secrets: []Secret{
						{Service: "Arc Safe Storage", Account: "Arc"},
					},
				},
				"linux": {
					CookiePathTemplates: []string{
						"~/snap/arc/common/arc/Default/Cookies",
						"~/.config/arc/Default/Cookies",
						"~/.config/arc/Profile */Cookies",
						"~/.var/app/org.arc.Arc/config/arc/Default/Cookies",
						"~/.var/app/org.arc.Arc/config/arc/Profile */Cookies",
					},
					LinuxLibsecretRefs: []LinuxLibsecretRef{
						{Schema: "chrome_libsecret_os_crypt_password_v2", Application: "arc"},
						{Schema: "chrome_libsecret_os_crypt_password_v1", Application: "arc"},
					},
					LinuxKWalletRefs: []LinuxKWalletRef{
						{Folder: "Arc Keys", Key: "Arc Safe Storage"},
					},
				},
				"windows": {
					CookiePathTemplates: []string{
						"%LOCALAPPDATA%/Packages/TheBrowserCompany.Arc*/LocalCache/Local/Arc/User Data/Default/Network/Cookies",
						"%LOCALAPPDATA%/Packages/TheBrowserCompany.Arc*/LocalCache/Local/Arc/User Data/Profile */Network/Cookies",
					},
					LocalStatePaths:   defaultLocalStatePaths(),
					WindowsKeySources: defaultWindowsKeySources(),
				},
			},
		},
	}

	specs["edge-dev"] = aliasChromiumChannel(specs["edge"], "edge-dev", map[string][]string{
		"darwin":  {" Dev"},
		"linux":   {"-dev"},
		"windows": {"-dev"},
	})
	edgeDevDarwin := specs["edge-dev"].Platforms["darwin"]
	edgeDevDarwin.Secrets = []Secret{
		{Service: "Microsoft Edge Dev Safe Storage", Account: "Microsoft Edge Dev"},
		{Service: "Microsoft Edge Safe Storage", Account: "Microsoft Edge"},
	}
	specs["edge-dev"].Platforms["darwin"] = edgeDevDarwin

	return specs
}()

var mozillaSpecs = map[string]MozillaSpec{
	"firefox": {
		Name: "firefox",
		Platforms: map[string]MozillaPlatform{
			"darwin": {
				ProfilePathTemplates: []string{"~/Library/Application Support/Firefox"},
			},
			"linux": {
				ProfilePathTemplates: []string{
					"~/snap/firefox/common/.mozilla/firefox",
					"~/.mozilla/firefox",
					"~/.var/app/org.mozilla.firefox/.mozilla/firefox",
				},
			},
			"windows": {
				ProfilePathTemplates: []string{
					"%APPDATA%/Mozilla/Firefox",
					"%LOCALAPPDATA%/Mozilla/Firefox",
				},
			},
		},
	},
	"librewolf": {
		Name: "librewolf",
		Platforms: map[string]MozillaPlatform{
			"darwin": {
				ProfilePathTemplates: []string{"~/Library/Application Support/librewolf"},
			},
			"linux": {
				ProfilePathTemplates: []string{
					"~/snap/librewolf/common/.librewolf",
					"~/.librewolf",
				},
			},
			"windows": {
				ProfilePathTemplates: []string{
					"%LOCALAPPDATA%/librewolf",
					"%APPDATA%/librewolf",
				},
			},
		},
	},
	"zen": {
		Name: "zen",
		Platforms: map[string]MozillaPlatform{
			"darwin": {
				ProfilePathTemplates: []string{"~/Library/Application Support/zen"},
			},
			"linux": {
				ProfilePathTemplates: []string{"~/.zen"},
			},
			"windows": {
				ProfilePathTemplates: []string{
					"%APPDATA%/zen",
					"%LOCALAPPDATA%/zen",
				},
			},
		},
	},
}

var safariSpecs = map[string]SafariSpec{
	"safari": {
		Name: "safari",
		Platforms: map[string]SafariPlatform{
			"darwin": {
				CookiePathTemplates: []string{
					"~/Library/Containers/com.apple.Safari/Data/Library/Cookies/Cookies.binarycookies",
					"~/Library/Cookies/Cookies.binarycookies",
				},
			},
		},
	},
}

func aliasChromiumChannel(base ChromiumSpec, name string, channels map[string][]string) ChromiumSpec {
	platforms := map[string]ChromiumPlatform{}
	for goos, platform := range base.Platforms {
		copied := ChromiumPlatform{
			CookiePathTemplates: append([]string(nil), platform.CookiePathTemplates...),
			Channels:            append([]string(nil), platform.Channels...),
			Secrets:             append([]Secret(nil), platform.Secrets...),
			LinuxLibsecretRefs:  append([]LinuxLibsecretRef(nil), platform.LinuxLibsecretRefs...),
			LinuxKWalletRefs:    append([]LinuxKWalletRef(nil), platform.LinuxKWalletRefs...),
			LocalStatePaths:     append([]string(nil), platform.LocalStatePaths...),
			WindowsKeySources:   append([]WindowsKeySource(nil), platform.WindowsKeySources...),
		}
		if override, ok := channels[goos]; ok {
			copied.Channels = append([]string(nil), override...)
		}
		platforms[goos] = copied
	}
	return ChromiumSpec{
		Name:      name,
		Platforms: platforms,
	}
}
