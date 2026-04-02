# browsercookie

[![Go Reference](https://pkg.go.dev/badge/github.com/Code-Hex/browsercookie.svg)](https://pkg.go.dev/github.com/Code-Hex/browsercookie)
[![test](https://github.com/Code-Hex/browsercookie/actions/workflows/test.yml/badge.svg?branch=main)](https://github.com/Code-Hex/browsercookie/actions/workflows/test.yml)
[![lint](https://github.com/Code-Hex/browsercookie/actions/workflows/lint.yml/badge.svg?branch=main)](https://github.com/Code-Hex/browsercookie/actions/workflows/lint.yml)
[![browser](https://github.com/Code-Hex/browsercookie/actions/workflows/browser.yml/badge.svg?branch=main)](https://github.com/Code-Hex/browsercookie/actions/workflows/browser.yml)

`browsercookie` is a Go library that reads cookies from browser stores on the local machine.

It can auto-discover supported browsers, load cookies from one browser directly, filter by domain, and turn the result into a `net/http/cookiejar.Jar`. If you just want browser cookies in normal Go types, that is the whole job.

## Inspiration

This package was inspired by these projects:

- [thewh1teagle/rookie](https://github.com/thewh1teagle/rookie)
- [richardpenman/browsercookie](https://github.com/richardpenman/browsercookie)

They solve the same kind of problem in other ecosystems. This repository does it as a Go library with a Go-shaped API.

## What it does

- Read cookies from local browser stores
- Load from every supported browser with `Load()`
- Load from a specific browser with functions such as `Chrome()`, `Firefox()`, or `Safari()`
- Load cookies from Electron apps explicitly with `Electron(app)`
- Inspect persisted Electron auth storage with `InspectElectronAuthStorage(app)`
- Filter cookies with `WithDomains(...)`
- Override auto-discovered cookie store paths with `WithCookieFiles(...)`
- Override Electron bundle paths with `WithElectronAppPaths(...)`
- Override Electron session roots with `WithElectronSessionRoots(...)`
- Override Electron keychain/keyring names with `WithElectronKeyringNames(...)`
- Convert `[]*http.Cookie` into a `*cookiejar.Jar` with `Jar(...)`

## Supported browsers and operating systems

The package currently knows these browser and OS combinations:

| Browser | Linux | macOS | Windows |
| :-- | :--: | :--: | :--: |
| Arc | yes | yes | yes |
| Brave | yes | yes | yes |
| Chrome | yes | yes | yes |
| Chromium | yes | yes | yes |
| Edge | yes | yes | yes |
| Edge Dev | yes | yes | yes |
| Firefox | yes | yes | yes |
| LibreWolf | yes | yes | yes |
| Opera | yes | yes | yes |
| Opera GX | - | yes | yes |
| Safari | - | yes | - |
| Vivaldi | yes | yes | yes |
| Zen | yes | yes | yes |

Support still depends on the browser and the operating system. When the current platform is not implemented, the package returns `ErrUnsupported`.

Electron apps are also supported as an explicit opt-in on Linux, macOS, and Windows with `Electron(app)`, as long as the app uses Chromium-style persisted session storage.

## Install

```bash
go get github.com/Code-Hex/browsercookie
```

## Synopsis

Load cookies from any supported browser, filter them to one domain, then use them with `http.Client`:

```go
package main

import (
	"log"
	"net/http"

	"github.com/Code-Hex/browsercookie"
)

func main() {
	cookies, err := browsercookie.Load(
		browsercookie.WithDomains("example.com"),
	)
	if err != nil {
		log.Fatal(err)
	}

	jar, err := browsercookie.Jar(cookies)
	if err != nil {
		log.Fatal(err)
	}

	client := &http.Client{Jar: jar}
	resp, err := client.Get("https://example.com")
	if err != nil {
		log.Fatal(err)
	}
	defer resp.Body.Close()
}
```

If you want a specific browser instead of auto-discovery, call it directly:

```go
cookies, err := browsercookie.Chrome()
if err != nil {
	// handle error
}

cookies, err = browsercookie.Firefox(
	browsercookie.WithDomains("example.com"),
)
if err != nil {
	// handle error
}
```

Electron apps are loaded explicitly and are not part of `Load()` auto-discovery:

```go
cookies, err := browsercookie.Electron("Code")
if err != nil {
	// handle error
}
```

If you want to inspect persisted Electron auth storage without reading secret values, use the inspection API:

```go
report, err := browsercookie.InspectElectronAuthStorage(
	"Discord",
	browsercookie.WithElectronAppPaths("/Applications/Discord.app"),
)
if err != nil {
	// handle error
}

for _, location := range report.Locations {
	log.Printf("%s %s %s", location.Kind, location.Status, location.Path)
}
```

If you already know the cookie file path, you can override discovery:

```go
cookies, err := browsercookie.Chrome(
	browsercookie.WithCookieFiles("/path/to/Cookies"),
)
if err != nil {
	// handle error
}
```

If the Electron app stores session data outside the default `userData` or `sessionData` path, override the session roots directly:

```go
cookies, err := browsercookie.Electron(
	"Code",
	browsercookie.WithElectronSessionRoots("/path/to/sessionData"),
	browsercookie.WithElectronKeyringNames("Code"),
)
if err != nil {
	// handle error
}
```

## Electron notes

- `Electron(app)` reads Chromium-style cookie databases only.
- `InspectElectronAuthStorage(app)` performs static discovery only. It reports persisted locations, bundle references, and secret-store refs without returning the stored values.
- It loads both the default session and persisted partition stores under `Partitions/*`.
- The inspection API can report `Cookies`, `Login Data`, `Local Storage`, `Session Storage`, `IndexedDB`, partition storage, `safeStorage`, `keytar`, and `Local State` references.
- In-memory partitions cannot be read from disk.
- Apps that use `session.fromPath(...)` outside the default app data directory need `WithElectronSessionRoots(...)`.
- Linux and Windows bundle discovery are intentionally conservative. Use `WithElectronAppPaths(...)` when you need deterministic bundle inspection there.
- On Windows, Chromium v20 app-bound encrypted cookies still follow the existing `ErrUnsupported` limitation.

## Errors

The package returns a small set of public errors:

- `ErrNotFound` when no readable cookie store was found
- `ErrUnsupported` when the browser or platform is not implemented
- `ErrInvalidStore` when a cookie store exists but cannot be parsed
- `ErrDecrypt` when an encrypted cookie value could not be decrypted
