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
- Filter cookies with `WithDomains(...)`
- Override auto-discovered cookie store paths with `WithCookieFiles(...)`
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

If you already know the cookie file path, you can override discovery:

```go
cookies, err := browsercookie.Chrome(
	browsercookie.WithCookieFiles("/path/to/Cookies"),
)
if err != nil {
	// handle error
}
```

## Errors

The package returns a small set of public errors:

- `ErrNotFound` when no readable cookie store was found
- `ErrUnsupported` when the browser or platform is not implemented
- `ErrInvalidStore` when a cookie store exists but cannot be parsed
- `ErrDecrypt` when an encrypted cookie value could not be decrypted
