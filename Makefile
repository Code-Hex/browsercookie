GOLANGCI_LINT ?= $(shell if [ -x "$$(go env GOPATH)/bin/golangci-lint" ]; then printf '%s/bin/golangci-lint' "$$(go env GOPATH)"; else command -v golangci-lint; fi)
GOCACHE ?= $(CURDIR)/.cache/go-build
GOLANGCI_LINT_CACHE ?= $(CURDIR)/.cache/golangci-lint

.PHONY: test test-unit test-smoke-macos lint lint-fix fmt

test: test-unit

test-unit:
	GOCACHE=$(GOCACHE) go test ./...

test-smoke-macos:
	GOCACHE=$(GOCACHE) BROWSERCOOKIE_SMOKE_MACOS=1 go test -run TestSmokeMacOS ./...

lint:
	GOCACHE=$(GOCACHE) GOLANGCI_LINT_CACHE=$(GOLANGCI_LINT_CACHE) $(GOLANGCI_LINT) run ./...

lint-fix:
	GOCACHE=$(GOCACHE) GOLANGCI_LINT_CACHE=$(GOLANGCI_LINT_CACHE) $(GOLANGCI_LINT) run --fix ./...

fmt:
	GOCACHE=$(GOCACHE) GOLANGCI_LINT_CACHE=$(GOLANGCI_LINT_CACHE) $(GOLANGCI_LINT) fmt ./...
