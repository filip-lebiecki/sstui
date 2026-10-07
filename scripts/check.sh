#!/usr/bin/env bash
# Checks to run before committing: formatting, go.mod tidiness, vet,
# staticcheck, and the tests with the race detector. Stops at the first
# failure. Needs only the Go toolchain; staticcheck is fetched at the pinned
# version on first use (network once, cached afterwards).
#
#   scripts/check.sh
set -euo pipefail
cd "$(dirname "$0")/.."

# Bump deliberately: a new staticcheck release can add checks.
STATICCHECK=honnef.co/go/tools/cmd/staticcheck@v0.8.1

step() { printf '\n== %s\n' "$*"; }

step gofmt
unformatted=$(gofmt -l .) || { echo "gofmt couldn't parse a file (syntax error above)"; exit 1; }
if [ -n "$unformatted" ]; then
	printf 'not gofmt-ed (run gofmt -w):\n%s\n' "$unformatted"
	exit 1
fi

step "go mod tidy"
if ! go mod tidy -diff; then
	echo "go.mod/go.sum are not tidy (run go mod tidy)"
	exit 1
fi

step "go vet"
go vet ./...

step staticcheck
go run "$STATICCHECK" ./...

step "go test -race"
# The race detector needs cgo (and a C compiler), even where releases are
# built with CGO_ENABLED=0.
CGO_ENABLED=1 go test -race ./...

printf '\nall checks passed\n'
