#!/usr/bin/env bash
# Scenario lab: recreates real network failures in throwaway network
# namespaces and checks sstui diagnoses them (and stays quiet on healthy
# traffic). See lab/lab_test.go.
#
# Builds sstui and the lab test binary as you, then runs the scenarios as
# root via sudo. Needs iproute2 (ip, ss) and tc with the netem qdisc.
#
#   scripts/lab.sh                      # every scenario
#   scripts/lab.sh -run 'ZeroWindow'    # some of them (go test -run syntax)
#   SSTUI_LAB_KEEP=dir scripts/lab.sh   # also keep every recording in dir
set -euo pipefail
cd "$(dirname "$0")/.."

out=$(mktemp -d)
trap 'rm -rf "$out"' EXIT

go build -o "$out/sstui" .
go test -c -tags lab -o "$out/lab.test" ./lab

args=()
for a in "$@"; do
	case "$a" in
	-run | -v | -count | -timeout) args+=("-test.${a#-}") ;;
	*) args+=("$a") ;;
	esac
done

keep=
if [ -n "${SSTUI_LAB_KEEP:-}" ]; then
	mkdir -p "$SSTUI_LAB_KEEP"
	keep=$(realpath "$SSTUI_LAB_KEEP")
fi
sudo env SSTUI_BIN="$out/sstui" SSTUI_LAB_KEEP="$keep" \
	"$out/lab.test" -test.v -test.timeout 10m "${args[@]}"
