#!/usr/bin/env bash
# Scenario lab: recreates real network failures in throwaway network
# namespaces and checks sstui diagnoses them (and stays quiet on healthy
# traffic). See lab/lab_test.go.
#
# Builds sstui and the lab test binary as you, then runs the scenarios as
# root via sudo, here or on another machine. Needs iproute2 (ip, ss) and tc
# with the netem qdisc there.
#
#   scripts/lab.sh                      # every scenario
#   scripts/lab.sh -run 'ZeroWindow'    # some of them (go test -run syntax)
#   SSTUI_LAB_KEEP=dir scripts/lab.sh   # also keep every recording in dir
#   SSTUI_LAB_HOST=user@vm scripts/lab.sh
#                                       # run on another machine over ssh
#                                       # (passwordless sudo there)
#   SSTUI_LAB_HOSTWIDE=1 scripts/lab.sh # also scenarios that change
#                                       # host-wide settings (tcp_mem): only
#                                       # on a disposable machine
#   SSTUI_LAB_DEMO=docs/demo/web-1.jsonl.gz scripts/lab.sh -run Demo
#                                       # record the README demo (here only;
#                                       # also needs unshare and hostname)
set -euo pipefail
cd "$(dirname "$0")/.."

out=$(mktemp -d)
trap 'rm -rf "$out"' EXIT

# Static, so the binaries also run on another machine.
CGO_ENABLED=0 go build -o "$out/sstui" .
CGO_ENABLED=0 go test -c -tags lab -o "$out/lab.test" ./lab

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
hostwide=${SSTUI_LAB_HOSTWIDE:-}
demo=
if [ -n "${SSTUI_LAB_DEMO:-}" ]; then
	if [ -n "${SSTUI_LAB_HOST:-}" ]; then
		echo "SSTUI_LAB_DEMO records here only; unset SSTUI_LAB_HOST" >&2
		exit 2
	fi
	demo=$(realpath "$SSTUI_LAB_DEMO")
fi

if [ -z "${SSTUI_LAB_HOST:-}" ]; then
	sudo env SSTUI_BIN="$out/sstui" SSTUI_LAB_KEEP="$keep" SSTUI_LAB_HOSTWIDE="$hostwide" SSTUI_LAB_DEMO="$demo" \
		"$out/lab.test" -test.v -test.timeout 30m "${args[@]}"
	exit
fi

host=$SSTUI_LAB_HOST
rdir=$(ssh "$host" mktemp -d)
trap 'rm -rf "$out"; ssh "$host" sudo rm -rf "$rdir"' EXIT
scp -q "$out/sstui" "$out/lab.test" "$host:$rdir/"
rkeep=
if [ -n "$keep" ]; then
	rkeep=$rdir/keep
	ssh "$host" mkdir "$rkeep"
fi
# ssh joins its arguments into one remote command line: quote ours.
rargs=
if [ ${#args[@]} -gt 0 ]; then
	rargs=$(printf '%q ' "${args[@]}")
fi
status=0
ssh "$host" sudo env SSTUI_BIN="$rdir/sstui" SSTUI_LAB_KEEP="$rkeep" SSTUI_LAB_HOSTWIDE="$hostwide" \
	"$rdir/lab.test" -test.v -test.timeout 30m "$rargs" || status=$?
if [ -n "$keep" ]; then
	scp -q "$host:$rkeep/*" "$keep/" 2>/dev/null || true
fi
exit $status
