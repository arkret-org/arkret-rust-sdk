#!/usr/bin/env bash
set -euo pipefail
# Isolate the real daemon and keyring from any developer login session.
scratch_home="$(mktemp -d)"
trap 'rm -rf "$scratch_home"' EXIT
export CARGO_HOME="${CARGO_HOME:-$HOME/.cargo}"
export RUSTUP_HOME="${RUSTUP_HOME:-$HOME/.rustup}"
export HOME="$scratch_home"
export ARKRET_TEST_LINUX_KEYSTORE=1
dbus-run-session -- bash -euo pipefail -c '
  export GNOME_KEYRING_CONTROL="$HOME/.cache/keyring"
  mkdir -p "$GNOME_KEYRING_CONTROL"
  printf "%s" "arkret-test-keyring" | gnome-keyring-daemon --unlock --components=secrets --control-directory "$GNOME_KEYRING_CONTROL"
  gnome-keyring-daemon --start --components=secrets --control-directory "$GNOME_KEYRING_CONTROL" >/dev/null
  printf "%s" "durable" | secret-tool store --label=arkret-test-preflight service arkret.test.preflight account preflight
  test "$(secret-tool lookup service arkret.test.preflight account preflight)" = durable
  secret-tool clear service arkret.test.preflight account preflight
  "$@"
' bash "$@"
