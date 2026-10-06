#!/usr/bin/env bash
# Builds the Windows client and every test of the workspace for Windows, copies them
# to a Windows test machine over ssh, runs them there and prints a summary.
#
#   scripts/windows-vm-test.sh <ssh host> [test name filter]
#
# The host is anything ssh accepts (`user@windows-vm`, or a Host from ~/.ssh/config)
# and needs the OpenSSH server; cmd or PowerShell as its default shell both work.
# Point it only at a disposable test machine: the tests start the real client there
# (against a mock portal on loopback, with its folders in %TEMP%).
#
# An administrator's ssh session on Windows is elevated (no UAC filtering over ssh);
# the end-to-end test then checks that the client refuses it and allows it in its own
# config. Log in as a standard user to test the unelevated path.
#
# Needs cargo-xwin (`cargo install cargo-xwin`). The first build downloads the MSVC
# CRT and Windows SDK into XWIN_CACHE_DIR; that needs XWIN_ACCEPT_LICENSE=1.
set -euo pipefail

host=${1:?usage: $0 <ssh host> [test name filter]}
filter=${2:-}
target=x86_64-pc-windows-msvc
root=$(cd "$(dirname "$0")/.." && pwd)
target_dir=${CARGO_TARGET_DIR:-$root/target}
stage=$(mktemp -d "${TMPDIR:-/var/tmp}/pithagoras-sync-win.XXXXXX")
remote=pithagoras-sync-test-$(date +%Y%m%d-%H%M%S)
trap 'rm -rf "$stage"' EXIT

cd "$root"
echo "== building for $target"
cargo xwin build --release --target "$target" -p pithagoras-sync
cp "$target_dir/$target/release/pithagoras-sync.exe" "$stage/"
# A fresh Windows has no Visual C++ runtime: the program must link it statically
# (.cargo/config.toml), or it does not start there and prints nothing.
if command -v llvm-objdump >/dev/null &&
  llvm-objdump -p "$stage/pithagoras-sync.exe" | grep -qi 'DLL Name: vcruntime'; then
  echo "pithagoras-sync.exe needs VCRUNTIME140.dll; build with crt-static" >&2
  exit 1
fi
cargo xwin test --no-run --target "$target" --workspace --message-format=json \
  | python3 -c '
import json, sys
for line in sys.stdin:
    try:
        m = json.loads(line)
    except ValueError:
        continue
    if m.get("reason") == "compiler-artifact" and m.get("executable") and m["profile"]["test"]:
        print(m["executable"])
' > "$stage/tests.txt"
tests=()
while read -r exe; do
  cp "$exe" "$stage/"
  tests+=("$(basename "$exe")")
done < "$stage/tests.txt"
rm "$stage/tests.txt"
echo "== ${#tests[@]} test programs"

# Through powershell explicitly, so the remote default shell does not matter.
remote_ps() {
  ssh -o BatchMode=yes "$host" "powershell -NoProfile -NonInteractive -Command \"$1\""
}

echo "== copying to $host:$remote"
scp -q -r "$stage" "$host:$remote"

failed=()
for t in "${tests[@]}"; do
  echo "== $t"
  # One thread: the end-to-end tests start clients and commands of their own. The
  # path works in cmd and in PowerShell, whichever is the remote default shell.
  rc=0
  ssh -o BatchMode=yes "$host" ".\\$remote\\$t --test-threads=1 $filter" || rc=$?
  if ((rc)); then
    # ssh passes on the low byte of the exit code: 53 is 0xC0000135, a DLL missing.
    ((rc == 53)) && echo "exit 53: probably STATUS_DLL_NOT_FOUND (0xC0000135)"
    failed+=("$t")
  fi
done

echo "== removing $remote"
remote_ps "Remove-Item -Recurse -Force $remote" || echo "could not remove $remote on $host"

if ((${#failed[@]})); then
  echo "== FAILED: ${failed[*]}"
  exit 1
fi
echo "== all ${#tests[@]} test programs passed"
