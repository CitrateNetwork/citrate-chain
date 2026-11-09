#!/usr/bin/env bash
# Fixture (shell-pipefail, negative): the same pipeline with pipefail set, plus text that only
# looks like a pipe. Nothing here may be flagged.
set -euo pipefail
case "$(uname -m)" in
  arm64 | aarch64) arch=arm64 ;;
esac
grep -E 'a|b' file.txt || true
curl -fsSL "$URL" | tar -xz -C "${DEST:?}"
