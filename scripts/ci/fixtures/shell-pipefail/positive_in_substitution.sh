#!/usr/bin/env bash
# Fixture (shell-pipefail, positive): the only pipeline sits inside a quoted command
# substitution; a failed sha256sum would still yield an empty, "successful" digest. Flagged.
set -eu
digest="$(sha256sum "${1:?}" | awk '{print $1}')"
