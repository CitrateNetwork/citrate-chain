#!/usr/bin/env bash
# Fixture (shell-pipefail, positive): an ops script that pipes without pipefail, so a failed
# download is hidden by tar's exit status. Must be flagged.
set -eu
curl -fsSL "$URL" | tar -xz -C "${DEST:?}"
digest="$(sha256sum "${DEST:?}/payload" | awk '{print $1}')"
