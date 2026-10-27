#!/bin/sh
# Fixture (shell-pipefail, negative): no pipefail, but also no pipeline — case arms, quoted
# bars, `||` and here-document text are not pipelines. Nothing here may be flagged.
set -eu
case "$1" in
  x86_64 | amd64) echo linux-x86_64 ;;
esac
command -v jq >/dev/null || exit 1
printf '%s\n' "a | b"
cat <<EOF2
| table | row |
EOF2
