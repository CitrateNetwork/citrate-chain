#!/usr/bin/env bash
# Fixture (shell-rm-guard, negative): guarded, literal or non-recursive removals, and text
# that only mentions rm. Nothing here may be flagged.
set -euo pipefail
rm -rf "${WORK:?}"
rm -rf "${STAGE:?}/payload" /tmp/fixed-literal-path
rm -f "$LOGFILE"
trap 'rm -rf "${tmp:?}"' EXIT
echo "to undo: rm -rf '$DATA_DIR' && mv backup '$DATA_DIR'"
# rm -rf "$COMMENTED_OUT"
cat <<NOTE
rm -rf $INSIDE_A_HEREDOC_IS_TEXT
NOTE
