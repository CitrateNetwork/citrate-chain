#!/usr/bin/env bash
# producer_baseline.sh: skeleton (red commit).
set -euo pipefail
case "${1:-}" in
  apply|check|print-unit|print-disk-alert) exit 0 ;;
  *) echo "usage: $0 apply|check|print-unit|print-disk-alert" >&2; exit 2 ;;
esac
