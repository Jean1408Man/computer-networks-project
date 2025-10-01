#!/usr/bin/env bash
set -euo pipefail

BIN="${1:-$(readlink -f "$(command -v python3)")}"

/usr/bin/env sudo setcap cap_net_raw,cap_net_admin+ep "$BIN"
/usr/bin/env getcap -v "$BIN"
echo "✅ Capacidades aplicadas a: $BIN"
