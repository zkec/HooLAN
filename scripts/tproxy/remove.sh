#!/usr/bin/env bash
# Remove ONLY the table and route tuple owned by proxy-manager.
set -euo pipefail
RUNTIME_DIR="${RUNTIME_DIR:-/run/proxy-manager}"
STATE_FILE="$RUNTIME_DIR/state.conf"
need() { command -v "$1" >/dev/null 2>&1 || { echo "missing dependency: $1" >&2; exit 1; }; }
for tool in nft ip flock; do need "$tool"; done
if [[ "$(id -u)" -ne 0 ]]; then echo "remove.sh must run as root" >&2; exit 1; fi
mkdir -p "$RUNTIME_DIR"
exec 9>"$RUNTIME_DIR/tproxy.lock"
flock -x 9
TPROXY_FWMARK="0x1"
TPROXY_TABLE="100"
if [[ -f "$STATE_FILE" ]]; then source "$STATE_FILE"; fi

# A permission/kernel failure is not the same as an absent table. Do not
# remove routing while interception could still be installed.
TABLES="$(nft list tables)"
if printf '%s\n' "$TABLES" | grep -qx 'table inet proxy_tproxy'; then
  nft delete table inet proxy_tproxy
fi
# Remove duplicate legacy automatic-priority rules as well as our fixed one.
# The entire mark and dedicated lookup table identify this gateway's rule.
while ip -4 rule del fwmark "$TPROXY_FWMARK/0xffffffff" lookup "$TPROXY_TABLE" 2>/dev/null; do :; done
# Do not flush arbitrary other routes in the table.
ip -4 route del local default dev lo table "$TPROXY_TABLE" 2>/dev/null || true
rm -f "$STATE_FILE"
echo "[remove] removed inet proxy_tproxy and its policy route"
# Host-wide ip_forward/rp_filter settings are shared with Docker/WireGuard.
