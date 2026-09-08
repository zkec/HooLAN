#!/usr/bin/env bash
# scripts/tproxy/remove.sh — tear down the TPROXY interception ruleset
#
# Counterpart to apply.sh. Reads the ephemeral state file written by the last
# apply.sh so it removes exactly what was installed — no hardcoded marks or
# tables that can drift. Idempotent and safe to run when nothing is installed.
set -euo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
STATE_FILE="/run/proxy-manager/state.conf"

need() { command -v "$1" >/dev/null 2>&1 || { echo "missing dependency: $1" >&2; exit 1; }; }
need nft; need ip

if [[ $EUID -ne 0 ]]; then echo "remove.sh must run as root" >&2; exit 1; fi

# Defaults match tproxy.conf; the state file overrides them when present.
TPROXY_FWMARK="0x1"
TPROXY_TABLE="100"
if [[ -f "$STATE_FILE" ]]; then
  # shellcheck disable=SC1090
  source "$STATE_FILE"
fi

echo "[remove] tearing down table inet proxy_tproxy (if present)..."
# `delete table` is atomic and does not touch any other table —
# DOCKER-USER / DOCKER / nat / filter tables from iptables-nft are separate
# tables and are left intact. `|| true` makes this idempotent.
nft delete table inet proxy_tproxy 2>/dev/null || true

echo "[remove] removing policy routing rule fwmark $TPROXY_FWMARK -> table $TPROXY_TABLE..."
ip rule del fwmark "$TPROXY_FWMARK" lookup "$TPROXY_TABLE" 2>/dev/null || true
# Only flush the TPROXY table we own; the main table and Docker's routes
# are untouched.
ip route flush table "$TPROXY_TABLE" 2>/dev/null || true

# Do NOT reset net.ipv4.ip_forward or rp_filter here — those are host-wide
# sysctls that may have been set before we ever ran, and clearing them would
# break Docker networking or WireGuard for other services.

rm -f "$STATE_FILE" 2>/dev/null || true
echo "[remove] done"
