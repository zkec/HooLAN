#!/usr/bin/env bash
# scripts/tproxy/apply.sh — render + load the TPROXY interception ruleset
#
# Bare-metal nftables, hook priority mangle (-150). NOT inside Docker:
# the Go backend runs as a systemd unit and calls this script via os/exec.
# Idempotent — safe to re-run. Fails closed: on render or `nft --check`
# failure the kernel ruleset is untouched.
set -euo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
CONF_FILE="${CONF_FILE:-$SCRIPT_DIR/tproxy.conf}"
TEMPLATE="$SCRIPT_DIR/tproxy.nft.template"
RENDERED="/run/proxy-manager/tproxy.nft"
STATE_FILE="/run/proxy-manager/state.conf"

need() { command -v "$1" >/dev/null 2>&1 || { echo "missing dependency: $1" >&2; exit 1; }; }
need nft; need ip; need sysctl

# --- 1. Load config (single source of truth, also read by remove.sh) --------
if [[ ! -f "$CONF_FILE" ]]; then echo "config not found: $CONF_FILE" >&2; exit 1; fi
# shellcheck disable=SC1090
source "$CONF_FILE"

: "${LAN_IF:?LAN_IF missing in $CONF_FILE}"
: "${TPROXY_PORT:?TPROXY_PORT missing}"
: "${TPROXY_FWMARK:?TPROXY_FWMARK missing}"
: "${TPROXY_TABLE:?TPROXY_TABLE missing}"
: "${PI_LAN_IP:?PI_LAN_IP missing}"

# Must be run as root — nft/ip rule/route all require CAP_NET_ADMIN.
if [[ $EUID -ne 0 ]]; then echo "apply.sh must run as root" >&2; exit 1; fi

# --- 2. Discover LAN CIDRs from live addresses (not a hardcoded /24) --------
# A /22 or /23 site would silently miss half its subnet with a static mask.
LAN_CIDRS_RAW="$(ip -4 -o addr show dev "$LAN_IF" scope global 2>/dev/null | awk '{print $4}' || true)"
if [[ -z "$LAN_CIDRS_RAW" ]]; then
  echo "warning: no global IPv4 on $LAN_IF — using $PI_LAN_IP/32 as LAN_CIDRS fallback" >&2
  LAN_CIDR_LIST="$PI_LAN_IP/32"
else
  # "192.168.1.0/24, 10.0.0.0/8" style, nft set literal syntax
  LAN_CIDR_LIST="$(printf '%s\n' "$LAN_CIDRS_RAW" | awk 'NR>1{printf ", "}{printf "%s", $0}')"
fi

# Self-origin exemptions: SELF_ORIGIN_NETS (tproxy.conf). Always include a
# reserved placeholder so the interval set is never empty (nft accepts an
# empty set too, but a placeholder makes the rule path uniform).
SELF_ORIGIN_LIST="240.0.0.1/32"
if [[ -n "${SELF_ORIGIN_NETS:-}" ]]; then
  # shellcheck disable=SC2086
  for net in $SELF_ORIGIN_NETS; do
    SELF_ORIGIN_LIST+=", $net"
  done
fi

mkdir -p "$(dirname "$RENDERED")"

# --- 3. Render template ------------------------------------------------------
# Naive {{VAR}} -> value substitution. Every placeholder must be replaced;
# a leftover {{...}} would be rejected by nft anyway, but we fail early with
# a readable error instead.
render() {
  local out="$1" tmp val
  tmp="$(mktemp)"
  cp "$TEMPLATE" "$tmp"
  # Escape characters special to sed's replacement text: \ & and the | delimiter.
  esc() { printf '%s' "$1" | sed -e 's/[\\&|]/\\&/g'; }
  subst() { # subst VAR VALUE
    sed -i "s|{{$1}}|$(esc "$2")|g" "$tmp"
  }
  subst LAN_CIDR_LIST   "$LAN_CIDR_LIST"
  subst SELF_ORIGIN_LIST "$SELF_ORIGIN_LIST"
  subst TPROXY_PORT     "$TPROXY_PORT"
  subst TPROXY_FWMARK   "$TPROXY_FWMARK"
  subst TPROXY_TABLE    "$TPROXY_TABLE"
  if grep -q '{{' "$tmp"; then
    echo "render failed — unreplaced template variable remains:" >&2
    grep '{{' "$tmp" >&2
    rm -f "$tmp"; exit 1
  fi
  mv "$tmp" "$out"
}

render "$RENDERED"
echo "[apply] rendered $RENDERED"

# --- 4. Pre-flight nft syntax check (kernel untouched on failure) ------------
# NOTE: --check validates syntax only; some errors (e.g. tproxy on wrong hook)
# surface at actual load. The table is small enough that load failure is cheap.
if ! nft --check -f "$RENDERED" 2>/tmp/proxy-manager-nft-check.log; then
  echo "[apply] nft --check failed:" >&2
  cat /tmp/proxy-manager-nft-check.log >&2
  exit 1
fi
echo "[apply] nft syntax ok"

# --- 5. Policy routing for TPROXY --------------------------------------------
# fwmark 0x1 -> lookup table 100 -> local route for ANY destination.
# This is what lets the kernel hand a TPROXY'd packet to sing-box's
# transparent socket without a real route for the client's destination.
# `ip rule del || true` first makes re-runs idempotent.
ip rule del fwmark "$TPROXY_FWMARK" lookup "$TPROXY_TABLE" 2>/dev/null || true
ip rule add fwmark "$TPROXY_FWMARK" lookup "$TPROXY_TABLE"
ip route replace local default dev lo table "$TPROXY_TABLE"

# This box forwards between LAN_IF and WAN.
sysctl -w net.ipv4.ip_forward=1 >/dev/null

# Kernel-mode WireGuard on the Pi (if any): TPROXY-marked packets with
# non-local sources fail rp_filter validation on ingress without this.
# Harmless when no wg interfaces exist (the glob simply matches nothing).
if [[ "${WG_RP_FILTER:-yes}" != "no" ]]; then
  for f in /proc/sys/net/ipv4/conf/wg*/rp_filter; do
    echo 0 > "$f" 2>/dev/null || true
  done
fi

# --- 6. Load nftables ---------------------------------------------------------
# Atomic per-table replace. DOCKER-USER / DOCKER / nat / filter tables from
# iptables-nft are separate tables and are not touched.
nft -f "$RENDERED"
echo "[apply] table inet proxy_tproxy loaded"

# --- 7. Persist state for remove.sh -------------------------------------------
cat > "$STATE_FILE" <<EOF
# generated by apply.sh — do not edit
TPROXY_FWMARK="$TPROXY_FWMARK"
TPROXY_TABLE="$TPROXY_TABLE"
LAN_IF="$LAN_IF"
EOF
echo "[apply] done — state at $STATE_FILE"
