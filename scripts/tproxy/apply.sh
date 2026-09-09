#!/usr/bin/env bash
# Render and atomically replace ONLY inet proxy_tproxy, at priority -150.
# Syntax/configuration failures leave the running firewall untouched.
set -euo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
CONF_FILE="${CONF_FILE:-$SCRIPT_DIR/tproxy.conf}"
RUNTIME_DIR="${RUNTIME_DIR:-/run/proxy-manager}"
TEMPLATE="$SCRIPT_DIR/tproxy.nft.template"
RENDERED="$RUNTIME_DIR/tproxy.nft"
STATE_FILE="$RUNTIME_DIR/state.conf"

need() { command -v "$1" >/dev/null 2>&1 || { echo "missing dependency: $1" >&2; exit 1; }; }
for tool in nft ip sysctl flock; do need "$tool"; done
if [[ "$(id -u)" -ne 0 ]]; then echo "apply.sh must run as root" >&2; exit 1; fi
if [[ ! -f "$CONF_FILE" ]]; then echo "config not found: $CONF_FILE" >&2; exit 1; fi
# This is an administrator-owned shell configuration, never browser input.
# shellcheck disable=SC1090
source "$CONF_FILE"
: "${LAN_IF:?LAN_IF missing}"
: "${TPROXY_PORT:?TPROXY_PORT missing}"
: "${TPROXY_FWMARK:?TPROXY_FWMARK missing}"
: "${TPROXY_TABLE:?TPROXY_TABLE missing}"
: "${PI_LAN_IP:?PI_LAN_IP missing}"
TPROXY_RULE_PRIORITY="${TPROXY_RULE_PRIORITY:-10000}"

# Validate values that are interpolated into nft syntax or reserved route IDs.
[[ "$LAN_IF" =~ ^[a-zA-Z0-9_.:-]{1,15}$ ]] || { echo "invalid LAN_IF" >&2; exit 1; }
[[ "$TPROXY_PORT" =~ ^[1-9][0-9]{0,4}$ ]] && ((TPROXY_PORT <= 65535)) || { echo "invalid TPROXY_PORT" >&2; exit 1; }
[[ "$TPROXY_FWMARK" =~ ^(0x[0-9a-fA-F]{1,8}|[1-9][0-9]{0,9})$ ]] && ((TPROXY_FWMARK > 0 && TPROXY_FWMARK <= 4294967295)) || { echo "invalid TPROXY_FWMARK" >&2; exit 1; }
[[ "$TPROXY_TABLE" =~ ^[1-9][0-9]{0,8}$ ]] && ((TPROXY_TABLE != 253 && TPROXY_TABLE != 254 && TPROXY_TABLE != 255)) || { echo "TPROXY_TABLE must be a dedicated numeric table" >&2; exit 1; }
[[ "$TPROXY_RULE_PRIORITY" =~ ^[1-9][0-9]{0,4}$ ]] && ((TPROXY_RULE_PRIORITY < 32766)) || { echo "TPROXY_RULE_PRIORITY must be between 1 and 32765" >&2; exit 1; }
printf -v TPROXY_FWMARK '0x%x' "$TPROXY_FWMARK"
MARK_SPEC="$TPROXY_FWMARK/0xffffffff"

mkdir -p "$RUNTIME_DIR"
exec 9>"$RUNTIME_DIR/tproxy.lock"
flock -x 9

# Changing the reserved mark/table while active can orphan the previous rule.
# Require the normal OFF -> change config -> ON sequence for those changes.
if [[ -f "$STATE_FILE" ]]; then
  old_mark="$TPROXY_FWMARK"; old_table="$TPROXY_TABLE"
  read -r old_mark old_table < <(
    source "$STATE_FILE"
    printf '%s %s\n' "$TPROXY_FWMARK" "$TPROXY_TABLE"
  )
  if ((old_mark != TPROXY_FWMARK)) || [[ "$old_table" != "$TPROXY_TABLE" ]]; then
    echo "disable the proxy before changing TPROXY_FWMARK or TPROXY_TABLE" >&2
    exit 1
  fi
fi

# Discover complete prefixes rather than assuming a /24 site network.
LAN_CIDRS_RAW="$(ip -4 -o addr show dev "$LAN_IF" scope global | awk '{print $4}')"
if [[ -z "$LAN_CIDRS_RAW" ]]; then
  echo "no global IPv4 on LAN_IF=$LAN_IF; refusing interception until the LAN interface is ready" >&2
  exit 1
fi
LAN_CIDR_LIST="$(printf '%s\n' "$LAN_CIDRS_RAW" | awk 'NR>1{printf ", "}{printf "%s", $0}')"
SELF_ORIGIN_LIST="240.0.0.1/32"
for net in ${SELF_ORIGIN_NETS:-}; do SELF_ORIGIN_LIST+=", $net"; done

RENDER_TMP="$(mktemp "$RUNTIME_DIR/tproxy.nft.XXXXXX")"
CHECK_LOG="$(mktemp "$RUNTIME_DIR/nft-check.XXXXXX")"
STATE_TMP="$(mktemp "$RUNTIME_DIR/state.XXXXXX")"
trap 'rm -f "$RENDER_TMP" "$CHECK_LOG" "$STATE_TMP"' EXIT
cp "$TEMPLATE" "$RENDER_TMP"
esc() { printf '%s' "$1" | sed -e 's/[\\&|]/\\&/g'; }
subst() { sed -i "s|{{$1}}|$(esc "$2")|g" "$RENDER_TMP"; }
subst LAN_IF "$LAN_IF"
subst LAN_CIDR_LIST "$LAN_CIDR_LIST"
subst SELF_ORIGIN_LIST "$SELF_ORIGIN_LIST"
subst TPROXY_PORT "$TPROXY_PORT"
subst TPROXY_FWMARK "$TPROXY_FWMARK"
if grep -q '{{' "$RENDER_TMP"; then echo "unreplaced template variable" >&2; exit 1; fi
if ! nft --check -f "$RENDER_TMP" 2>"$CHECK_LOG"; then
  echo "[apply] nft validation failed; existing firewall retained:" >&2
  cat "$CHECK_LOG" >&2
  exit 1
fi

# Numeric output avoids table aliases; match ONLY our full mark/table tuple.
# Keep an already correct rule rather than briefly deleting live routing.
RULES="$(ip -4 -N rule show)"
MATCHING_PREFS="$(printf '%s\n' "$RULES" | awk -v mark="$TPROXY_FWMARK" -v spec="$MARK_SPEC" -v table="$TPROXY_TABLE" '
  { m=""; t=""; for(i=1;i<=NF;i++) { if($i=="fwmark") m=$(i+1); if($i=="lookup") t=$(i+1) }
    if((m==mark || m==spec) && t==table) { sub(/:$/, "", $1); print $1 } }')"
if printf '%s\n' "$RULES" | awk -v pref="$TPROXY_RULE_PRIORITY:" -v mark="$TPROXY_FWMARK" -v spec="$MARK_SPEC" -v table="$TPROXY_TABLE" '
  $1==pref { m=""; t=""; for(i=1;i<=NF;i++) { if($i=="fwmark") m=$(i+1); if($i=="lookup") t=$(i+1) }
    if((m!=mark && m!=spec) || t!=table) found=1 } END { exit !found }'; then
  echo "policy priority $TPROXY_RULE_PRIORITY is occupied; choose a free TPROXY_RULE_PRIORITY" >&2
  exit 1
fi

# Record ownership before route mutations so normal failure cleanup also
# removes a partially installed custom mark/table configuration.
cat > "$STATE_TMP" <<STATE
TPROXY_FWMARK="$TPROXY_FWMARK"
TPROXY_TABLE="$TPROXY_TABLE"
TPROXY_RULE_PRIORITY="$TPROXY_RULE_PRIORITY"
TPROXY_PORT="$TPROXY_PORT"
LAN_IF="$LAN_IF"
STATE
mv "$STATE_TMP" "$STATE_FILE"
ip -4 route replace local default dev lo table "$TPROXY_TABLE"
if ! printf '%s\n' "$MATCHING_PREFS" | grep -qx "$TPROXY_RULE_PRIORITY"; then
  ip -4 rule add priority "$TPROXY_RULE_PRIORITY" fwmark "$MARK_SPEC" lookup "$TPROXY_TABLE"
fi
kept=no
for pref in $MATCHING_PREFS; do
  if [[ "$pref" == "$TPROXY_RULE_PRIORITY" && "$kept" == no ]]; then kept=yes; continue; fi
  ip -4 rule del priority "$pref" fwmark "$MARK_SPEC" lookup "$TPROXY_TABLE"
done

# Forwarding is needed for bypassed LAN flows, not for sing-box's new sockets.
# Changing ip_forward from 0 to 1 may reset other IPv4 sysctls; avoid rewrites
# when it is already enabled, and inspect the final values with diagnose.sh.
if [[ "$(sysctl -n net.ipv4.ip_forward)" != 1 ]]; then
  sysctl -w net.ipv4.ip_forward=1 >/dev/null
fi
if [[ "${WG_RP_FILTER:-yes}" != no ]]; then
  for f in /proc/sys/net/ipv4/conf/wg*/rp_filter; do
    [[ -f "$f" ]] || continue
    echo 0 > "$f"
  done
fi

# add/delete/recreate are submitted together in one transaction, including
# all sets and counters. Docker tables and global policies are untouched.
nft -f "$RENDER_TMP"
mv "$RENDER_TMP" "$RENDERED"
echo "[apply] replaced inet proxy_tproxy; $MARK_SPEC -> table $TPROXY_TABLE at priority $TPROXY_RULE_PRIORITY"
