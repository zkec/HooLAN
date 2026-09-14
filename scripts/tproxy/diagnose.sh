#!/usr/bin/env bash
# Read-only snapshot. Does not probe the transparent port, start captures,
# change firewall/sysctls, print engine config, or read service environments.
set -uo pipefail
SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
CONF_FILE="${CONF_FILE:-$SCRIPT_DIR/tproxy.conf}"

# Read only known literal values; never execute/source a config in diagnostics.
if [[ -r "$CONF_FILE" ]]; then
  while IFS= read -r line; do
    if [[ "$line" =~ ^(LAN_IF|TPROXY_PORT|TPROXY_FWMARK|TPROXY_TABLE|TPROXY_RULE_PRIORITY)=(.*)$ ]]; then
      key="${BASH_REMATCH[1]}"; value="${BASH_REMATCH[2]}"
      value="${value%\"}"; value="${value#\"}"
      value="${value%\'}"; value="${value#\'}"
      [[ -v "$key" ]] || printf -v "$key" '%s' "$value"
    fi
  done < "$CONF_FILE"
fi
LAN_IF="${LAN_IF:-eth0}"
TPROXY_PORT="${TPROXY_PORT:-7892}"
TPROXY_FWMARK="${TPROXY_FWMARK:-0x1}"
TPROXY_TABLE="${TPROXY_TABLE:-100}"
CLIENT_IP="${1:-${CLIENT_IP:-}}"
TARGET_IP="${2:-${TARGET_IP:-1.1.1.1}}"
NODE_IP="${3:-${NODE_IP:-}}"

ipv4() {
  local part; local -a parts
  [[ "$1" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]] || return 1
  IFS=. read -r -a parts <<< "$1"
  for part in "${parts[@]}"; do [[ ${#part} -le 3 ]] && ((10#$part <= 255)) || return 1; done
}
if [[ "$CLIENT_IP" == --help || "$CLIENT_IP" == -h ]]; then
  echo "Usage: sudo bash $0 CLIENT_IPV4 [PUBLIC_TARGET_IPV4] [PROXY_NODE_IPV4]"
  echo "Optional env: CONF_FILE, LAN_IF, TPROXY_PORT, TPROXY_FWMARK, TPROXY_TABLE"
  exit 0
fi
[[ -z "$CLIENT_IP" ]] || ipv4 "$CLIENT_IP" || { echo "invalid client IPv4" >&2; exit 2; }
ipv4 "$TARGET_IP" || { echo "target must be an IPv4 literal" >&2; exit 2; }
[[ -z "$NODE_IP" ]] || ipv4 "$NODE_IP" || { echo "node must be an IPv4 literal" >&2; exit 2; }
[[ "$LAN_IF" =~ ^[a-zA-Z0-9_.:-]{1,15}$ && "$TPROXY_PORT" =~ ^[1-9][0-9]{0,4}$ && "$TPROXY_FWMARK" =~ ^(0x[0-9a-fA-F]{1,8}|[1-9][0-9]{0,9})$ && "$TPROXY_TABLE" =~ ^[1-9][0-9]{0,8}$ ]] || { echo "invalid literal network config" >&2; exit 2; }

run() {
  printf '\n$'; printf ' %q' "$@"; printf '\n'
  if command -v "$1" >/dev/null 2>&1; then "$@" 2>&1 || echo "(unavailable or command failed; continuing)"
  else echo "(command not installed)"; fi
}
echo "TPROXY read-only snapshot: LAN_IF=$LAN_IF port=$TPROXY_PORT mark=$TPROXY_FWMARK table=$TPROXY_TABLE"
echo "Counters accumulate since the last apply; compare two snapshots around ONE new client request."
run uname -r
run nft --version
run ip -Version
run sing-box version
run ip -br -4 addr
run ip -4 -N rule show
run ip -4 route show table "$TPROXY_TABLE"
run ip -4 route show table main
run ip -4 route get "$TARGET_IP" mark 0
if [[ -n "$NODE_IP" ]]; then run ip -4 route get "$NODE_IP" mark 0; fi
if [[ -n "$CLIENT_IP" ]]; then
  run ip -4 route get "$TARGET_IP" from "$CLIENT_IP" iif "$LAN_IF" mark "$TPROXY_FWMARK"
  run ip -4 route get "$CLIENT_IP" mark 0
  run ip -4 route get "$CLIENT_IP" mark "$TPROXY_FWMARK"
fi
run ss -H -4 -lntup "sport = :$TPROXY_PORT"
run ss -H -6 -lntup "sport = :$TPROXY_PORT"
run sysctl net.ipv4.ip_forward net.ipv4.tcp_fwmark_accept net.ipv4.fwmark_reflect net.ipv6.bindv6only
for iface in all default "$LAN_IF"; do
  run sysctl "net.ipv4.conf.$iface.rp_filter" "net.ipv4.conf.$iface.src_valid_mark" "net.ipv4.conf.$iface.accept_local" "net.ipv4.conf.$iface.send_redirects"
done
run nft -a list table inet proxy_tproxy
# All base chains matter: accept in one chain does not overrule a later drop.
run nft -a list ruleset
run iptables --version
run iptables -S INPUT
run iptables -S FORWARD
run iptables -t mangle -S
run iptables -t nat -S
run nstat -az IpInDiscards IpOutNoRoutes TcpExtIPReversePathFilter TcpExtListenDrops
run systemctl show hoolan.service --property=MainPID --property=ActiveState --property=SubState --property=ExecMainStatus

printf '\nInterpretation:\n'
cat <<'GUIDE'
* lan_packets unchanged: traffic is not arriving on LAN_IF (or it is IPv6).
* tproxy_attempt_* rises but tproxy_assigned_* does not: transparent socket
  lookup failed. Check IPv4 wildcard TCP AND UDP, port agreement, and engine PID.
* tproxy_assigned_* rises but marked_input does not: inspect policy-rule order,
  mark rewrites/DNAT in later PREROUTING chains, and effective rp_filter values.
* marked_input rises: local routing reached INPUT; inspect every INPUT chain,
  then sing-box inbound/outbound logs and the selected node's actual host route.
* marked_output rises: check tcp_fwmark_accept and outbound routing_mark.
  Reusing the interception mark for replies/egress sends them to the local table.
* INPUT/FORWARD default ACCEPT does not remove explicit drops in other chains.
* Normal sing-box egress uses a new Pi-sourced socket. General forwarding NAT
  matters for bypassed traffic, not this local socket's path.
GUIDE
if [[ -n "$CLIENT_IP" ]]; then
  printf '\nOptional capture (run separately during a new client request):\n'
  printf 'sudo tcpdump -ni %q -s 96 -c 60 %q\n' "$LAN_IF" "host $CLIENT_IP and host $TARGET_IP and (tcp or udp)"
fi
if [[ -n "$NODE_IP" ]]; then
  printf 'sudo tcpdump -ni any -s 96 -c 60 %q\n' "host $NODE_IP and (tcp or udp)"
fi
echo "TPROXY preserves the ORIGINAL destination address/port. Capturing port 7892 or only lo can miss the handoff."
echo "A gateway-host curl bypasses LAN interception; generate the test on the actual LAN client."
