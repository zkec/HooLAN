# Connection distribution and device rate limits

The supplied revision (`0b8995879f29a9b98ee027bc17b75e101445b238`) is upstream
sing-box 1.14.0. Its [outbound types](https://sing-box.sagernet.org/configuration/outbound/)
do not include `loadbalance`. This implementation keeps that engine, as requested:
nftables distributes connections across separate sing-box TPROXY listeners. The
local node store calls these configurations `loadbalance`; generated sing-box
JSON contains only supported `tproxy` inbounds, `selector` groups and ordinary
node outbounds. No external Go requirements or frontend libraries were added.

## File-by-file changes

| File | Implementation |
| --- | --- |
| `internal/api/balance.go` | Create/save a group with private copies of members and chain dependencies; configure global/device firewall dispatch |
| `internal/subscription/parser.go` | Local group representation and validation |
| `internal/store/balance.go`, `db.go` | Resolve persistent member IDs to current deduplicated tags; validate uncommitted snapshots |
| `internal/engine/balance.go` | Deterministic group/member listener allocation, missing/nested-member checks and default fallback selection |
| `internal/engine/singbox.go` | Extra transparent listeners, sniffing, member routing after DNS/private/Iran/custom policy, upstream-compatible group selector |
| `internal/netfilter/balance.go` | Stable five-tuple hash and per-device/global dispatch chains |
| `internal/netfilter/qos.go` | IPv4/rate validation, explicit Mbps-to-bytes conversion, independent upload/download policing, atomic QoS table replacement |
| `internal/netfilter/tproxy.go` | Pass generated fragments to apply.sh, retain desired limits/groups, detect outdated scripts |
| `scripts/tproxy/tproxy.nft.template`, `apply.sh` | Include generated dispatch chains and QoS table in the same checked nft transaction |
| `internal/api/service.go`, `service_dashboard.go` | Persist limits, restore them while OFF, reconcile dispatch on selection/reload, check ownership of every TCP/UDP listener |
| `internal/api/devices.go`, `usage.go` | Extend device PUT and Usage response; attribute proxied distributed traffic to the visible saved group |
| `internal/api/handlers_dashboard.go`, `handlers.go` | Group creation route and member count in node rows |
| `internal/api/backup.go` | Restore group references and QoS, validate before applying; treat absent/empty alias maps equivalently |
| `internal/api/batch.go`, `edit.go`, `node_edit.go`, `speed.go`, `telegram.go` | Guard unsupported nested/edited/exported groups and isolated tests; exclude groups from automatic latency selection |
| `internal/api/web/index.html`, `app.js`, `i18n.js` | Create Load Balancer form, checkbox selection across cards, group rows, per-device rate form, English/Persian copy |

The new forms reuse existing theme-aware CSS classes (`form-card`, `form-footer`,
`device-name-form`, inputs/buttons); no separate styling framework is needed.

## Create and select a group

Select 2–32 enabled configurations across the existing cards, enter a name, and
click **Create Load Balancer**. Existing chains can be members; groups cannot be
nested. At most 16 saved groups are supported. Group creation snapshots each
member and its complete detour path. Editing, deleting or refreshing the source
configurations does not change those private copies. Delete/recreate the group
to change its members or credentials. Bulk Delete removes the group and all its
private copies and clears device assignments to it.

```http
POST /api/load-balancers
Content-Type: application/json
X-CSRF-Token: <session token>

{"name":"Home pool","node_ids":["first-node-id","second-node-id"]}
```

Returns 201 with `node_id`. Activate it with the existing node activation button,
or select it for a device in Usage. Groups appear in the Manual configurations
card. They persist in `nodes.json` with manual ownership in `state.json` and are
included in ZIP backup/restore.

Each group member gets one IPv4 TCP+UDP TPROXY listener after the main port
(default: 7893, 7894, ...). Ports are assigned by sorted group ID and member order.
Adding/removing a group can reassign ports and restarts the managed engine;
reserve this adjacent port range for proxy-manager. Readiness verifies every
listener belongs to sing-box before interception is installed. Original packet
source/destination addresses and ports remain unchanged.

After the existing LAN/local/Docker exclusions, nft dispatch checks explicit
per-device assignments first. Devices assigned Direct or an ordinary node use
the original listener; devices assigned a group enter that group's dispatcher.
Unassigned devices use the globally activated group, if any. A fixed per-group
seed hashes source IP, destination IP, protocol and both ports to a member.
Every packet of a stable flow computes the same result; there is no per-packet
round-robin or repurposing of conntrack marks. A failed member socket handoff is
dropped rather than forwarded directly. See the official
[nft expression and TPROXY reference](https://www.netfilter.org/projects/nftables/manpage.html).

In sing-box, sniffing and existing DNS/private/Iran/custom policy retain priority.
A remaining connection on a distributed listener routes through that listener's
member, including its saved detour chain. Intercepted DNS keeps its existing
global-selector rule and may use the group selector's first member. Locally
originated manager/Telegram traffic does not pass LAN prerouting; Telegram proxy
mode uses the first saved member if a group is selected.

This is connection distribution, not bandwidth bonding or health-aware failover.
One connection uses one member; multiple independent connections can use both.
A failed upstream remains in the hash pool until the group is recreated. Groups
are not included in URLTest or the active-node Telegram health probe. Test original
members individually; group Speed Test/Bulk Ping is disabled because an isolated
SOCKS probe would not measure this LAN dispatcher. Ordinary Auto selection still
uses eligible single-node configurations. If only chains/groups remain, the
first visible configuration supplies the default; a group default is dispatched
through its member listeners. Traffic counters attribute distributed proxied
bytes to the visible group, and bypassed bytes remain Direct.

## Device rate limits

Usage has a **Speed Limit (Mbps)** field and **Save limit** next to each device.
Blank or 0 clears the limit. Valid nonzero values are 0.01–10000 Mbps, with up to
256 limited private IPv4 devices. Limits apply independently in each direction,
not to their combined total. Fields omitted from a PUT retain their values.

```http
PUT /api/devices
Content-Type: application/json
X-CSRF-Token: <session token>

{"ip":"192.168.3.141","alias":"Phone","node_id":"saved-group-id","speed_limit_mbps":8}
```

`GET /api/usage` includes `device_limits` keyed by IP. Rates are saved in
`state.json` and restored from backups. A limit-only change does not restart
sing-box. Saving first persists validated state, then applies a checked atomic
nft batch; a failed apply restores previous device settings and attempts to
restore the old kernel limit.

8 Mbps means 1,000,000 **bytes/second**, not 8 MBytes/second. The generated rules
use explicit bytes, avoiding MB/MiB ambiguity. The burst allowance is roughly
100 ms of traffic, with a 1500-byte minimum.

The independent `inet proxy_qos` table uses:

- Upload: `prerouting` priority -151, matching the configured LAN interface and
  the device source IP, before TPROXY at -150.
- Download: `postrouting` priority 99, matching the LAN egress interface and
  device destination IP, covering transparent replies and forwarded traffic
  before source NAT at 100.

Private/local-service traffic is excluded, including the dashboard, AdGuard,
Docker and WireGuard private networks. Internet traffic that Iran/custom rules
route Direct is still limited. Removing interception with OFF leaves QoS and
normal forwarding/NAT intact. Clearing all limits removes only `proxy_qos`.
IPv6 is outside this gateway's existing IPv4 interception/limiting scope.

These are nft token-bucket **drop/policing** rules, as requested, not queued
traffic shaping. Expect TCP adaptation, short bursts, and potentially visible
UDP loss under a tight cap. Byte accounting includes packet headers and does
not exactly match sing-box payload usage counters.
[Official rate-limit reference](https://wiki.nftables.org/wiki-nftables/index.php/Rate_limiting_matchings).

## Deployment and verification

Deploy the rebuilt binary **and** `scripts/tproxy/apply.sh` and
`tproxy.nft.template` into the existing scripts directory. Keep the site's
`tproxy.conf`. Deploying only the binary is insufficient for distribution;
feature checks reject outdated scripts instead of silently selecting one member.
No sing-box fork, Go dependency installation, new frontend build or global
firewall-policy change is needed.

Validation in this checkout covers saved chains/members, malformed groups,
route priority, deterministic hashes, rate conversion, script transactions,
authentication/CSRF, write/apply rollback and backup restore. Network commands
in script tests are mocks. `nft` and `sing-box` are unavailable in this workspace,
so kernel parsing and real client traffic still need Pi verification.

On the Pi, activate a group and make several independent connections from a LAN
client. Inspect the `balance_g*_m*` counters using
`sudo nft list table inet proxy_tproxy`. Apply a device limit and inspect
`sudo nft list table inet proxy_qos`; compare sustained traffic in each direction
and verify OFF retains ordinary internet forwarding. A single download is not
an adequate test of distribution. The apply script runs `nft --check` before
committing generated rules, and sing-box configuration/listener errors leave
interception removed so normal router forwarding can continue.
