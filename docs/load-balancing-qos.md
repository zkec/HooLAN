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
`device-qos-card`, inputs/buttons); no separate styling framework is needed.

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

## Four-way device limits

In **Usage → LAN devices → Manage Limits**, a dialog edits the alias, outbound
assignment (Global Default, Direct, node, chain or load balancer), and a 2×2 grid
of Proxy Upload/Download and Direct Upload/Download limits. It uses the existing
dark/light theme and English/Persian RTL preferences. Polling does not replace an
open draft. Save sends one request; Cancel discards the draft.

Rates are decimal Mbps. Each field accepts 0 (unlimited) or 0.01–10000. Blank UI
fields become zero. Up to 256 private IPv4 device entries are supported. Settings
remain keyed by IP; use DHCP reservations. No MAC discovery or IPv6 limiting is
added.

```http
PUT /api/devices
Content-Type: application/json
X-CSRF-Token: <session token>

{
  "ip": "192.168.3.141",
  "alias": "Phone",
  "node_id": "direct",
  "qos": {
    "proxy_upload_mbps": 2,
    "proxy_download_mbps": 10,
    "direct_upload_mbps": 4,
    "direct_download_mbps": 20
  }
}
```

Omitted `alias`, `node_id` or `qos` leaves that part unchanged. An included `qos`
object replaces all four limits; omitted fields inside that object are zero.
`"qos": {}` clears all limits for the IP, without clearing its alias or route.
Empty `node_id` means Global Default. Negative, nonfinite, excessive and tiny
nonzero rates are rejected, as are unknown QoS property names.

`GET /api/usage` returns `device_limits` keyed by IP, whose values now contain
these four fields. `state.json` and backups use that same shape. Old scalar
entries such as `"192.168.3.141": 8` migrate to **8 in all four fields** on load;
subsequent saves write objects. The old `speed_limit_mbps` PUT field remains
supported and sets all four fields equally. Sending both it and `qos` is rejected.

A limits-only change does not restart sing-box. The service validates and saves
state, then uses `nft --check -f` followed by a single atomic `nft -f` transaction.
A failed apply restores previous settings and attempts to restore the old kernel
table. Route changes still use the existing engine restart path. Proxy OFF
retains the independent `inet proxy_qos` table and ordinary forwarding/NAT.
Clearing all device limits removes only the QoS table.

### Packet classification and enforcement

- Upload: `prerouting` at **-149**, immediately after TPROXY at -150 and before
  delivery to userspace or Docker DNAT. Match the LAN interface and device
  `ip saddr`. The actual configured `TPROXY_FWMARK` is read from `tproxy.conf`.
- Download: `postrouting` at **99**, before SNAT. Match LAN egress and device
  `ip daddr`. Forwarded packets (`iif != 0`) take Direct. Local transparent
  replies have no ingress interface and use the reversed connection tuple.
- Two IP-to-verdict maps select a device chain without scanning all devices.
  Each device has exactly four shared token buckets. No policy-routing or
  conntrack marks are overwritten. Ordinary forwarded packets use Direct
  immediately, even if a previously observed tuple appears in a flow set.
- Routed private/LAN traffic is now included in Direct. Traffic switched within
  the LAN without crossing the Pi cannot be limited here. Access to the Pi's
  own services (including published ports before DNAT) and locally sourced
  service replies are exempt. Docker traffic to private *container* IPs that
  actually crosses the Pi is treated as forwarded Direct traffic.

**TPROXY mark 0x1 is not an outbound class.** Iran/custom Direct decisions happen
inside sing-box after interception. `usage.go` reads the existing one-second
Clash `/connections` snapshots, matches the actual leaf in `chains`, and exports
the original source/destination IP, protocol and ports into separate expiring
Proxy/Direct nft sets. This also works for chains and distributed TPROXY
listeners; a device's configured default is never used to guess its actual
route. Snapshots replace only set elements in one transaction, preserving the
rate buckets. Set lookups work in both directions without changing conntrack.

**Classification is sampled, not exact from the first packet.** Before a valid
observation, an intercepted flow uses the **stricter nonzero cap for that
direction**, sharing that class's existing bucket. If both are zero it is
unlimited. Thus a class configured as unlimited can temporarily be restricted
before classification when the other class has a cap. Short flows may remain
conservatively limited throughout. This avoids giving unobserved connections a
free unlimited path, but cannot guarantee exact separate accounting from the
first packet with upstream Clash snapshots.

Observations expire after 3 seconds, are removed on subsequent samples when
closed, and are capped at 8192 entries per snapshot. Missing/malformed tuple
metadata or unknown outbound leaves stay unclassified. Conflicting tuple
observations also stay unclassified. A failed/oversized snapshot or nft update
lets old observations expire; conservative limits then apply. A reused tuple
can briefly inherit its previous class until the next snapshot/expiry. The
Usage view indicates sampler/update failures; details are in
`usage.qos_error` from `/api/usage`. A busy lifecycle/background operation can
delay sampling and cause the same conservative behavior.

These are token-bucket **packet-drop policers**, not queued traffic shapers.
8 Mbps is 1,000,000 bytes/second. The generated extra burst is 10% of that rate,
with a 1500-byte minimum; nft byte-limit buckets also include the rate's byte
value, so short bursts can exceed the nominal Mbps. Counts include IP packet
headers and differ from sing-box's payload statistics. UDP can lose packets;
TCP generally adapts to drops. Firewall flow offload must not bypass these
hooks for limited devices.

References: [nftables limits, hooks, sets and verdict maps](https://netfilter.org/projects/nftables/manpage.html),
[upstream Clash connection metadata and leaf ordering](https://github.com/SagerNet/sing-box/blob/master/experimental/clashapi/trafficontrol/tracker.go).

### Changed files for granular QoS

| File | Change |
| --- | --- |
| `internal/netfilter/qos.go` | Four-field schema, legacy JSON migration, validation, verdict maps and four buckets, checked atomic replacement |
| `internal/netfilter/qos_flows.go` | Validated, bounded, expiring five-tuple sets; atomic sample updates without resetting buckets |
| `internal/netfilter/tproxy.go` | Retain typed limits and reset classification cache on table replacement |
| `internal/netfilter/balance.go` | Reuse typed device-address validation for distribution rules |
| `scripts/tproxy/tproxy.nft.template` | Document hook ordering and insert generated standalone QoS table alongside interception |
| `internal/api/service.go` | Persist the new `device_limits` shape in `State` |
| `internal/api/devices.go` | Extend existing authenticated PUT handler; combined validation, persistence, apply and rollback |
| `internal/api/usage.go` | Read full Clash tuple metadata, classify actual outbounds, synchronize sets, expose QoS errors |
| `internal/api/web/index.html` | Accessible device dialog, 2×2 limits grid and status/error elements |
| `internal/api/web/app.js` | Manage Limits buttons, grouped route choices, one-request save and draft preservation |
| `internal/api/web/style.css` | Responsive dialog/grid using existing theme tokens and RTL logical spacing |
| `internal/api/web/i18n.js` | Persian translations for new labels and explanations |

The existing `PUT /api/devices` registration in `handlers_dashboard.go` remains
valid; no additional route is needed. Backup/restore already validates, saves
and applies `State.DeviceLimits`, so it uses the migration and new fields too.

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


For development validation, run `go test -race ./...` and `go vet ./...`.
`PROXY_MANAGER_TEST_NFT_NAMESPACE=1 go test ./internal/netfilter -run TestQoSIsolatedNamespace -v`
validates the rendered maps, sets, four buckets, repeated atomic updates and
clearing against the kernel inside a new user/network namespace. It never
changes the host firewall. If the development kernel lacks `nft_fib`, the test
explicitly reports that and omits only the two service-exemption guards in its
temporary fixture. The shipped rules retain those guards; the Pi already needs
`nft_fib` for the existing TPROXY template.

On the Pi, verify all four limits with sustained transfers to one proxy-routed
and one bypassed destination, separately uploading and downloading. After at
least one second, `sudo nft list table inet proxy_qos` should show the matching
original tuple in `proxy_flows` or `direct_flows`. Each bucket's `qos-...` counter
counts **dropped** packets; `qos-unclassified-...` counts fallback packets. Repeat
the direct tests with the engine OFF. A blank/unlimited field should stop drops
in that class once classified; the conservative fallback caveat still applies.
