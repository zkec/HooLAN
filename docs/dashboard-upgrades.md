# Dashboard upgrades and deployment

> Feature implementation notes. For current installation, tabs and operational
> behavior, start with [README](../README.md) ([فارسی](../README-fa.md));
> the latest device limiter is documented in [four-way QoS](load-balancing-qos.md).

All code is embedded Go plus vanilla HTML/JS/CSS. There is no frontend build
step and no additional Go module dependency.

## Files and endpoints

| Files | Change |
| --- | --- |
| `internal/api/static.go`, `auth.go`, `web/login.html`, `web/login.js` | `/login` and `/login/` serve the login page. Protected dashboard documents redirect to `/login.html` before JavaScript executes. Session cookies cover `/`; login clears the obsolete `/api/` cookie. Token validation, HttpOnly, SameSite and CSRF protection remain. |
| `scripts/tproxy/install-router.sh` | One-time persistent UFW forwarding, marked INPUT exceptions, scoped MASQUERADE and IPv4 sysctls for this single-interface gateway. `remove.sh` continues to remove only interception. |
| `internal/api/node_edit.go`, `handlers_dashboard.go`, `internal/store/db.go` | `POST /api/nodes/delete {node_id}` and `PUT /api/nodes/detour {node_id,detour_id}`. Empty detour clears a chain. Stable IDs survive renames/duplicate tags; cycles and unavailable hops are rejected. The current bulk API and Chain Builder supersede row actions; see `configuration-workflow.md`. |
| `internal/engine/rule_policy.go`, `config.go`, `singbox.go` | Validated domain, suffix and CIDR rules; editable Iran source URLs/action; additional HTTPS binary SRS sources. All downloads stage and validate through `sing-box rule-set decompile` before a generation becomes active. |
| `internal/api/rules.go`, `service.go`, `service_dashboard.go` | `GET/PUT /api/rules`, `POST /api/rules/update`; persisted scheduling, asynchronous jobs, file paths, last attempt/success/error, next due time. The service scheduler runs with the engine OFF. |
| `internal/api/usage.go`, `clash.go`, `service.go` | `GET /api/usage`; background one-second Clash `/connections` polling, cumulative upload/download, sampled attribution to node IDs and direct, counters persisted with state at most once per minute and on graceful shutdown. |
| `internal/api/web/index.html`, `app.js`, `style.css` | Configurations (bulk actions, Chain Builder, usage), Settings (DNS/rules/schedules), and Live logs. |

## Deploy on this Pi

Use the current source checkout. Build before stopping the service:

```bash
go build -trimpath -o /tmp/proxy-manager-new ./cmd/server
```

The following router installation is specifically for the supplied topology:
Pi `192.168.3.5/24`, upstream `192.168.3.1`, both through `eth0`. Review
`scripts/tproxy/install-router.sh`, then run **on the Pi**, once:

```bash
sudo env LAN_IF=eth0 LAN_CIDR=192.168.3.0/24 bash scripts/tproxy/install-router.sh
```

The script backs up `/etc/ufw/before.rules` and `/etc/ufw/sysctl.conf`, adds
managed blocks, writes `/etc/sysctl.d/90-proxy-manager-router.conf`, reloads
UFW and applies those sysctls. It does not flush Docker or the nftables ruleset.
It leaves existing rules and policies intact. It requires an already enabled
UFW installation. For a separate WAN interface, adapt the forwarding/NAT rules
instead of running the single-interface recipe unchanged.

Confirm `ip -4 route show default` points to **192.168.3.1**, never the Pi's own
address. Test a new connection with the proxy OFF before replacing the binary.
Old TCP connections through the stopped proxy cannot survive the transition.
Direct routing also cannot provide access to sites blocked by the upstream ISP.

For the README's default service path:

```bash
sudo systemctl stop proxy-manager
sudo install -m 0755 /tmp/proxy-manager-new /opt/proxy-manager/proxy-manager
sudo systemctl start proxy-manager
```

If your ExecStart uses a different path, install there. Retain all existing
service arguments. Login requires `PROXY_MANAGER_TOKEN` to be set in the service
environment. For `https://vpn.zkec.eu.cc`, retain `-secure-cookies` and preserve
the public Host at the reverse proxy. Forwarded headers are not blindly trusted.
An empty token intentionally retains the existing unauthenticated mode.

## Rule schedules and storage

Intervals: manual only (0), daily, weekly, every 30 days, or 1–365 days.
Calendar scheduling: daily/weekly at HH:MM in an explicit IANA timezone such as
`Asia/Tehran`. Timezone data is embedded for minimal Pi installations. This is
not the same as a calendar-month schedule: “every 30 days” is a fixed interval.
Jobs are checked once per minute, serialized with subscription/latency jobs,
retried no more than hourly after a failed attempt, and canceled on shutdown.
A missed scheduled run executes after restart; jobs never overlap.

A successful batch stores immutable files next to the engine config, normally:

```text
/etc/proxy-manager/singbox/rule-sets/generation-<timestamp>/<source-hash>.srs
```

The Rules tab reports exact paths and the batch's last-success timestamp. Until
an initial managed download, remote bootstrap can use sing-box's existing cache;
that is shown as not yet downloaded by the manager. Press **Update now** after
saving sources to populate the managed files. Initial bootstrap may fetch a
source once; subsequent updates are owned by the Go scheduler. Old generation
folders are retained for recovery; administrators can prune unused generations
while the engine is stopped, retaining paths referenced by the state/config.

Safety/listener rejection, sniff, DNS and private routing stay ahead of custom
rules. Custom domain/IP rules run in order, then additional rule sets in order,
then Iran matching. Local/Docker destinations exempted by nftables never reach
these rules. Rule sources must be HTTPS compiled `.srs`; arbitrary shell
commands, local file URLs and unrestricted sing-box JSON are not accepted.

Settings' Iran toggle controls whether the editable Iran rules participate.
Saving routing or chain changes briefly restarts a running engine with
interception removed before the listener stops. Download/validation failures
preserve existing files and routes. A failure applying a configuration leaves
interception off and reports an error; inspect logs before enabling again.

Deleting a manual config removes its record from `nodes.json`. If it also came
from a subscription, a future explicit subscription refresh may import it again.
New saved chains keep independent snapshots through pruning; broken legacy detours are disabled. A chain's selected config is
its exit node; its detour is the upstream hop. Manual node selection still omits
URLTest, and Bulk Ping remains available.

## Usage accuracy

The aggregate uses cumulative sing-box counters, so completed flows count even
when they disappear between polls. It measures **payload handled by sing-box**,
not the WAN interface or ISP billing. It excludes raw forwarding while OFF,
local AdGuard/Docker traffic, and proxy-protocol overhead.

Per-node and direct values are **sampled estimates**, not exact accounting.
Clash exposes current connections; short flows and the final bytes of a flow
can disappear between one-second samples. Never assume the node rows sum to the
aggregate. Chain payload is attributed once to the selected exit node. These
are not per-hop transport byte counters. Unsupported/failed Clash reads appear
as unavailable/errors, not invented measurements.

State is checkpointed at most once per minute to limit SD-card writes; abrupt
power loss can lose data since the last checkpoint/sample. Totals survive normal
service restarts and engine counter resets. The full socket-based integration
suite and real Pi network/engine validation must be run in a suitable environment.

References: [sing-box rule sets](https://sing-box.sagernet.org/configuration/rule-set/),
[Clash connection counters](https://github.com/SagerNet/sing-box/blob/testing/experimental/clashapi/connections.go).
