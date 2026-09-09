# proxy-manager

A transparent proxy gateway for a home LAN. It runs on a Raspberry Pi, intercepts
outbound traffic from every client on the network with nftables TPROXY, and
forwards it through sing-box — without installing or configuring anything on the
clients themselves.

Point your router's DHCP at the Pi and the whole LAN is proxied. Phones, TVs,
consoles, guests: anything that takes a DHCP lease.

- **No client config.** No per-device apps, no proxy settings, no root.
- **No Docker for the gateway.** A single static Go binary plus a systemd unit.
  Your existing Docker stack (AdGuard Home, Nginx Proxy Manager, Jellyfin) keeps
  working untouched.
- **No third-party Go dependencies.** `go.mod` has an empty require block. All
  netfilter work lives in auditable shell scripts under [scripts/tproxy/](scripts/tproxy/).
- **Fails open, not closed.** Every failure path removes the ruleset before it
  gives up, because a loaded ruleset with no engine behind it blackholes the LAN.

---

## Contents

- [How it works](#how-it-works)
- [Requirements](#requirements)
- [Setup](#setup)
  - [1. Enable IP forwarding](#1-enable-ip-forwarding)
  - [2. Install sing-box](#2-install-sing-box)
  - [3. Build the binary](#3-build-the-binary)
  - [4. Install files](#4-install-files)
  - [5. Configure the interception](#5-configure-the-interception)
  - [6. Install the systemd unit](#6-install-the-systemd-unit)
  - [7. Add a subscription and start](#7-add-a-subscription-and-start)
  - [8. Point the LAN at the Pi](#8-point-the-lan-at-the-pi)
- [Docker coexistence](#docker-coexistence)
- [Configuration reference](#configuration-reference)
- [API](#api)
- [Troubleshooting](#troubleshooting)
- [Development](#development)

---

## How it works

```
LAN client                Raspberry Pi                          Internet
──────────               ──────────────────────────────         ────────
                         ┌────────────────────────────┐
 192.168.3.x ─── eth0 ──▶│ nftables prerouting (-150) │
 default gw = Pi         │   bypass local / RFC1918   │──────▶ direct
                         │   else: mark 0x1 + tproxy  │
                         └─────────────┬──────────────┘
                                       │ ip rule fwmark 0x1 → table 100
                                       │ ip route local default dev lo
                                       ▼
                         ┌────────────────────────────┐
                         │ sing-box tproxy in :7892   │──────▶ proxy node
                         │   sniff → route → outbound │
                         └────────────────────────────┘
                                       ▲
                         ┌─────────────┴──────────────┐
                         │ proxy-manager (Go, :8080)  │
                         │   renders config.json      │
                         │   supervises sing-box      │
                         │   loads/unloads nftables   │
                         └────────────────────────────┘
```

The Go service owns the lifecycle. It renders `config.json` from your
subscription, starts sing-box, waits for the TPROXY port to reach `LISTEN`, and
only then loads the nftables ruleset. On the way down it does the reverse. That
ordering is the whole ballgame — rules loaded with nothing listening on 7892
means every LAN connection hangs.

The ruleset hooks `prerouting` at priority `mangle` (-150), which is **before**
Docker's DNAT chains at -100. That ordering is what makes the
`fib daddr type local` bypass work: at -150 the destination address is still the
original one, so traffic aimed at any port published by any container is
recognised as local and left alone.

### Interception policy

Bypassed (never proxied):

| Match | Why |
| --- | --- |
| `iifname lo, docker0, br-*, veth*` | Container and loopback traffic |
| `fib daddr type local` | **Every** port bound on this host, present and future |
| `ip daddr @lan_cidrs` | Same-subnet traffic never leaves the LAN |
| `ip daddr @bypass_daddrs` | RFC1918, CGNAT, multicast, link-local |

On `LAN_IF`, remaining IPv4 TCP and UDP packets are assigned to TPROXY and
then marked. This includes established client packets. Named counters record
attempts, successful socket assignments, failures, and marked INPUT/OUTPUT.
Failed socket lookups fall back to ordinary forwarding without adding our mark.

IPv4 only, deliberately. Clients should get **no** IPv6 connectivity while this
gateway is active, or they will route around sing-box entirely. Disable IPv6 RA
and DHCPv6 on your router.

---

## Requirements

- Raspberry Pi running Raspberry Pi OS or Debian (arm64 or armhf), wired via
  Ethernet. Wi-Fi works but is a bad idea for a gateway.
- A **static IP** on the Pi, with its own default gateway hardcoded to the
  router. If the Pi takes its gateway from DHCP and DHCP points at the Pi, you
  get a routing loop on boot.
- `nftables`, `iproute2`, `bash`, and Go 1.21+ (or build elsewhere and copy).
- `sing-box` 1.14 or newer. The default generated config uses typed DNS
  servers and `http_client` settings for rule-set downloads (tested against 1.14).
- Root, for `CAP_NET_ADMIN`.
- A proxy subscription URL, or a file of `vless://` / `vmess://` / `trojan://`
  / `ss://` / `hysteria2://` links.

This README assumes the topology the project was built against. Substitute your
own addresses throughout:

| Thing | Value |
| --- | --- |
| LAN | `192.168.3.0/24` |
| Router | `192.168.3.1` |
| Pi | `192.168.3.5`, static |
| LAN interface | `eth0` |
| TPROXY port | `7892` |
| API / dashboard | `:8080` |

---

## Setup

### 1. Enable IP forwarding

`apply.sh` sets this at runtime, but it must survive reboots:

```bash
echo 'net.ipv4.ip_forward=1' | sudo tee /etc/sysctl.d/99-gateway.conf
sudo sysctl --system
```

Confirm the Pi's own default route points at the **router**, not at itself:

```bash
ip route show default    # expect: default via 192.168.3.1 dev eth0
```

If that says anything else, fix it before continuing. A Pi that is its own
gateway cannot reach the internet, and no amount of correct nftables will save
it.

### 2. Install sing-box

Use the official repo so you get 1.14+; the Debian archive version is usually
too old.

```bash
sudo mkdir -p /etc/apt/keyrings
curl -fsSL https://sing-box.app/gpg.key | sudo gpg --dearmor -o /etc/apt/keyrings/sagernet.asc
sudo chmod a+r /etc/apt/keyrings/sagernet.asc
echo 'deb [signed-by=/etc/apt/keyrings/sagernet.asc] https://deb.sagernet.org/ * *' \
  | sudo tee /etc/apt/sources.list.d/sagernet.list
sudo apt update && sudo apt install -y sing-box nftables
sing-box version
```

Disable its own unit. proxy-manager supervises the process itself, and two
instances fighting over port 7892 is a confusing failure:

```bash
sudo systemctl disable --now sing-box 2>/dev/null || true
```

### 3. Build the binary

On the Pi:

```bash
cd /home/hooman/Documents/proxy-manager
go build -trimpath -ldflags='-s -w' -o proxy-manager ./cmd/server
```

Cross-compiling from a workstation (no cgo, so this is clean):

```bash
GOOS=linux GOARCH=arm64 CGO_ENABLED=0 \
  go build -trimpath -ldflags='-s -w' -o proxy-manager ./cmd/server
# 32-bit userland: GOARCH=arm GOARM=7
```

Verify the toolchain and tests first if you're building on the Pi:

```bash
go vet ./... && go test ./...
```

### 4. Install files

```bash
# Binary and scripts
sudo install -Dm755 proxy-manager /opt/proxy-manager/proxy-manager
sudo install -Dm755 scripts/tproxy/apply.sh   /opt/proxy-manager/scripts/tproxy/apply.sh
sudo install -Dm755 scripts/tproxy/remove.sh  /opt/proxy-manager/scripts/tproxy/remove.sh
sudo install -Dm755 scripts/tproxy/diagnose.sh /opt/proxy-manager/scripts/tproxy/diagnose.sh
sudo install -Dm644 scripts/tproxy/tproxy.nft.template \
                                              /opt/proxy-manager/scripts/tproxy/tproxy.nft.template

# Config and state
sudo install -Dm644 scripts/tproxy/tproxy.conf /opt/proxy-manager/scripts/tproxy/tproxy.conf
sudo mkdir -p /etc/proxy-manager/singbox /var/lib/proxy-manager
sudo chmod 700 /var/lib/proxy-manager
```

`/opt/proxy-manager/scripts/tproxy` is one of the paths the binary probes by
default, so `-scripts` can be omitted if you use it.

The store at `/var/lib/proxy-manager/nodes.json` holds proxy credentials and is
written `0600`. Keep the parent directory `0700`.

### 5. Configure the interception

Edit `/opt/proxy-manager/scripts/tproxy/tproxy.conf`. One `KEY="value"` per
line, and **no inline comments after a value** — the file is sourced by bash and
scraped for template substitution.

```bash
LAN_IF="eth0"            # interface facing your clients
TPROXY_PORT="7892"       # must equal -tproxy-port
TPROXY_FWMARK="0x1"      # mark proving we intercepted the packet
TPROXY_TABLE="100"       # dedicated policy routing table
TPROXY_RULE_PRIORITY="10000" # free priority before main-table lookup
PI_LAN_IP="192.168.3.5"  # site reference; LAN_IF must have a live IPv4 address
SELF_ORIGIN_NETS=""      # extra source prefixes to never intercept
WG_RP_FILTER="yes"       # zero rp_filter on wg* interfaces
```

`TPROXY_PORT` here and `-tproxy-port` on the binary must match. The service
checks this before enabling interception and requires IPv4 TCP and UDP wildcard
listeners owned by the sing-box PID. The default listen address is `0.0.0.0`.

The LAN subnet is **discovered from the live addresses on `LAN_IF`**, not
hardcoded — a `/22` site works correctly without editing the template.

Sanity-check the ruleset before wiring up systemd:

```bash
sudo bash /opt/proxy-manager/scripts/tproxy/apply.sh
sudo nft list table inet proxy_tproxy
sudo ip rule show | grep 0x1
sudo bash /opt/proxy-manager/scripts/tproxy/remove.sh
```

`apply.sh` renders to `/run/proxy-manager/tproxy.nft` and runs `nft --check`
before touching the kernel, so a bad template leaves your networking alone.
Both scripts are idempotent.

> Do not hand-edit the loaded ruleset. `apply.sh` re-renders from
> `tproxy.nft.template` on every run and your changes will vanish. Edit the
> template.

### 6. Install the systemd unit

```bash
sudo tee /etc/systemd/system/proxy-manager.service >/dev/null <<'EOF'
[Unit]
Description=proxy-manager transparent gateway
Documentation=https://github.com/your/proxy-manager
After=network-online.target docker.service
Wants=network-online.target

[Service]
Type=exec
ExecStart=/opt/proxy-manager/proxy-manager \
  -listen 127.0.0.1:8080 \
  -scripts /opt/proxy-manager/scripts/tproxy \
  -sub https://example.com/your-subscription \
  -tproxy-port 7892 \
  -log-level info

# Root is required: nft, ip rule and ip route all need CAP_NET_ADMIN, and the
# scripts refuse to run as anyone else.
User=root

# Credentials live here rather than in the unit file, so they stay out of
# `systemctl cat` and the journal. chmod 600.
EnvironmentFile=-/etc/proxy-manager/env

Restart=on-failure
RestartSec=5s

# Teardown removes the nftables ruleset and stops sing-box. Give it room: a
# SIGKILL mid-teardown is what leaves the LAN blackholed.
TimeoutStopSec=90s
KillMode=mixed

[Install]
WantedBy=multi-user.target
EOF
```

Optional credentials file:

```bash
sudo tee /etc/proxy-manager/env >/dev/null <<'EOF'
PROXY_MANAGER_TOKEN=generate-a-long-random-string
PROXY_MANAGER_SUBS=https://example.com/your-subscription
EOF
sudo chmod 600 /etc/proxy-manager/env
```

```bash
sudo systemctl daemon-reload
sudo systemctl enable --now proxy-manager
journalctl -u proxy-manager -f
```

> **Security.** The API starts and stops interception and reads node metadata.
> Bound to `127.0.0.1:8080` as above, it is reachable only from the Pi. If you
> bind it anywhere else, set `-token` (or `PROXY_MANAGER_TOKEN`) — the service
> logs a loud warning if you expose it without one.
>
> The token gates `/api` only. The dashboard's own HTML, CSS and JS load without
> it, by necessity: a browser cannot attach an `Authorization` header to a
> document or script load. Those assets are a static shell holding no secrets,
> and every operation that touches the engine, the ruleset or node metadata sits
> behind the token. `/healthz` is also exempt, for systemd and monitoring, and
> exposes nothing. To reach the dashboard from your LAN, front it with your
> existing Nginx Proxy Manager rather than binding `0.0.0.0`.

### 7. Add a subscription and start

Open `http://127.0.0.1:8080/` on the Pi (or via an SSH tunnel:
`ssh -L 8080:127.0.0.1:8080 pi@192.168.3.5`) and use the dashboard. Or curl it:

```bash
TOKEN=your-token   # omit the -H below if you did not set a token

# Fetch the subscription, parse links, latency-test each node
curl -sX POST -H "Authorization: Bearer $TOKEN" \
  localhost:8080/api/nodes/refresh | jq

# Turn interception on
curl -sX POST -H "Authorization: Bearer $TOKEN" \
  -d '{"enabled":true}' localhost:8080/api/proxy/toggle | jq

# Confirm
curl -s -H "Authorization: Bearer $TOKEN" localhost:8080/api/status | jq
```

You want `proxy_enabled`, `engine_running` and `tproxy_rules_loaded` all `true`.
Then verify from the Pi itself — the Pi's own traffic is **not** proxied, so this
should show your real IP, while a LAN client shows the proxy's:

```bash
curl -s https://api.ipify.org        # on the Pi: your ISP address
```

The on/off state persists to `/var/lib/proxy-manager/state.json` and is restored
at startup, so interception comes back by itself after a reboot. Start with
`-no-restore` to suppress that while debugging.

### 8. Point the LAN at the Pi

Only once the above is verified. On OpenWrt, under **Network → Interfaces → LAN
→ DHCP Server → Advanced Settings**:

- **DHCP-Options**: `3,192.168.3.5` (gateway) and `6,192.168.3.5` (DNS, if
  AdGuard runs on the Pi)
- Disable **RA** and **DHCPv6** under IPv6 Settings, so clients get no IPv6 to
  leak through

Then renew a client's lease and confirm it picked up the Pi as its gateway.

Keep a way back in. If interception breaks the LAN, you need to reach the Pi
over SSH to run `remove.sh` — its own connectivity does not depend on the
ruleset, but revert the DHCP options from a device with a static config if
you're locked out.

---

## Docker coexistence

This is the constraint the ruleset is built around, and it is handled:

- The table is `inet proxy_tproxy`. It creates **no** iptables rules, touches
  **no** `DOCKER-USER` chain, and claims no chain name Docker uses. Docker's
  rules run after ours, untouched.
- `fib daddr type local` at priority -150 protects **every** published container
  port, including ones you add later — NPM on 80/443, AdGuard on 53, Jellyfin on
  8096. A port list would only cover the ports that existed when it was written.
- `bypass_daddrs` covers `172.16.0.0/12` (bridges), `10.0.0.0/8` (WireGuard
  subnets) and the rest of RFC1918.
- `remove.sh` deletes only its own table, full-mark policy rules and local default route. It
  deliberately does **not** reset `ip_forward` or `rp_filter`, since those are
  host-wide and Docker may depend on them.

Sing-box opens new outbound sockets sourced from the Pi. These use the normal
host route; no special MASQUERADE rule is needed for them. Keep sing-box's
outbound `routing_mark` at zero. The TPROXY mark is reserved for local delivery.

Bypassed traffic is different: it follows the host's forwarding rules and needs
a return route or site-specific SNAT. Docker may install forwarding drops.
Check the complete firewall before changing policies; an ACCEPT in one base
chain does not override a DROP in another. Avoid broad MASQUERADE rules as a
substitute for diagnosing the intercepted path.

Use [the packet-path diagnostic guide](docs/network-diagnostics.md) to distinguish
socket lookup, policy routing, INPUT filtering, and outbound connectivity.

---

## Configuration reference

### Flags

| Flag | Default | Purpose |
| --- | --- | --- |
| `-listen` | `:8080` | API and dashboard bind address |
| `-token` | `$PROXY_MANAGER_TOKEN` | API bearer token and browser login; empty disables auth |
| `-secure-cookies` | `false` | Require Secure session cookies behind an HTTPS reverse proxy |
| `-sub` | — | Subscription URL or file; repeatable or comma-separated |
| `-scripts` | probed | Directory with `apply.sh`, `remove.sh`, `tproxy.conf` |
| `-tproxy-port` | `7892` | Must equal `TPROXY_PORT` in `tproxy.conf` |
| `-sing-box` | `sing-box` | Binary path or name on `PATH` |
| `-config` | `/etc/proxy-manager/singbox/config.json` | Generated sing-box config |
| `-store` | `/var/lib/proxy-manager/nodes.json` | Node store (`0600`) |
| `-state` | `/var/lib/proxy-manager/state.json` | Proxy on/off and selection |
| `-cache` | `/var/lib/proxy-manager/cache.db` | sing-box cache; persists selection |
| `-clash-api` | `127.0.0.1:9090` | Clash API; required to switch nodes without a restart |
| `-clash-secret` | `$PROXY_MANAGER_CLASH_SECRET` | Clash API token |
| `-probe-url` | `http://cp.cloudflare.com/generate_204` | Latency probe target |
| `-probe-concurrency` | `4` | Parallel probes; each is its own sing-box process |
| `-refresh-timeout` | `10m` | Budget for one refresh job |
| `-log-level` | `info` | `debug` \| `info` \| `warn` \| `error` |
| `-expose-credentials` | `false` | Include UUIDs and passwords in `/api/nodes` |
| `-no-restore` | `false` | Do not re-enable the proxy at startup |

Env vars: `PROXY_MANAGER_TOKEN`, `PROXY_MANAGER_SUBS`,
`PROXY_MANAGER_CLASH_SECRET`.

### Supported protocols

`vless://` (including Reality and XTLS Vision), `vmess://`, `trojan://`, `ss://`,
`hysteria2://` / `hy2://`. Transports: `tcp`, `ws`, `grpc`, `http`. TLS and
Reality are both supported, with optional uTLS fingerprinting.
Multi-hop chaining is supported per node via a `detour` to another node's tag.

An unparseable node is skipped with a warning rather than failing the whole
subscription.

### Routing behaviour

Generated route rules, in order:

1. **Loop breaker** — rejects any connection to a local/private address on the
   TPROXY port. Without it, the `ip_is_private → direct` rule below matches
   `127.0.0.1:7892` and sing-box dials its own listener in an unbounded loop.
2. **Sniff** — extracts SNI/Host, since TPROXY hands over an IP and no domain.
   Every domain-based rule depends on this having run.
3. **DNS forwarding** — intercepted DNS goes through the proxy to the original
   resolver (`action: route`, not `hijack-dns`). DNS addressed to local AdGuard
   bypasses interception. The dashboard DNS setting changes the engine resolver
   used for outbound server names; it does not reconfigure AdGuard.
4. **Private destinations → direct.**
5. **Iran rule-sets → direct** (on by default), with optional ad/tracker
   rejection.

Auto mode includes a `urltest` group tagged `auto` and a `selector` tagged
`proxy`. Manual mode omits URLTest so other nodes are not probed in the
background. Switching modes briefly restarts the engine with interception
removed during the restart; switching between manual nodes uses the Clash API
without restarting. Subscription refresh skips automatic probes in manual
mode, while the explicit latency-test buttons remain available.

---

## API

With `-token` set, API clients use `Authorization: Bearer <token>`. The browser
logs in at `/login.html` and uses an HttpOnly session cookie plus a CSRF header
for mutations. Login/session discovery are public; privileged routes are protected.
See [dashboard routes, persistence and deployment](docs/dashboard.md) for the new
subscription, manual-config, latency, DNS, Iran bypass and SSE log controls.

| Method | Path | Body | Purpose |
| --- | --- | --- | --- |
| `GET` | `/api/status` | — | Engine, ruleset, selection, node counts |
| `GET` | `/api/nodes` | — | Node list with latency |
| `POST` | `/api/nodes/refresh` | — | Fetch subscriptions, parse, latency-test |
| `POST` | `/api/proxy/toggle` | `{"enabled":true}` | Start/stop; omit body to flip |
| `POST` | `/api/proxy/select` | `{"auto":true}` or `{"node_id":"..."}` or `{"tag":"..."}` | Choose a node |
| `GET` | `/healthz` | — | Liveness. Never authenticated |

`node_id` is stable across refreshes; `tag` is a convenience for humans and is
rejected when ambiguous.

Notable statuses: `409` toggling on with no nodes, `503` selecting a node with no
Clash API configured, `502` when the engine's control API is unreachable.

---

## Troubleshooting

**Start here.** These two commands answer most questions:

```bash
journalctl -u proxy-manager -n 100 --no-pager
curl -s localhost:8080/api/status | jq
```

### The whole LAN loses internet when I toggle on

Almost always the ruleset is loaded with nothing on 7892. Check
`tproxy_rules_loaded` against `engine_running` in `/api/status`. Immediate
recovery:

```bash
sudo bash /opt/proxy-manager/scripts/tproxy/remove.sh
```

Then confirm `TPROXY_PORT` in `tproxy.conf` equals `-tproxy-port`, and that
sing-box is actually listening:

```bash
sudo ss -lntup | grep 7892
```

### Logs spam `inbound connection to 127.0.0.1:7892`

A sing-box self-connection loop: the engine is dialing its own listener, each
connection spawning another. The giveaway is `outbound/direct[direct]` pointing
at the TPROXY port.

The firewall deliberately bypasses loopback/local traffic. Route rule 0 rejects
private destinations on the TPROXY listener port to prevent self-dialing. If you see this, confirm the reject rule is
present in the generated config:

```bash
jq '.route.rules[0]' /etc/proxy-manager/singbox/config.json
# {"ip_is_private": true, "port": [7892], "action": "reject"}
```

Also make sure nothing external is probing 7892 in a loop. Readiness is checked
by reading the engine PID’s IPv4 TCP/UDP socket tables and socket inodes, so
the health check creates no connection of its own.

### TCP connections hang or reset

Do not restore a blanket `ct state established,related accept` in prerouting:
client ACK/data packets also need transparent socket assignment and a local
route. Reloading now atomically replaces the owned table and sets, so stale
rules cannot survive an apply.

For a stall after this correction, capture the gateway **while enabled** using
[diagnose.sh](scripts/tproxy/diagnose.sh). An absent table, empty table 100 and no
7892 listeners describe an off/cleaned-up gateway, not a packet-path failure.
Follow [the counter interpretation guide](docs/network-diagnostics.md).

### A container or local service became unreachable

Verify the local bypass is in place and the table is at the right priority:

```bash
sudo nft list table inet proxy_tproxy | grep -E 'fib daddr|priority'
```

`prerouting` must be `priority mangle` (-150). At a later priority Docker's DNAT
has already rewritten the destination and `fib daddr type local` no longer
recognises it.

### Clients bypass the proxy entirely

Usually IPv6. Confirm clients have no IPv6 route, and that they actually took the
Pi as their gateway:

```bash
ip -6 addr show    # on the client
ip route get 1.1.1.1
```

### Rules survived a crash

`remove.sh` is idempotent and safe any time:

```bash
sudo bash /opt/proxy-manager/scripts/tproxy/remove.sh
sudo nft list table inet proxy_tproxy   # expect: No such file or directory
```

The service also sweeps stale rules at startup when the persisted state says the
proxy should be off.

### Counters, to see what is actually matching

```bash
sudo nft --handle list table inet proxy_tproxy
sudo conntrack -L | grep 7892     # apt install conntrack
```

---

## Development

```bash
go build ./...
go vet ./...
go test ./...
gofmt -l ./cmd ./internal    # silence means clean
```

Tests run without a sing-box binary, without root and without a live nft table:
the engine, firewall and tester are faked, and the fakes record call **order**,
because the ordering guarantees (engine up before rules load, rules down before
engine stops) are the properties most worth protecting.

Layout:

| Path | Contents |
| --- | --- |
| [cmd/server/](cmd/server/) | Flags, logging, signal handling, shutdown ordering |
| [internal/api/](internal/api/) | HTTP router, handlers, orchestration, readiness probe |
| [internal/engine/](internal/engine/) | sing-box config generation and process supervision |
| [internal/netfilter/](internal/netfilter/) | `os/exec` wrapper around the nftables scripts |
| [internal/subscription/](internal/subscription/) | Link parsing, chain validation |
| [internal/store/](internal/store/) | Node persistence |
| [internal/tester/](internal/tester/) | Latency probing |
| [scripts/tproxy/](scripts/tproxy/) | `apply.sh`, `remove.sh`, config, nft template |
| [internal/api/web/](internal/api/web/) | Embedded dashboard |

Some tests encode a bug that cost real debugging time. `TestLoopBreakerIsFirstRule`
pins the self-connection fix; the `/proc/net/tcp` parser tests bind a real socket
rather than trusting a fixture. If you touch route rule ordering or the readiness
probe, run the engine and api suites and read the comments before assuming a
failure is the test's fault.
