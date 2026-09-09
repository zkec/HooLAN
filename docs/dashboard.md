# Dashboard and API

The dashboard is compiled into the Go binary. All HTML, CSS and vanilla JavaScript
are local; it needs no CDN or frontend build step. Build with `go build ./cmd/server`.
The default generated configuration targets sing-box 1.14.

Manual selection removes the background URLTest group. Switching between Auto
and manual briefly restarts sing-box with interception removed during restart;
switching between manual nodes only updates the selector. Subscription refresh
skips its automatic latency sweep in manual mode. Explicit single-node and
subscription test buttons remain available in either mode.

## Browser access

Set `PROXY_MANAGER_TOKEN` in the service environment. Open the dashboard and sign
in with that token. The browser receives an opaque HttpOnly, SameSite=Strict
cookie, expiring after 12 hours. Sessions are kept in memory; a service restart
requires signing in again. The token is never saved in browser local/session
storage. Login is rate limited. Mutations require a per-session CSRF token and
same-origin requests. Existing bearer-token API clients continue to work.

For remote access, use the existing HTTPS reverse proxy, preserve the public
`Host` header, and add `-secure-cookies` to the Go service command. This explicitly
marks cookies Secure when TLS terminates at the proxy. Do not enable that flag
when intentionally accessing the site over plain HTTP. HTTP does not encrypt
the login token or session in transit. Forwarded headers are not automatically
trusted. With no configured token, the existing unauthenticated mode remains.

## Controls

- **Subscriptions:** save a name and HTTP(S) URL, refresh one source or all
  sources, and ping all configurations belonging to one source. Browser-added
  sources coexist with `-sub`/`PROXY_MANAGER_SUBS` sources. File sources remain
  available only through administrator configuration, not the browser API.
- **Manual Configs:** add one supported node URI, test its latency, and activate
  it. A node can also belong to subscriptions without being duplicated.
- **Latency:** “Ping” measures an HTTP request through the actual proxy node,
  not ICMP. Jobs are asynchronous and bounded by the existing probe concurrency
  and refresh timeout. Single-node tests retain detour dependencies without
  testing unrelated nodes. One refresh or latency job runs at a time.
- **Settings:** choose an engine DNS resolver (IP or IP:port; IPv6 ports use
  `[address]:port`), or leave it blank for the system resolver. Toggle Iran
  bypass on/off. The resolver remains available with Iran bypass disabled.
  This controls the engine's resolution of outbound server names; intercepted
  client DNS still goes through the selected outbound to its original resolver,
  and local AdGuard traffic still bypasses interception.
- **Live logs:** On opens an authenticated SSE connection; Off closes it while
  preserving visible lines. Go and sing-box logs share the feed. The browser
  holds at most 500 lines; the server retains 512 entries, limits subscribers,
  redacts recognized credentials, replays recent entries on reconnect and drops
  slow subscribers instead of blocking proxy processes. This is an in-process
  feed, not historical journald access.

Subscriptions, source membership, manual-node identities, DNS and Iran settings
are persisted in the existing `-state` file (0600). Credentials remain in the
node store (0600). Refresh with pruning preserves manually added nodes and other
sources. A partial source-fetch failure skips pruning.

Adding a node or saving changed settings while the engine runs reloads it.
Interception is removed before the restart and restored only after both IPv4
TCP/UDP listeners are owned by the new engine PID. Existing connections can
disconnect during this transition. Failed reloads leave interception off;
failed settings are rolled back. Adding a subscription alone does not fetch it;
use its Refresh button.

## Routes

JSON responses and errors use `Cache-Control: no-store`. GET `/api/auth/session`
returns `{authenticated, auth_required, csrf_token}`; browser mutations send
`X-CSRF-Token` plus the session cookie. Bearer clients do not need a CSRF token.

| Method | Route | Request / response |
| --- | --- | --- |
| POST | `/api/auth/login` | `{token}` → session metadata and cookie |
| GET | `/api/auth/session` | Session metadata; unauthenticated discovery allowed |
| POST | `/api/auth/logout` | Revokes the session and its open streams |
| GET | `/api/subscriptions` | `{subscriptions: [{id,name,url,node_count}]}` |
| POST | `/api/subscriptions` | `{name?,url}` → saved subscription |
| POST | `/api/subscriptions/refresh` | `{subscription_id}` → 202 background job |
| POST | `/api/subscriptions/test` | `{subscription_id}` → 202 latency job |
| GET | `/api/nodes` | Existing response plus `manual` and `subscription_ids` |
| POST | `/api/nodes` | `{link}` → `{node_id,message}` |
| POST | `/api/nodes/test` | `{node_id}` → 202 latency job |
| GET | `/api/settings` | `{dns_server,iran_bypass}` |
| PUT | `/api/settings` | One or both settings → saved settings |
| GET | `/api/logs` | SSE event `log`: `{id,time,level,source,message}` |

Existing toggle, selection, refresh-all, status and health endpoints remain.
Poll `/api/status` → `refresh` for jobs; `kind` is `refresh` or `latency` and
`state` is `running`, `succeeded` or `failed`. Probe failures are recorded on
nodes and reflected in `reachable`; a completed sweep can have zero successes.

SSE accepts `Last-Event-ID`, sends 15-second heartbeats and disables the ordinary
HTTP write deadline only for streaming responses, with bounded individual writes.
Set `proxy_buffering off` and a suitable `proxy_read_timeout` on the HTTPS proxy
if needed; the server also sends `X-Accel-Buffering: no`. Closing sessions and
service shutdown release SSE handlers.

## Implementation map

| Files | Responsibility |
| --- | --- |
| `internal/api/handlers.go`, `handlers_dashboard.go` | Routes, request validation, status codes, node provenance |
| `internal/api/service.go`, `service_dashboard.go` | Persisted subscriptions/settings, async jobs, safe engine/firewall transitions |
| `internal/api/auth.go`, `logs.go` | Browser sessions, CSRF, authenticated SSE |
| `internal/api/readiness.go` | IPv4 TCP+UDP listener ownership checks using `/proc`, without dialing |
| `internal/logstream/`, `cmd/server/main.go` | Bounded log feed and slog/journald integration |
| `internal/engine/settings.go`, `singbox.go` | DNS rendering, dynamic Iran bypass, IPv4 inbound |
| `internal/tester/latency.go` | Selective latency tests with complete detour context |
| `internal/api/web/` | Login, tabs, forms, polling, log pause/resume, responsive local CSS |

Run `go test ./...`, `go test -race ./...`, and `go vet ./...`. Tests requiring a
real sing-box binary skip unless it is installed or `SINGBOX_BIN` is supplied.
Firewall script tests use isolated command mocks; real packet delivery must be
verified on the Pi using [the network guide](network-diagnostics.md).
