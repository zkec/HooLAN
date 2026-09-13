# Notifications, backups, speed tests and QR sharing

All backend code uses the Go standard library. `go.mod` retains zero external
requirements. The dashboard is embedded Vanilla JS/HTML/CSS. Rebuild and replace
the Go binary to deploy these features; no frontend build is needed.

## File-by-file implementation

| Files | Changes |
| --- | --- |
| `internal/api/telegram.go` | Token settings, bounded notification queue, standard HTTP Telegram sender, active-node health checks |
| `internal/api/service.go`, `service_dashboard.go` | Persist Telegram settings, start/cancel workers, lifecycle/subscription alerts and job speed results |
| `internal/api/backup.go` | ZIP snapshot, bounded upload validation, transactional live-state restore and engine reconciliation |
| `internal/netfilter/config_backup.go` | Expose the configured firewall file path; validate literal shell settings before restore |
| `internal/tester/speed.go` | Isolated sing-box SOCKS engine and a measured fixed-size download through the target and its detours |
| `internal/api/speed.go` | Asynchronous speed-test endpoint using existing jobs/status polling |
| `internal/subscription/share.go`, `parser.go` | Reconstruct current share links, preserve encoded names and VMess insecure setting |
| `internal/api/share.go` | Explicit authenticated export of one node's credential-bearing link |
| `internal/api/handlers_dashboard.go` | New API routes |
| `internal/api/static.go` | CSP permits only the pinned QR renderer URL in addition to local scripts |
| `internal/api/web/index.html`, `app.js`, `style.css`, `i18n.js` | Settings forms, backup upload/download, speed buttons/spinners/results, QR popup, theme-compatible styles and Persian copy |
| `internal/api/advanced_test.go`, `internal/tester/speed_test.go`, `internal/netfilter/config_backup_test.go`, `internal/subscription/share_test.go` | Notification, archive, rollback, speed, authentication and sharing regression checks |

All mutations require the existing session + CSRF header or bearer-token
credentials. Responses and sensitive downloads use the existing no-store policy.

## Telegram

```http
PUT /api/telegram
Content-Type: application/json

{"enabled":true,"use_proxy":true,"token":"123456:BOT_TOKEN_FROM_BOTFATHER","chat_id":"-1001234567890"}
```

Use an actual valid bot token and chat ID. Omit `token` to preserve it; an empty
string deletes it (disable notifications at the same time). `GET /api/telegram`
returns `enabled`, `use_proxy`, `chat_id`, `token_set` and `last_error`, never the token.
Omitting `use_proxy` on PUT preserves the existing choice. Its default is false.
The token lives in the existing mode-0600 state file and is included in backups.

The sender posts JSON to Telegram's
[`sendMessage` API](https://core.telegram.org/bots/api#sendmessage), with no
Markdown/HTML parsing. It blocks redirects and limits response reads/timeouts;
errors never contain the token-bearing request URL or Telegram's echoed body.
Notifications are best-effort, with a 32-message queue, a 30-second timeout (including temporary proxy startup), and
no unbounded retry loop. Failure does not stop the gateway. Normal shutdown
makes one final attempt bounded to three seconds.

Alerts cover engine enable/disable, unexpected exits and managed restarts, plus
each successfully committed subscription refresh with its resulting node count.
When Telegram is enabled and the gateway is ON, an additional five-minute health
check probes only the active node, including its chain dependencies. It skips a
busy manager and never sweeps other nodes in Manual mode. Repeated failures are
suppressed until a successful health check (or a different active node).

The bot must be permitted to post to the chosen chat. With **Send Telegram through proxy** OFF, the Pi connects directly to
api.telegram.org, ignoring HTTP_PROXY/HTTPS_PROXY environment variables. With it
ON, a temporary loopback SOCKS sing-box process uses the selected node and its
complete chain. The live engine, LAN routes and selector are not changed. In
Auto mode it uses the live automatic choice; if no live choice is available, it
uses the fastest saved healthy enabled configuration. Without a usable choice,
the notification reports an error. Proxy mode never falls back to direct.
This separate process permits stop notifications after the production engine
has stopped; shutdown's final attempt still has only three seconds. Telegram
blocking or a loss of upstream connectivity can prevent delivery, including a
stop alert. No messages are sent simply by viewing the settings page.

**Save & send test message** saves the form first, then calls
`POST /api/telegram/test` (empty JSON body, existing authentication/CSRF).
The endpoint uses saved credentials and returns a normal 202 job, kind
`telegram`, polled through `/api/status`. It works even if automatic alerts are
disabled. The UI displays progress and success/failure; the message identifies
whether it used direct or proxy. Credentials must be valid and the bot must
have access to the chat. A Telegram error or unavailable proxy reports failure
without exposing the bot token or proxy credentials.

## Backup and restore

`GET /api/backup` downloads `backup.zip` containing exactly:

- `nodes.json` — complete node inventory and saved chain copies;
- `state.json` — device mappings, aliases, usage, routing, scheduling, Telegram
  settings and ON/OFF/selection intent;
- `tproxy.conf` — the actual file used by the current firewall manager;
- `devices.json` — an explicit copy of aliases/routes, checked against state.

The snapshot excludes live sing-box configs, environment-based manager tokens,
logs, downloaded rule-set files and system-wide UFW/router installation files.
The latter remain managed by their existing installation scripts. A download
fails if the configured firewall file cannot be read or safely round-tripped.

```http
POST /api/restore
Content-Type: application/zip
X-CSRF-Token: session-csrf-token

<raw ZIP file bytes>
```

Upload raw bytes, not multipart form data. Both compressed and total expanded
sizes are limited to 32 MiB. Unknown/duplicate paths, directories/symlinks,
ZIP traversal, invalid JSON, broken ID references, conflicting device mappings
and executable shell config are rejected before any state change. Firewall
restore accepts only known literal assignments; substitutions, shell commands
and reserved routing tables are forbidden. The restored TPROXY port must match
the current engine port. Subscription entries must be HTTP(S) URLs; backups of
CLI/local-file subscriptions need those subscriptions converted before restore.

Returns 202 with `refresh` and `poll: "/api/status"`. Restore is a background job,
so disconnecting the browser does not abort a half-applied restore. It removes
interception using the OLD mark/table, stops sing-box, writes the selected files
atomically, replaces in-memory Go state and starts sing-box if the backup says
ON. An OFF backup leaves it stopped. The Go API process stays available; no
systemctl permission or API process restart is required to load the new state.

A normal write/start failure rolls back the previous inventory, state and
firewall file and attempts to restore the previous running gateway. If removing
new interception itself fails, its config is retained so OFF can retry cleanup;
the job reports that error. Individual file writes are atomic, but this is not
a multi-file transaction that survives power loss at every intermediate point.
Keep an independently downloaded backup before restoring.

Host-specific rule-set file paths and engine counter baselines are cleared on
restore. Rule-set URLs/schedules and accumulated usage remain saved. Rule sets
bootstrap/download again through the normal manager/engine mechanisms. Existing
forwarding/NAT setup is not replaced by this archive.

## Speed test

```http
POST /api/nodes/speed
Content-Type: application/json

{"node_id":"configuration-id"}
```

Returns the normal 202 background job response. Poll `/api/status`; its `refresh`
object contains `kind: "speed"`, `node_id`, state/error and, on success:

```json
{"speed":{"bytes":15000000,"seconds":2,"mbps":60,"server":"speed.cloudflare.com"}}
```

A temporary sing-box process binds SOCKS on loopback, routes exclusively to the
requested node with its complete detour path, and is killed/reaped afterward.
A standard Go `http.Transport` uses this SOCKS proxy for
`https://speed.cloudflare.com/__down?bytes=15000000`. If that fails (including
HTTP 403), it tries the independent
[NetOne random 10 MiB payload](https://speedtest.netone.nl/speedtest/) at
`https://speedtest.netone.nl/speedtest/random-10mb.bin` through the same node.
An endpoint's rejection is not treated as evidence that the node itself is
broken. If both fail, the error names both hosts and their failure reasons.
The result includes the successful server, also shown on hover over Mbps.
It never switches the live
selector or changes TPROXY rules. No protocol implementation or Go library is
added. One existing manager job runs at a time.

Startup is excluded from timing; target DNS/TLS, first-byte latency and the
successful endpoint’s payload are included. Failed attempts are excluded from Mbps timing. Compression and redirects are disabled;
non-200, truncated, oversized and failed downloads are errors. HTML/JSON/XML error pages are rejected even with HTTP 200. Each endpoint has a
40-second deadline inside the 90-second overall limit, bounded further by the
configured job timeout. Mbps is
`bytes * 8 / elapsed_seconds / 1_000_000`. This is one download's achieved
throughput, not a guarantee of line rate. A successful primary download consumes 15 MB; the fallback is 10 MiB. A click
can download up to about 26 MB of payload if both attempts transfer data. Temporary test traffic is not part of the production engine's usage
counters.

## QR code sharing

The QR button calls `POST /api/nodes/share` with `node_id`. This explicit action
returns the current link with credentials; the ordinary node list stays redacted.
The standard-library serializer supports VLESS, VMess, Trojan, Hysteria2 and plain
Shadowsocks, including supported transport/TLS settings. A saved or legacy chain
is rejected because a single mobile link cannot represent its detours.

The browser loads the pinned, standalone
[QRCode.js renderer](https://github.com/davidshimjs/qrcodejs) from
`https://cdnjs.cloudflare.com/ajax/libs/qrcodejs/1.0.0/qrcode.min.js` only when a
QR popup is opened. It renders locally to canvas; there is no QR image API and
the link is not sent to the CDN. Normal dashboard use has no CDN dependency.
This uses the CDN option requested for QR rendering; the renderer is not bundled
in the Go binary. If the renderer cannot load or the link exceeds QR capacity,
the popup still offers the text link for copying. Closing the popup clears its
link, canvas and title. Provider names/raw logs remain untranslated.
