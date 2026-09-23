# HooLAN API

[Home](../README.md) · [Documentation](../README.md#documentation)

The dashboard and HTTP API are served by the same binary. Use
`Authorization: Bearer <HOOLAN_TOKEN>` for automation. Browser sessions use an
HttpOnly cookie plus `X-CSRF-Token` on mutations. State-changing browser requests
must match the public origin. `/healthz` is public liveness, not a routing test.

## Routes

| Method and path | Purpose |
| --- | --- |
| `GET /api/status`, `GET /api/nodes` | Engine, job, selection and inventory |
| `POST /api/proxy/toggle`, `POST /api/proxy/select` | Engine control and selection |
| `POST /api/nodes`, `PUT /api/nodes/edit` | Add link, edit manual endpoint |
| `GET/POST /api/subscriptions`, `POST /api/subscriptions/refresh` | Sources and refresh |
| `POST /api/nodes/test`, `POST /api/nodes/delete` | Batch `node_ids` actions |
| `GET/POST/PUT /api/chains` | Ordered chain read/create/edit |
| `POST /api/load-balancers` | Snapshot a group and its strategy |
| `GET /api/usage`, `PUT /api/devices` | Usage, device alias/route/limits |
| `GET/PUT /api/settings` | Tunneled DoH, Direct DNS, listener, FakeDNS and Iran preset |
| `GET/PUT /api/rules`, `POST /api/rules/update` | Rule policy and schedules |
| `GET /api/logs` | SSE logs, Last-Event-ID replay |
| `GET/PUT /api/telegram`, `POST /api/telegram/test` | Notifications and delivery tests |
| `GET /api/backup`, `POST /api/restore` | Download/upload ZIP |
| `POST /api/nodes/speed`, `POST /api/nodes/share` | Throughput job and explicit share link |

## Request examples

Set `HOOLAN_TOKEN` in your shell before using these examples.

```bash
curl --fail-with-body -H "Authorization: Bearer $HOOLAN_TOKEN" \
  http://127.0.0.1:8080/api/status
```

Device update (`node_id: ""` means Global Default):

```json
{
  "ip": "192.168.x.x",
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

Send that object with `PUT /api/devices`. Omitted top-level fields are preserved;
an included `qos` replaces all limits. Group creation uses:

```json
{"name":"Fast routes","node_ids":["NODE_A_ID","NODE_B_ID"],"strategy":"latency"}
```

`strategy` accepts `hash` or `latency`; omission means `hash`. Chain creation uses
`name` and ordered `node_ids`; editing also includes the chain's `node_id`.

Telegram settings include `enabled`, `use_proxy`, `node_id`, `chat_id` and an
optional `token`. Omit token to preserve it; empty token removes it. Omitted
node_id preserves the pin; empty node_id selects Global Default. GET returns
`token_set` rather than the token.

## Jobs and errors

Refresh, latency, speed, Telegram test and restore operations use background jobs.
A successful start returns HTTP 202 and job state; poll `/api/status` for progress
and completion. HTTP 409 generally means a conflicting operation is running.
HTTP 400 indicates invalid input, and 401/403 indicate authentication or browser
request checks. An external service rejection inside a job is reported in that
job's error rather than as a browser-origin decision.

The route handlers in `internal/api/handlers.go` and `handlers_dashboard.go`
define the complete interface. Sensitive endpoints use no-store responses.

## Split DNS and FakeDNS settings

`PUT /api/settings` accepts partial updates:

```json
{
  "tunneled_doh":"https://1.1.1.1/dns-query",
  "direct_dns":"192.168.3.1",
  "fake_dns":{"enabled":false,"listen":"192.168.3.5"}
}
```

Use a private IPv4 address actually assigned to the Debian host. A missing/blank
listen address defaults to `127.0.0.1`; TCP/UDP port is 1053. Omitted top-level
settings retain their previous values, so changing `iran_bypass` does not reset
FakeDNS. A supplied `fake_dns` object replaces that object. `GET /api/settings`
returns the normalized object. Values persist in `state.json` and backups.
Changes restart a running engine using the existing firewall teardown/readiness
sequence. Invalid values are rejected; apply failures restore the old settings.
The listener runs even with FakeDNS disabled. The legacy `dns_server` field is
accepted as a Direct DNS input alias; existing state inherits it when
`direct_dns` is absent. Blank resolver fields use the documented defaults.
See [split DNS](dns.md) before pointing AdGuard at this listener.
