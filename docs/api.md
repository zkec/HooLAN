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
| `GET/PUT /api/containers`, `POST /api/containers/refresh` | Docker inventory, container policies and immediate discovery |
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

Use a private IPv4 address actually assigned to the host. A missing/blank
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

## Containers

`GET /api/containers` returns `enabled`, `updated_at`, `error` and `containers`.
Each entry includes `id`, stable `key`, `name`, `image`, `state`, `status`,
`network_mode`, `bindings` (`ip`, `bridge`, `network`), `supported`, optional
`reason`, and saved `settings` (`proxy`, `node_id`, `qos`). Discovery errors
retain the last good inventory. Docker metadata is read only; neither endpoint
starts or stops containers.

`PUT /api/containers` accepts partial top-level updates:

```json
{
  "key": "STABLE_KEY_FROM_CONTAINER_INVENTORY",
  "node_id": "",
  "qos": {
    "proxy_upload_mbps": 5,
    "proxy_download_mbps": 20,
    "direct_upload_mbps": 10,
    "direct_download_mbps": 30
  }
}
```

Use `node_id: "direct"` for Direct, `node_id: ""` for Global Default, or an
enabled visible node, chain or load-balancer ID. Selecting Global Default or a
node enables proxy routing; Direct disables interception. Newly discovered
containers default Direct. The legacy `proxy` field remains accepted for
existing clients and in persisted settings; it is not a separate UI control.
`proxy: true` combined with `node_id: "direct"` is rejected.
Omitted fields are preserved; supplied `qos` replaces all four limits. Rates are
0 (unlimited) or 0.01–10000 Mbps. Unsupported or stale inventory cannot be edited.
Browser mutations require the same session, origin and CSRF checks as device
settings. Policies persist in `state.json` and are included in backups.

`POST /api/containers/refresh` performs discovery/reconciliation synchronously.
It returns 200 on success; conflicting jobs return 409. Automatic discovery
runs every ten seconds. Route changes apply through an engine reload; limits-only
updates atomically replace nftables policing without restarting sing-box.
See [container networking and limitations](containers.md).

## Device presence

`GET /api/usage` includes `device_presence`, keyed by private LAN IPv4, with
`online` and `last_seen` fields. Presence comes from confirmed LAN neighbour
reachability and recent transparent traffic, with a 60-second window reported
as `device_online_window_seconds`. `device_presence_error` reports neighbour
lookup failures; the UI then uses recent observed traffic. Presence is runtime
state and is not restored from backups. Neighbour discovery runs every five
seconds independently of engine ON/OFF. A cached neighbour or an idle connection
alone is not proof of current reachability.

The Usage UI sorts complete tables before paginating, remembers separate
row-count preferences for Internet usage and LAN devices, and keeps all online
devices together on the first page even above the selected count. The API
continues returning complete counters; pagination does not affect accounting.
