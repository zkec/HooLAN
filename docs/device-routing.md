# Device usage and routing

The dashboard has Configurations, Usage, Settings and Live logs tabs. Manual
configurations (including saved chains) have their own card with the same layout
as subscription cards. Each card has independent checkboxes, Select all, Bulk
Ping and Bulk Delete. Shared nodes can appear in more than one card; deleting a
node deletes it from the inventory and all its groups. Chain Builder sits between
Add a configuration and Add a subscription.

## Files

| File | Change |
| --- | --- |
| `internal/api/web/index.html` | Ordered input cards, manual group and dedicated Usage tab |
| `internal/api/web/app.js` | Group selection, batch requests, zero-byte filtering, device counters, names and grouped route selects |
| `internal/api/web/style.css` | Matching configuration cards and device editing layout |
| `internal/api/service.go` | Persistent `device_aliases` and `device_routes` maps in State |
| `internal/api/devices.go` | Validated, serialized alias/assignment updates and rollback |
| `internal/api/handlers_dashboard.go` | Authenticated `PUT /api/devices` registration |
| `internal/api/usage.go` | Clash source metadata, per-device counter deltas and read API |
| `internal/api/service_dashboard.go` | Pass assignments to the engine and clear mappings to pruned/invalid nodes |
| `internal/api/batch.go` | Clear assignments to bulk-deleted nodes in the inventory/state transaction |
| `internal/engine/config.go` | `source_ip_cidr` route matcher |
| `internal/engine/singbox.go` | Resolve stable node IDs to rendered outbound tags and append device rules |
| `internal/api/devices_test.go`, `internal/engine/devices_test.go` | Persistence, validation, routing, rollback, pruning and accounting regression checks |

## Read usage and device settings

`GET /api/usage` keeps its existing response and adds:

```json
{
  "usage": {
    "devices": {
      "192.168.3.141": {"upload": 1024, "download": 8192}
    }
  },
  "device_aliases": {"192.168.3.141": "Phone"},
  "device_routes": {"192.168.3.141": "stable-node-id"}
}
```

The response also contains total/outbound counters, sample timestamp, errors,
support status and accounting scope. The routing dropdown also offers Direct (`node_id: "direct"`); see
[Dashboard editing and localization](dashboard-editing.md). Only configurations with nonzero upload or
download appear in the Usage table. Historical usage for deleted configurations
remains visible under its stable ID. Device rows include observed IPs and any
saved aliases or assignments, even when their counters are zero.

Clash `/connections` exposes original source addresses in `metadata.sourceIP`
and the inbound type/tag in `metadata.type`. The sampler collects private IPv4
sources from the TPROXY inbound; it excludes probes/other inbounds and loopback.
It sums connection deltas separately for device and outbound attribution,
including proxied and sing-box-direct flows without counting each chain hop
again. Upload is client-to-internet; download is internet-to-client.

Counters are payload estimates sampled once per second. Connections which start
and finish between samples can be missed, as can a connection's final bytes
before it closes. Device/node sums need not equal the engine's cumulative global
total. This is not exact link-layer or billing accounting. Traffic forwarded by
Linux while the proxy is OFF, traffic bypassed by nftables, and local
AdGuard/Docker traffic are outside the scope. Counters are checkpointed in the
existing state JSON at most once per minute during sampling and through existing
lifecycle saves; an abrupt power loss can lose recent uncheckpointed bytes.
Names and routes are saved immediately. IP aliases follow addresses, not MACs.

## Update a name or assignment

```http
PUT /api/devices
Content-Type: application/json

{"ip":"192.168.3.141","alias":"Phone"}
```

```http
PUT /api/devices
Content-Type: application/json

{"ip":"192.168.3.141","node_id":"stable-node-id"}
```

Both fields may be supplied together. Omitted fields are unchanged. An empty
`alias` removes the name; an empty `node_id` removes the assignment and restores
Global Default. Null is treated as omitted. Successful updates return 200 with
`{"message":"Device settings saved"}`. Existing session/CSRF or bearer-token
authentication applies. The dashboard calls this endpoint on dropdown change;
name changes use Save name. No page reload is needed.

Only private IPv4 host addresses are accepted because this gateway's nftables
and policy-routing configuration intercept IPv4. Names allow up to 80 Unicode
characters with no control characters. Targets may be `direct` or existing, enabled,
visible configurations; saved chain exits are allowed, internal hops are not.
Unknown IDs return 404, invalid fields 400, and an active refresh conflicts with
the update. Alias changes do not restart the engine.

## Routing and application

The generated rule uses sing-box's actual field
[`source_ip_cidr`](https://sing-box.sagernet.org/configuration/route/rule/#source_ip_cidr):

```json
{
  "inbound": ["tproxy-in"],
  "source_ip_cidr": ["192.168.3.141/32"],
  "action": "route",
  "outbound": "rendered-node-tag"
}
```

Ordering is the existing safety/sniff/DNS/private rules, custom rules, Iran
rules, then device rules, with `route.final = "proxy"` as global fallback.
Device assignments therefore preserve Iran bypass and do not override earlier
custom matches. The existing DNS behavior is unchanged. IDs are resolved after
tag deduplication, so identical provider display names cannot misdirect a device.
Successful source refreshes prune orphaned source-owned nodes, clear affected
device assignments, and preserve their aliases/counters. Shared/manual-owned
nodes remain. Failed or malformed feeds preserve their previous membership.
Bulk deletion likewise clears assignments. Missing/disabled nodes in a rendered
inventory fall back to the global route.

An assignment change is saved and applied immediately using the existing managed
engine reload: remove interception, render/check/start sing-box, wait for its
listener, restore selection and interception. This **briefly restarts the engine**;
it is not a connection-preserving hot reload. Upstream sing-box's Clash
[`PUT /configs` implementation](https://github.com/SagerNet/sing-box/blob/testing/experimental/clashapi/configs.go)
is a no-op, so sending a Clash config-update request would not install these
rules. A failed application restores the previous saved assignment; the existing
failure cleanup can leave the engine stopped with interception removed. When
OFF, assignments are saved and applied on the next enable.

Rebuild and replace the Go binary to deploy the backend and embedded assets;
there is no frontend build step. No additional firewall rule or Clash API public
exposure is required. Live forwarding and reload behavior should be checked on
the Pi with two devices assigned to different nodes.
