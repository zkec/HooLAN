# Configuration workflow

The embedded dashboard has three tabs: **Configurations**, **Settings**, and
**Live logs**. Configurations combines source management, manual imports, one
node list, the Chain Builder and expandable usage statistics. Settings combines
DNS, the Iran toggle, editable routing rules and rule-set update schedules.
Old hashes (`#manual`, `#subscriptions`, `#usage`, `#rules`) map to their new tabs.

## Strict synchronization

Every successful subscription refresh replaces that source's membership;
`prune=false` no longer disables synchronization. A node absent from the new
response is deleted if no other subscription or explicit manual ownership
retains it. Untouched and failed subscriptions keep their members. One failed
source does not block another successful source's pruning. A valid empty
response clears that source. Any parse error rejects that source's entire
response, preserving its previous inventory rather than pruning on malformed
input. Existing unowned legacy/manual records are not treated as source-owned.

If synchronization removes the selected config, selection returns to Auto.
If it removes the last enabled config, a running proxy is stopped safely.
Legacy mutable detours that lose a hop are disabled rather than silently
becoming direct connections. Newly built chains use independent snapshots and
are unaffected by source pruning.

## Batch operations

Each visible configuration has a checkbox. A single global bar offers Select
all, Bulk Ping and Bulk Delete; it displays the count of unique selected IDs.
Selection survives polling, and IDs that disappear during sync are deselected.
Ping/Delete/Chain buttons are no longer shown per row; Activate remains.

```http
POST /api/nodes/test
Content-Type: application/json

{"node_ids":["node-a-id","node-b-id"]}
```

Returns 202 with the existing background job response. The complete inventory
is available to resolve chain dependencies, but only the selected configs are
probed. Poll `/api/status` as before.

```http
POST /api/nodes/delete
Content-Type: application/json

{"node_ids":["node-a-id","node-b-id"]}
```

Returns `{"deleted":2,"message":"Selected configurations deleted"}`. Inputs
are validated before mutation; duplicate IDs count once, and batches accept
1–500 IDs. Both manual and subscription configs can be deleted. A subsequent
subscription refresh can reimport its configs. Deleting an entire saved chain
also deletes its internal copies. An unselected legacy chain dependency blocks
the whole batch. Deleting the selected config switches to Auto; deleting all
usable configs stops interception and the engine. One inventory write and one
engine reconciliation cover the batch.

The older single `node_id` request remains accepted for API compatibility.
Supplying both spellings is rejected. Existing authentication/CSRF requirements
apply to all these mutations.

## Chain Builder

Choose 2–8 distinct enabled single-hop configurations and arrange them with
Add hop, Move up/down and Remove. The preview shows **first hop → ... → exit**.
Save creates a new independently identifiable configuration; original nodes and
other saved chains are unchanged. Existing chained configs cannot be used as
nested hops; choose their original single-hop endpoints instead.

```http
POST /api/chains
Content-Type: application/json

{"name":"Three-hop route","node_ids":["first-hop-id","middle-hop-id","exit-id"]}
```

Returns 201 with the new exit configuration's `node_id`. The backend copies the
endpoints, stores private variant identities and ID-based detours, then renders
middle → first and exit → middle in sing-box's `detour` fields. This is consistent
with [sing-box's upstream outbound semantics](https://sing-box.sagernet.org/configuration/shared/dial/#detour).

Internal copies live in `nodes.json` but are hidden from the list and excluded
from the selector and automatic probes. The exit is visible, selectable,
bulk-testable and deletable. Source refreshes cannot overwrite chain copies;
rebuild a chain to adopt changed endpoint credentials. Saving while ON briefly
restarts the engine with interception removed during the transition.

## Modified files

| File | Responsibility |
| --- | --- |
| `internal/api/web/index.html` | Three tabs, unified list, bulk bar and ordered Chain Builder |
| `internal/api/web/app.js` | Checkbox state, batch requests, hop ordering, merged tabs and usage |
| `internal/api/web/style.css` | Bulk bar and chain layout |
| `internal/api/handlers_dashboard.go`, `node_edit.go` | Array request decoding and `/api/chains` route |
| `internal/api/batch.go` | Batch validation, deletion, selected probes and independent chain creation |
| `internal/api/service_dashboard.go` | Authoritative membership reconciliation and pruning |
| `internal/api/service.go`, `handlers.go` | Probe scope, visible counts, hidden hop filtering |
| `internal/store/batch.go` | Atomic inventory replacement with memory rollback on write failure |
| `internal/store/db.go`, `id.go`, `internal/subscription/parser.go` | Persisted chain group and private variant identities |
| `internal/engine/singbox.go` | Keep internal hops out of selector/URLTest |

Build/deploy the Go binary to update both backend and embedded assets; no frontend
build step is needed. Existing nodes keep their IDs. No firewall changes are
required for this dashboard update.
