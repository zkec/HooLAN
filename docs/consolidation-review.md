# Consolidation review

Reviewed 2026-09-14. [English setup](../README.md) · [راهنمای فارسی](../README-fa.md)

This review covers the current API/service, engine, store, netfilter scripts and
embedded dashboard. It records concrete fixes and retained design constraints;
it is not a security certification, capacity benchmark or guarantee of HA.

## Changes made

| Area / files | Finding and change |
| --- | --- |
| `internal/api/usage.go`, `telegram.go` | GET usage and Telegram read/write responses encoded/wrote JSON while holding the shared state read lock. They now snapshot/commit under lock, unlock, then write. Usage maps are copied. A slow HTTP client cannot hold up state writers through this handler. |
| `internal/api/usage.go` | Per-connection attribution scanned all node tags. One reverse index per sample replaces that connections × nodes loop. Existing totals, Direct and group attribution remain intact. |
| `internal/api/handlers.go` | Listing every node repeatedly scanned all subscription memberships under separate locks. A single membership snapshot/index serves the listing, including deduplication and manual/legacy ownership. |
| `internal/api/readiness.go`, `service.go` | Multi-listener readiness repeatedly read `/proc/<pid>/fd` and protocol tables for individual ports. Each polling pass now reads descriptors once and each protocol table once, while requiring every listener to be IPv4 wildcard, correctly typed and PID-owned. |
| `internal/api/service.go`, `service_dashboard.go`, `internal/store/batch.go` | A latency sweep persisted/fsynced the entire node store for every result. `RecordMeasurements` commits a complete sweep once. Incomplete tester output is rejected before committing health. |
| `internal/store/db.go`, `batch.go` | Value copies still shared ALPN and load-balancer member/tag slices. Store reads, incoming records and Update callbacks now own their mutable slices. `All` sorts its detached snapshot after releasing the lock. |
| `internal/store/db.go`, `batch.go` | Several mutations could leave memory changed after persistence failed, or after a rejected Update callback. Upsert, measurements, SetEnabled, Update and Prune now restore/retain the previous generation on failure. |
| `internal/engine/singbox.go` | Unterminated child-process output could grow without bound and repeatedly copy its partial line. The writer now retains at most 64 KiB per unfinished line, drains/discards excess bytes and resumes after newline, marking truncation. |
| `internal/logstream/hub.go` | Once full, every log append shifted all 512 history records under lock. A ring buffer makes retained-history append constant-time. Ordered replay, cursors and slow-subscriber eviction are preserved. |
| `web/preferences.js`, `web/i18n.js` | Theme changes retraversed the full DOM for translation; regex/message arrays were rebuilt per text node; attribute changes rewalked descendants. Theme changes now update CSS variables/button state; language changes alone request a full refresh. Translation constants are reused, mutation roots deduplicated, and attribute changes translated without subtree traversal. |
| `web/app.js` | Device buttons each captured the whole usage response. One delegated listener uses a single latest snapshot. Deleted-node speed results/group-open state are pruned; logout clears those caches. Selection cleanup uses a Set; usage/device rows use indexed node lookups. QR script handlers/timers are cleared on success, failure and timeout. |
| `web/style.css` | Removed stale inline device-name/limit form styling after the modal migration; device table headers use logical start alignment. Existing theme tokens and RTL rules are retained. |
| `scripts/tproxy/install-router.sh` | Marked UFW INPUT exceptions were hardcoded to `0x1`, conflicting with configurable interception marks. The installer now accepts and validates `TPROXY_FWMARK` before writing and uses it in both exceptions. Default remains `0x1`. |
| `deploy/` | Added explicit loopback-bound systemd and environment templates, with a post-stop interception cleanup hook that retains router/NAT/QoS. |
| `README.md`, `README-fa.md` | Replaced obsolete setup/UI descriptions with matching operational guides. Persian prose uses an RTL wrapper; code and diagrams have LTR wrappers. |

## Files and code to remove

| Path / item | Decision |
| --- | --- |
| `internal/api/listen_test.go` | **Removed in this change**, together with the unused `tcpPortIsListening`, `scanProcTCPListen` and `procTCPFiles` implementation. These only tested the superseded any-process TCP-only readiness contract. Current readiness regression tests are retained/extended. |
| Repository-root `.directory` | **Safe optional deletion.** Desktop folder-icon metadata; not an application asset, Go input or deployment dependency. Left for the owner because it is a desktop preference. |
| Repository-root `proxy-manager` | **Safe optional deletion after installing/retaining the desired binary elsewhere.** Ignored build output; rebuild from source. It is not the installed `/opt/proxy-manager/proxy-manager`. |
| `.device-name-form` and `.device-table select` CSS rules | **Removed in this change.** The four-limit modal replaced their only UI consumers. |

No active TPROXY shell script is obsolete: `apply.sh` installs interception,
`remove.sh` is the recovery path, `diagnose.sh` is read-only diagnosis and
`install-router.sh` supplies persistent OFF-mode routing for the supported UFW
site. Platform-specific `procattr_linux.go` / `procattr_other.go` files are build
variants, not duplicates.

Keep `node_edit.go` and the old singular/detour API compatibility paths: runtime
handlers still reference them and external API users may depend on them. Keep
`login.html`, `login.js`, `preferences.js` and `i18n.js`: they are embedded assets
referenced by the login/dashboard. Keep `MEMORY.md` as project-specific context;
it is not a runtime asset, but redundancy has not been established.

The older feature documents retain API examples and migration/debugging detail.
They now point readers to the current READMEs and four-way QoS guide. Deleting
them would break references or lose information; they are not marked safe for
bulk removal. Never clean up deployed `nodes.json`, `state.json`, `tproxy.conf`,
environment secrets or rule files as if they were build artifacts.

## Concurrency and resource decisions retained

- `opMu` still serializes lifecycle and inventory changes. Moving start/stop,
  subscription commits or rollback outside that ordering would risk intercepting
  traffic with no listener or applying stale node/route references.
- JSON persistence still runs under the relevant mutation lock. This ensures
  atomic memory/file rollback and ordered commits; moving fsync outside it needs
  a versioned commit design, not just an unlock. Batching removes the repeated
  latency-sweep writes; usage persistence remains at most once per minute plus
  lifecycle saves.
- Engine process pipes are drained by `os/exec`, with bounded WaitDelay and
  cancellation/reaping. SSE subscribers, history, message sizes, sessions,
  notifications and test-worker concurrency already have bounds; those remain.
- Historical usage maps intentionally retain past usage. Their growth with
  historical devices/configurations is retained product data, unlike the
  disposable frontend caches pruned here. Usage snapshots copy these maps per
  request; very long-lived or very large installations may need a retention policy.
- QoS sampling shares lifecycle serialization. Long/busy operations can delay
  samples and expire classification entries, so conservative fallback limits
  remain documented. This review does not silently change that packet policy.
- The gateway remains standard-library Go plus embedded Vanilla JS/HTML/CSS.
  Optional QR rendering uses the existing CDN library. Optional frontend test
  tooling is outside the embedded directory and uses no npm packages.

## Validation and boundaries

Regression coverage includes batch persistence failure/rollback, slice ownership,
rejected callbacks, bounded unterminated logs, ring replay/cursors, HTTP response
lock release and multi-port readiness. Existing suites cover authentication,
CSRF, SSE cancellation, chains/distribution, subscription pruning, rollback,
rule scheduling, restore and mock firewall ordering.

Run:

```bash
go test -race ./...
go vet ./...
node scripts/test-web.cjs
```

The frontend test checks English/Persian round trips, untouched user text,
deduplicated mutations, attribute-only updates, detached nodes and theme/RTL
switch behavior using a small DOM fixture. It is not a visual browser test.
Syntax/HTML references, shell syntax and README local links are also checked
while preparing this change. ARM64 cross-compilation validates the deployment
build. No live Pi firewall, DHCP or service installation is changed by this review.

No numerical throughput/CPU improvement is claimed without representative Pi
measurements. Validate a deployment with sustained ON/OFF traffic, QoS in both
directions/classes, multiple simultaneous balanced connections and long SSE
sessions. A reviewed home gateway still requires a stable host, reachable
upstream router and a tested recovery procedure.

Validation completed for this change: `go test -race ./...`, `go vet ./...`,
ARM64 static build, JavaScript syntax and element references, localization/theme
behavior, shell syntax, temporary UFW rendering (including custom/invalid marks)
and local README links passed. The frontend behavior suite ran in the installed
JavaScriptCore engine because Node is not installed in this workspace.
`systemd-analyze verify` passed on a temporary copy of the supplied unit with
executable paths adjusted to the built binary and checkout; no unit was installed.
The ARM64 review artifact is `/tmp/proxy-manager-consolidated`.
