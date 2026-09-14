# Develop HooLAN

[Home](../README.md) · [Documentation](../README.md#documentation)

## Repository map

| Directory | Responsibility |
| --- | --- |
| `cmd/server/` | Flags, service startup, shutdown and dependency wiring |
| `internal/api/` | Authentication, jobs, subscriptions, state and HTTP handlers |
| `internal/api/web/` | Embedded HTML, CSS, JavaScript, translations and SVG logos |
| `internal/engine/` | sing-box configuration, process supervision and rule-set downloads |
| `internal/store/` | JSON inventory, stable identities, health and private snapshots |
| `internal/subscription/` | Protocol parsing, validation and share links |
| `internal/tester/` | Isolated proxy latency/throughput probes |
| `internal/netfilter/` | Script coordination, distribution and device policers |
| `internal/logstream/` | Bounded service/engine log replay |
| `scripts/tproxy/` | Apply, remove, diagnose and host-router setup |
| `deploy/` | `hoolan.service` and `hoolan.env.example` |

The Go module is `hoolan` and has no third-party requirements. The dashboard is
Vanilla JS/HTML/CSS, embedded with `go:embed`. Rebuild the binary after changing
assets. QR rendering is the sole optional browser CDN dependency. Keep user
strings out of HTML interpolation; use DOM text nodes and preserve them from
translation.

## Validation

```bash
go test ./...
go test -race ./...
go vet ./...
node scripts/test-web.cjs
node scripts/test-dashboard.cjs
for script in scripts/tproxy/*.sh; do bash -n "$script"; done
CGO_ENABLED=0 GOOS=linux GOARCH=arm64 \
  go build -trimpath -ldflags='-s -w' -o hoolan ./cmd/server
```

Node is optional for the development-only UI tests; it is not a runtime or build
dependency. Tests with temporary HTTP servers need localhost sockets. Firewall
fixtures use isolated or fake environments; do not run tests against a live
LAN ruleset. `HOOLAN_TEST_NFT_NAMESPACE=1` opts into the isolated namespace test
where supported. UI tests exercise behavior, not browser layout; inspect both
themes, mobile widths and Persian RTL in a browser before releasing UI changes.

## Runtime boundaries

Serialize state-changing engine/firewall operations while keeping HTTP response
writes outside state locks. Bound queues, replay buffers, probes and response
reads. Keep subprocess output handling bounded. Persist operator settings and
roll back unsuccessful live updates where supported.

Interception is installed after listener ownership is verified and removed
before engine shutdown. Never add a broad established-flow bypass to the TPROXY
path. Do not give the engine the ingress mark as its outbound mark. Use atomic
scoped nft batches instead of flushing unrelated tables. Preserve the local
Docker/service exclusions and the independent OFF forwarding path.

Stable node IDs describe connection identity, not display names. Saved chains
and groups own their snapshots; editing or pruning sources must not mutate them.
Sensitive state, backups, node links and notification tokens must not enter
public responses or logs. Record names separately from generated engine tags.

Build output `hoolan`, JSON stores and cache databases are ignored by Git.
Runtime artifacts do not belong in `internal/api/web/`, which is embedded whole.
