# Configurations and chains

[Home](../README.md) · [Documentation](../README.md#documentation)

## Add and refresh

Paste a supported node link in Add a configuration, or add a subscription
URL.

Supported families include VLESS, VMess, Trojan,
Shadowsocks, Hysteria2 and TUIC; accepted fields depend on the protocol parser.

A successful subscription refresh replaces that subscription's membership.
Nodes removed by the provider are pruned when no manual ownership or other
subscription still retains them. A failed refresh does not replace the source
with an empty list.

Manual configurations remain distinct from provider-managed entries. Use their
Edit action to update supported endpoint and transport settings.

## Batch actions

With no rows selected, Ping all and Delete all apply to that card’s configurations.
Select rows to narrow these actions to Ping selected and Delete selected. **Ping
skips load-balanced groups** ; test their original members instead.

Tests are bounded background jobs. The dashboard shows completed/total tests and a percentage,
and refreshes completed node results about every 1.5 seconds while testing.

Select a single row to test just that configuration. Deleting a shared node removes
it from every source group; a future subscription refresh can import it again.
Deleting an active configuration may change selection or stop the engine when
no usable configuration remains.

## Multi-hop chains

Add 2–8 enabled single-hop nodes in traversal order:

```text
Client → first hop → intermediate hops → exit → destination
```

A saved chain contains private snapshots of its hops. Provider refreshes and
source edits do not silently change the chain;

Use Edit on a chain to add, remove or reorder hops and save the changed path.
The selected configuration represents its exit, whose outbound detours through
previous hops. Deleting the chain deletes its private hop records.

## Test and share

Ping selected measures latency through isolated sing-box probe processes. A Speed
Test downloads a fixed payload through the selected node or chain and reports
Mbps. Neither is an ICMP ping or a guarantee of future throughput.

QR Code opens an explicit credential-bearing share link. Single nodes can be
imported by a compatible mobile client. A chain/group cannot be faithfully
represented by one ordinary node URL. See [integrations](integrations.md).

