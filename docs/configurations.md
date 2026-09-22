# Configurations and chains

[Home](../README.md) · [Documentation](../README.md#documentation)

## Add and refresh

Paste a supported node link in **Add a configuration**, or add a subscription
URL and refresh it. Supported families include VLESS, VMess, Trojan,
Shadowsocks, Hysteria2 and TUIC; accepted fields depend on the protocol parser.

A successful subscription refresh replaces that subscription's membership.
Nodes removed by the provider are pruned when no manual ownership or other
subscription still retains them. A failed refresh does not replace the source
with an empty list. Shared nodes are deduplicated by connection identity.

Manual configurations remain distinct from provider-managed entries. Use their
Edit action to update supported endpoint and transport settings. Credential
fields left blank preserve the saved value.

## Sort configurations

Click Configuration, Protocol, Server, Latency or Checked in a card’s table
header. Click again to reverse the order. Each card keeps its own sort order
during refreshes. Sorting preserves checked rows and does not change the active
configuration. Measured latencies come first, followed by failed tests, then
untested configurations in either direction. Missing check times stay at the bottom.

## Batch actions

With no rows selected, Ping all and Delete all apply to that card’s configurations.
Select rows to narrow these actions to Ping selected and Delete selected. Ping
skips load-balanced groups; test their original members instead. Tests are bounded
background jobs, with progress in the dashboard. Deleting a shared node removes
it from every source group; a future subscription refresh can import it again.
Deleting an active configuration may change selection or stop the engine when
no usable configuration remains. Read the confirmation before submitting.

## Multi-hop chains

Add 2–8 enabled single-hop nodes in traversal order:

```text
Client → first hop → intermediate hops → exit → destination
```

A saved chain contains private snapshots of its hops. Provider refreshes and
source edits do not silently change the chain. Source names are retained for
editing; internal engine tags are separate. If an original name cannot be
recovered, the editor shows its server/port.

Use Edit on a chain to add, remove or reorder hops and save the changed path.
The selected configuration represents its exit, whose outbound detours through
previous hops. Deleting the chain deletes its private hop records. Choose a
chain globally or assign it to a device.

## Test and share

Ping selected measures latency through isolated sing-box probe processes. A Speed
Test downloads a fixed payload through the selected node or chain and reports
Mbps. Neither is an ICMP ping or a guarantee of future throughput.

QR Code opens an explicit credential-bearing share link. Single nodes can be
imported by a compatible mobile client. A chain/group cannot be faithfully
represented by one ordinary node URL. See [integrations](integrations.md).

## Screenshot

Configurations tab with illustrative sample data. The screenshot follows your
viewer’s light or dark color preference.

<picture>
  <source media="(prefers-color-scheme: dark)" srcset="images/configurations-dark.png" />
  <source media="(prefers-color-scheme: light)" srcset="images/configurations-light.png" />
  <img src="images/configurations-light.png" alt="Configurations tab with manual nodes, subscriptions, chains and load balancing" width="1440" />
</picture>
