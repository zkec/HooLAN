# Load balancing and automatic selection

[Home](../README.md) · [Documentation](../README.md#documentation)

Create a group in **Configurations → Add & create → Load balancing**. Search
and select 2–32 enabled nodes or chains, enter a name and choose a strategy.
Group creation snapshots members and their detour paths. Up to 16 groups are
supported. Nested groups are not supported. Activate the group or assign it to
a device; merely creating it does not select it.

## Distribute connections

The `hash` strategy distributes IPv4 TCP/UDP flows using nftables' hash of the
source/destination addresses, protocol and ports. Each member receives a separate
TPROXY listener. A flow keeps its listener, preserving connection continuity.

This is active-active connection distribution. It does not bond a single
transfer, guarantee equal byte counts, measure server CPU/load or automatically
remove failed members. Reserve the ports immediately after the main TPROXY
port; readiness checks verify that the managed engine owns all required sockets.

Upstream sing-box is used without a `loadbalance` outbound. HooLAN renders
ordinary outbounds, supported selector groups and transparent listeners.

## Best latency

The `latency` strategy renders a native sing-box URLTest group through the
ordinary TPROXY listener. It selects a member using the configured URL-test
probe URL, interval and tolerance. Device assignments use the same group.
Established connections are retained when the selected member changes.

This selects one measured path rather than spreading traffic across all paths.
It measures URL response latency, not ICMP latency or remote server load.
[sing-box URLTest reference](https://sing-box.sagernet.org/configuration/outbound/urltest/).

## Global automatic selection

The switch beside the builder controls HooLAN's global ordinary-node automatic
selection. It is separate from a group's saved strategy. Activate a saved group
to use its strategy. A manual ordinary-node selection omits the global background
URLTest sweep; explicitly configured latency groups still use their own URL tests.

The create API accepts `strategy: "hash"` or `strategy: "latency"`; omitted
strategy means `hash`. Rows show the saved strategy. To change group members or
strategy, create a replacement group, select it and remove the unused group.
Isolated speed/share operations do not emulate LAN connection distribution.
Telegram proxy delivery uses a group's first saved member.
