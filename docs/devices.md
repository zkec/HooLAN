# Devices, usage and speed limits

[Home](../README.md) · [Documentation](../README.md#documentation)

## Device routing

Open **Usage → LAN devices → Settings**. Assign a name and choose Global Default,
Direct, a node, chain or saved group. Names and routes persist by original client
IPv4 address. Reserve IPs in DHCP; aliases are not device identity or MAC tracking.

Device rules run after safety, DNS/private-network and custom/Iran policies.
Saving a changed route applies it to the engine and can briefly restart it.
Global Default follows the gateway's selection. Configurations are grouped by
manual ownership and subscription in the selector.

## Four-way limits

| Field | Applies to |
| --- | --- |
| Proxy Upload | Client data using a proxy outbound |
| Proxy Download | Proxy-routed data sent to the client |
| Direct Upload | Direct/bypassed client data crossing the Debian host |
| Direct Download | Direct/bypassed data sent back to the client |

Values are Mbps; blank or zero means unlimited. **Reset limits** clears all four
fields, and **Save device settings** applies the reset without changing the name
or route. The table's Speed set column displays saved limits, not measured speed.

HooLAN installs per-device nftables byte-rate policers with atomic updates.
Each device/direction/category has its own bucket. These rules drop excess
packets rather than queue them; observed throughput varies with packet overhead,
bursts and transport behavior. The host's flow-offload settings must not bypass
the applicable hooks.

Proxy/direct classification uses the engine's sampled connection route. Until
classification is available, the stricter nonzero limit applies. Short flows may
keep that limit. Raw forwarded traffic uses Direct immediately, including with
the engine OFF. Same-subnet traffic that avoids the Debian host and access to the Debian host's own
services are outside these device limit paths.

## Usage attribution

Total usage is payload bytes reported by the engine. Per-device, per-node and
direct attribution is estimated from one-second connection samples; short flows
can be missed. Device entries include original client IPs for traffic sing-box
routes directly. Raw forwarding with the engine OFF is excluded from these totals.

Click a column heading to sort, and click again to reverse the order. Upload
and download use byte counts; IP addresses use numeric ordering. The speed
column compares proxy upload, proxy download, direct upload, then direct download,
with unlimited above any finite value (so it comes last in ascending order). Zero-byte nodes are hidden. Direct/bypass has
its own row. Chains are attributed to their visible exit configuration; groups
to their visible group, rather than counting each hop again. Closed flows between
samples, process restarts and counter resets can limit attribution accuracy.

`PUT /api/devices` supports partial top-level updates. An included `qos` object
replaces all four values; `{}` clears them. Limits remain subject to the network
path through this Debian host. [API examples](api.md).
