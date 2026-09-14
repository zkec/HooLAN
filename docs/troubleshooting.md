# Troubleshoot HooLAN

[Home](../README.md) · [Documentation](../README.md#documentation)

Collect evidence while the failure is present, using an affected LAN client IP:

```bash
sing-box version
sudo journalctl -u hoolan -n 100 --no-pager
sudo bash /opt/hoolan/scripts/tproxy/diagnose.sh 192.168.3.141
```

## Engine OFF and no internet

Test IPv4 forwarding, the Debian host's upstream default route, FORWARD rules and return
routing/NAT. With clients using the Debian host as gateway, turning interception off still
requires a working router. HooLAN's removal script preserves routing/NAT and
limits; it cannot invent missing host forwarding. See [installation](installation.md).

## Engine ON and stalled clients

| Evidence | Next check |
| --- | --- |
| No `lan_packets` increase | DHCP gateway, ARP, interface and IPv6 |
| Bypass counters increase | Intended private/local/source exclusions |
| TPROXY attempts rise but assignments do not | Engine PID ownership, wildcard IPv4 TCP and UDP, port match |
| Assignments rise but `marked_input` does not | Policy-rule order, mark rewrites, later DNAT, reverse-path filters |
| `marked_input` rises without an engine connection | All later INPUT chains and completed client handshake |
| Engine outbound attempt without return | Node reachability, credentials, resolver and upstream route |
| Marked output appears | Outbound socket marks and `tcp_fwmark_accept` |

The ordinary intercepted path uses mark `0x1` and table `100` by default:

```bash
ip -4 rule show
ip -4 route show table 100
sudo nft -a list table inet proxy_tproxy
sudo ss -lntup '( sport = :7892 )'
```

TPROXY preserves the original destination IP and port. Capturing only loopback
or port 7892 can miss it; observe client ingress and node egress. A curl started
on the Debian host tests host output, not client interception. Established packets must
continue to reach their transparent socket rather than bypass interception.

An ACCEPT in one nftables base chain does not override a later DROP. UFW's
non-local INPUT checks can reject marked traffic retaining a public destination;
use scoped marked TCP/UDP exceptions before those drops. Allowing only INPUT
port 7892 is insufficient because original ports are preserved.

Keep sing-box egress free of the ingress interception mark. Set reverse-path
filters consistently at global/interface scope; changing `ip_forward` can reset
other IPv4 sysctls. Do not enable `src_valid_mark` indiscriminately for a mark
used only in the interception direction.

## Dashboard and jobs

| Symptom | Resolution |
| --- | --- |
| Login rejected | Check `HOOLAN_TOKEN` in `/etc/hoolan/env`, service restart and browser cookie policy |
| Cross-origin API denied | Preserve the public Host header; align HTTPS access with `-secure-cookies` |
| SSE stops behind proxy | Disable buffering and use a sufficient read timeout |
| Busy / HTTP 409 | Wait for the current job to finish or inspect its failure |
| Speed test HTTP 403 | Remote endpoint refused the download; test the node and another permitted endpoint |
| Telegram bot-to-bot 403 | Use the receiver's Chat ID, not the bot ID; send `/start` first |
| Other Telegram rejection | Read the API reason, check permissions or selected proxy path |
| Unexpected speed limit | Check source IP, route category, sampling delay, packet bursts and flow offload |
| Usage below expected | Only engine payload is counted; short flows and OFF forwarding are excluded |

## Recover normal forwarding

If the dashboard is unavailable, inspect the service, then remove interception
using its configured helper:

```bash
sudo bash /opt/hoolan/scripts/tproxy/remove.sh
```

The script acts on its owned table and policy-routing tuple. It keeps device
limits and normal routing/NAT. Fix the upstream/forwarding path if clients remain
offline. Avoid flushing the host's entire ruleset.

References: [Linux TPROXY](https://docs.kernel.org/networking/tproxy.html),
[IPv4 sysctls](https://docs.kernel.org/networking/ip-sysctl.html).
