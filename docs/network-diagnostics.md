# Locate the TPROXY failure

Collect a snapshot while the dashboard reports ON and while a real LAN client
makes a fresh request. If the table is absent, table 100 is empty and port 7892
has no listener, interception is off or startup failed and cleanup ran. Start
with the toggle error and `journalctl -u proxy-manager -n 100 --no-pager` in that
case; an off-state snapshot cannot establish where intercepted packets fail.

## Read-only collection

After installing the updated scripts, substitute the affected client's IPv4,
the public destination being tested and, optionally, the actual proxy-node IP:

```bash
sudo bash /opt/proxy-manager/scripts/tproxy/diagnose.sh \
  192.168.3.50 1.1.1.1 203.0.113.10
```

The last address above is a documentation placeholder: use a real node IP or
omit it. The script reads routes, sysctls, TCP/UDP listeners, all firewall base
chains and counters. It never enables the proxy, changes policies, starts a
capture, reads credentials from the engine config, or dials port 7892. If you
use another install path, invoke that checkout's script and configuration.

Compare two snapshots around one new client request. The updated table has:

| Observation | Next boundary to inspect |
| --- | --- |
| `lan_packets` does not increase | Client gateway/ARP, LAN interface, or IPv6 bypass |
| `bypass_local`, `bypass_private`, `bypass_source` increase | Packet matched an intentional exclusion |
| `tproxy_attempt_tcp/udp` rises; `tproxy_assigned_tcp/udp` does not | Transparent socket lookup: correct PID, IPv4 address, TCP and UDP, matching port |
| Assignment rises; `marked_input` does not | Rule precedence, mark rewrites, later PREROUTING/DNAT, reverse-path filtering |
| `marked_input` rises | Later INPUT rules, handshake completion, then sing-box logs and selected outbound |
| `marked_output` rises | Engine outbound `routing_mark`, `tcp_fwmark_accept`, other marking rules |
| Engine logs an outbound attempt but no return | Pi route to the proxy node, DNS/bootstrap, upstream reachability or proxy credentials |

`tproxy_failed_tcp/udp` counts socket-assignment failures. Marks are set only
after successful assignment; failures fall back to ordinary forwarding. That
fallback still needs the site's normal forwarding and return routing/NAT.

## Specific checks after removing the established bypass

1. **Verify the deployed generation.** Copy the updated template, apply/remove
   scripts and Go binary. Restart only after installation. An old `nft -f`
   implementation appended rules rather than replacing them. The new batch
   atomically recreates only `inet proxy_tproxy`, including sets and counters.
2. **Use IPv4 listeners.** The generated inbound now uses `0.0.0.0`. A displayed
   `:::7892` alone does not prove IPv4 UDP or TCP is usable. Readiness now checks
   wildcard IPv4 TCP and UDP socket inodes owned by the engine PID. It catches
   wrong-process listeners and port/config drift without creating a self-dial.
3. **Keep egress unmarked.** Mark `0x1` means local delivery to table 100. Setting
   the same mark on sing-box's outbound sockets routes them locally too, even
   with OUTPUT policy ACCEPT. Also inspect `net.ipv4.tcp_fwmark_accept`; enabling
   it can make accepted TCP sockets inherit the incoming mark on reply packets.
4. **Inspect all chains.** ACCEPT in one INPUT/FORWARD base chain cannot override
   a later DROP. TPROXY preserves the original destination port; allowing only
   INPUT port 7892 does not cover intercepted HTTPS packets with port 443.
5. **Inspect effective sysctls after enabling.** Linux takes the maximum of
   `all` and the interface values for `rp_filter` and `src_valid_mark`. Setting
   `ip_forward` from 0 to 1 resets IPv4 configuration to router defaults, so a
   previous sysctl change may no longer be effective. Do not enable
   `src_valid_mark=1` by habit: the kernel documents zero for marks used in only
   one direction, including transparent proxying.
6. **Distinguish host egress from forwarding.** Sing-box opens a new Pi-sourced
   socket, including for its direct outbound. It needs a working default route
   and permitted OUTPUT/return INPUT; a general LAN MASQUERADE rule does not fix
   transparent socket lookup. Bypassed client traffic needs its own forwarding
   and return route or appropriately scoped SNAT.

The helper prints optional `tcpdump` commands. Capture the client's original
destination and port on its ingress interface, plus the node IP on egress.
Capturing only `lo` or port 7892 can miss transparent delivery because TPROXY
does not rewrite packet headers. A `curl` launched on the Pi tests host egress,
not LAN interception.

The DNS route is forwarding through the proxy, not `hijack-dns`. Local AdGuard
and private destinations remain bypassed before Docker DNAT at priority -100;
the gateway runs at priority -150 and explicitly preserves `10.42.42.0/24`.

References: [Linux TPROXY](https://docs.kernel.org/networking/tproxy.html),
[kernel socket-assignment implementation](https://raw.githubusercontent.com/torvalds/linux/master/net/netfilter/nft_tproxy.c),
[IPv4 sysctls](https://docs.kernel.org/networking/ip-sysctl.html),
[nftables atomic replacement](https://wiki.nftables.org/wiki-nftables/index.php/Atomic_rule_replacement).
