# DNS & FakeDNS

[Home](../README.md) · [Routing](routing.md) · [Troubleshooting](troubleshooting.md) 

Configure DNS in **Settings → Routing & DNS**. HooLAN listens on **port 1053**
over TCP and UDP while the engine is running.

## Choose your DNS servers

| Setting | Purpose | Example |
| --- | --- | --- |
| Tunneled DoH Server | Encrypted DNS through the active proxy | `https://1.1.1.1/dns-query` |
| Direct DNS Server | DNS for local and bypassed domains | `192.168.3.1` |

Enter an HTTPS URL for tunneled DNS and an IP address, optionally with a port,
for direct DNS. Use your own resolver addresses; the examples are not automatic
network discovery. Click **Save settings** to apply changes.

Local and bypassed domains use Direct DNS. Other queries use tunneled DoH.
If the proxy cannot reach the DoH server, those real lookups fail rather than
falling back to an unencrypted connection.

## Listen address

The default listen address is `127.0.0.1`. To accept requests from another
machine, select a private IPv4 address assigned to the gateway and allow that
client to reach TCP/UDP port 1053 in your firewall. Use `ADDRESS:1053` as the DNS
upstream. The address must be reachable from the caller.

The address field appears when the FakeDNS switch is on. To edit it while
keeping FakeDNS off, turn the switch on in the form, edit the address, turn it
off again, then save. Hiding the field preserves the address and keeps split
DNS running. The direct resolver must not forward back to this listener.

## FakeDNS

Enable **FakeDNS** to return virtual IPv4 addresses for proxied domains.
When a client connects, HooLAN recovers the original domain, resolves its real
address through encrypted DNS and applies your routing rules. Bypassed domains
keep real answers from Direct DNS.

- Virtual addresses come from `198.18.0.0/15`.
- Only clients whose connections pass through HooLAN's TPROXY gateway should
  receive virtual addresses. The gateway itself and other clients that bypass
  interception need real DNS answers.
- FakeDNS returns empty answers for AAAA and HTTPS/SVCB queries. It does not
  intercept IPv6 traffic or applications using their own DoH/DoT resolver.
- Virtual A answers cannot satisfy DNSSEC validation of the original records.
- Clear downstream DNS caches when switching FakeDNS on or off.

Leave FakeDNS off to use split DNS with ordinary real answers.

## Matching and bootstrap

DNS follows custom domain rules, custom rule sets and the Iran preset in their
configured order. Direct rules choose Direct DNS, proxy rules choose tunneled
DoH, and reject rules refuse the query. Disabling the Iran preset removes its
DNS matches. Local suffixes (`lan`, `local`, `home.arpa`) and reverse zones use
Direct DNS.

IP and GeoIP matching require an answer first. At the first address-dependent
rule, HooLAN evaluates an encrypted DoH answer. A direct match then performs a
Direct DNS lookup; otherwise the encrypted answer is reused. Custom rule sets
may contain IP criteria, so they also require evaluation. Known domain rules
before that point can select Direct DNS without querying DoH.

Proxy endpoint names, rule-set download hosts and hostname-based DoH bootstrap
use Direct DNS to avoid a DNS/proxy dependency loop. IP-based endpoints reduce
this dependency. HTTPS certificate verification remains enabled.

Tunneled DNS uses the global active proxy, including its selected chain or
group. Per-device routing does not choose a separate DNS proxy. Hash-distribution
groups use their selector for this locally generated connection.

## Test DNS

Replace `GATEWAY_IP` with the saved listen address:

```bash
dig @GATEWAY_IP -p 1053 example.com A
dig @GATEWAY_IP -p 1053 example.com A +tcp
sudo ss -lntup '( sport = :1053 )'
```

With FakeDNS off, expect real addresses. With FakeDNS on, a non-bypass domain
returns an address in `198.18.0.0/15`. Check a known bypass domain too.

Test from the actual DNS caller as well as the gateway. A successful local
test does not prove that another machine can reach the listener. If only remote
requests time out, check the listen address, routing and firewall. If only
non-bypass queries fail, check the active proxy and DoH server. A DNS answer
alone does not prove that subsequent client traffic follows the gateway.

## Cache, shutdown and recovery

Stopping the engine stops port 1053, even when FakeDNS is off. Switch callers
to a working real resolver before stopping the engine. If FakeDNS was enabled,
also clear downstream DNS caches and reconnect applications: virtual addresses
cannot be forwarded as ordinary internet destinations.

Mappings persist in sing-box's cache, normally `/var/lib/hoolan/cache.db`.
Keep this file across restarts. It is not included in backup ZIPs, so clear
client caches after restoring to another host or losing the mapping store.
Virtual answers have a 60-second TTL, but applications may cache them longer.

The `inet hoolan_fakedns` guard drops virtual destinations that reach ordinary
forwarding or host output. It remains after interception stops to protect stale
caches. Increasing drops can indicate that clients bypass TPROXY or retain old
answers. Disabling FakeDNS alone keeps the real DNS listener running.

## Usage and speed limits

Device usage remains attributed to the original client IP. For virtual-address
connections, HooLAN combines engine samples with bounded nftables observations
to classify direct and proxy traffic. Missing or ambiguous observations use the
stricter unknown-traffic cap. Short connections can be missed by sampling.

## API

`GET/PUT /api/settings` uses these fields:

```json
{
  "tunneled_doh": "https://1.1.1.1/dns-query",
  "direct_dns": "192.168.3.1",
  "fake_dns": {"enabled": false, "listen": "127.0.0.1"}
}
```

Omitted fields retain their values. Settings persist in `state.json` and backups.
The legacy `dns_server` field is accepted as a Direct DNS alias.

The generated configuration targets sing-box 1.14+: a `dns-in` direct inbound,
`hijack-dns`, typed HTTPS/UDP DNS servers and response evaluation for IP rules.
See the official [DNS actions](https://sing-box.sagernet.org/configuration/dns/rule_action/),
[FakeIP server](https://sing-box.sagernet.org/configuration/dns/server/fakeip/) and
[persistent cache](https://sing-box.sagernet.org/configuration/experimental/cache-file/) references.
