# Routing, DNS and rule sets

[Home](../README.md) · [Documentation](../README.md#documentation)

## Packet routing

Interception applies to eligible IPv4 TCP/UDP arriving on the configured LAN
interface. Private/local destinations, source exclusions and the local Docker
network `10.42.42.0/24` bypass interception. Local services on ports 80, 443 and
53 remain accessible before Docker DNAT. The Debian host's own output is not a LAN
TPROXY client.

Inside sing-box, safety and DNS/private-network handling precede custom routing
rules, custom rule sets, the Iran preset, device assignments and the global
outbound. More specific device assignments therefore do not override the
preceding bypass policies. Eligible intercepted DNS is handled by sing-box using
split DNS. Local resolver traffic still bypasses interception; connect AdGuard
explicitly to the DNS listener on port 1053.

## DNS

Routing & DNS has separate **Tunneled DoH Server** and **Direct DNS Server**
fields. The former uses HTTPS through the active proxy; the latter sends local
and bypass queries directly to SmartDNS. A configurable private/loopback DNS
listener lets AdGuard retain port 53. This works with FakeDNS off or on.

Follow the [split-DNS setup guide](split-dns.md) for Docker AdGuard, rule order,
GeoIP response matching, bootstrap exceptions and engine-OFF handling. For
optional synthetic client answers, see [FakeDNS](fakedns.md).

## Iran preset

Rule sets contains a built-in Iran GeoIP/geosite preset. Its enable switch
applies immediately. Configure the compiled `.srs` source URLs and matching
action: direct, selected proxy or reject. Save routing rules applies source
and action edits. The enabled preset uses its saved action.

## Custom rules

Add compiled sing-box `.srs` sources with unique `custom-...` tags. Enable/disable
and reorder them, and choose their matching action. Custom sets are evaluated
before the Iran preset.

Custom match rules support domain, domain suffix and IP CIDR values, one per
line. First matching rule wins within the ordered rules. Use the toggles and
move controls to manage precedence. Private/local traffic already bypassed by
nftables never reaches these rules. Changes can briefly restart the engine.

## Updates and storage

Choose manual updates, an interval in days, daily at a time, or weekly on a
chosen day/time. Specify a timezone, such as `Asia/Tehran`. Schedules run in Go
and continue while the proxy engine is OFF. Update now starts a background job;
save draft rule changes before requesting it.

Downloaded rule sets are validated before activation. Settings shows last
successful update, next due time, file paths and the most recent error. Paths
are also returned by `GET /api/rules`; use those reported paths rather than
editing generated files. Downloads are kept in generation directories under
the engine's rule-set storage. The backup ZIP includes policy and schedule,
not downloaded `.srs` payloads.
