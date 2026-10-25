# Docker containers

[Home](../README.md) · [Dashboard](dashboard.md) · [Devices](devices.md)

Use **Containers** to choose how each container reaches the internet. HooLAN
lists containers automatically, including stopped containers, and checks Docker
every ten seconds. **Refresh containers** requests an immediate check. Click
column headings to sort the list.

## Requirements

Run HooLAN on the Docker host, in the host's network namespace. It reads the
local Docker Engine Unix socket at `/var/run/docker.sock`; the service account
must be able to access that socket. The supplied systemd service runs as root.
No Docker SDK, extra Go modules, Docker CLI or Compose changes are required.
HooLAN reads inventory only; it does not start, stop or modify containers.

Set `-docker-socket /path/to/docker.sock` or `HOOLAN_DOCKER_SOCKET` to change the
socket. Set either to an empty string to disable discovery. Only local Unix
sockets are accepted; remote TCP Docker endpoints are not supported.

Install the updated `apply.sh` and `tproxy.nft.template` with the executable.
See [updating an installation](installation.md#updating-an-installation).

## Routing

Newly discovered containers default to **Direct**, keeping Docker's normal
connection. Open **Settings → Assigned outbound routing** and choose **Direct**,
**Global Default**, an enabled node, a chain or a saved load balancer. One
selector controls the route; there is no separate proxy switch. Existing saved
routes and four-way limits are preserved.

A pulsing green light beside a container name means Docker reported it as
running in the latest discovery. Stopped, paused or restarting containers have
a blank indicator. The light also clears when discovery fails or its snapshot
is more than 30 seconds old. Detailed state remains available as a tooltip on
the name, without a separate Status column.

Global Default follows the gateway's active selection. Pinned configurations
use their own outbound. Existing DNS, private-network, custom and Iran bypass
rules still take precedence, just as they do for [devices](devices.md). With the
engine explicitly OFF, containers use normal Docker forwarding/NAT and their
Direct speed limits. Container proxy settings remain saved for engine startup.

A routing change briefly restarts a running engine to apply source-IP rules;
applications may need to reconnect. Changing only speed limits does not restart
the engine. These controls affect internet TCP/UDP connections initiated by the
container. Access to local/private destinations and replies from published
container services continue through Docker's ordinary path. Docker's firewall,
port publishing and NAT rules are left intact.

## Speed limits

The editor has four independent Mbps fields:

| Limit | Applies to |
| --- | --- |
| Proxy Upload | Container payload sent through a proxy outbound |
| Proxy Download | Proxy payload delivered to the container |
| Direct Upload | Container traffic forwarded normally or bypassed by sing-box |
| Direct Download | Direct traffic delivered to the container |

Empty or `0` means unlimited. Nonzero limits accept `0.01`–`10000` Mbps. **Reset
limits** clears the inputs; **Save container settings** applies the reset.

All managed IPv4 addresses of one container share the same four rate buckets,
even when the container is attached to multiple bridges. Limits use nftables
byte policing: excess packets are dropped rather than queued. Payload throughput
can be below the configured cap because of protocol overhead, retransmissions
and application behavior. Local host services are excluded. The engine reports
actual proxy/direct attribution using one-second connection samples; until a
flow is classified, the stricter applicable nonzero limit is used. See the
[device guide](devices.md) for the classification details.

## Settings and discovery

Policies live in `state.json` under `container_settings` and are included in
backups. They are keyed by a stable identity derived from Compose project,
service and replica number, or the container name for other containers. An IP
change or recreation with the same identity keeps the policy. Renaming a
standalone container or changing a Compose identity creates a new policy target.

Network changes take effect on the next discovery check. Until then, an old
endpoint retains its previous rules; fixed Docker addresses avoid IP reuse
during that interval. Successful discovery removes rules for endpoints that disappeared. Saved
policies remain available if the same identity returns. An unavailable Docker
API keeps the last successfully applied inventory and reports an error; settings
changes wait for a successful refresh. Initial discovery failure cannot apply
saved policies until Docker becomes available. Discovery pauses policy application
during conflicting background jobs and retries on the next check.

If a pinned node is removed, the container returns to Global Default while its
proxy preference and speed limits remain saved. At most 256 saved container
policies and 256 managed container IPv4 endpoints are supported, with a combined
maximum of 256 limited device/container addresses.

## Network limitations

Only running containers with private IPv4 endpoints on local, rootful
**bridge** networks can be
controlled independently. Stopped containers are visible but cannot be edited
until running. Host networking, shared container namespaces, rootless Docker,
overlays and non-bridge drivers are shown with an explanation. Ambiguous shared
IPs are rejected. Disable container IPv6: these rules do not intercept IPv6,
and IPv6-enabled endpoints are reported as unsupported.

Docker's embedded DNS resolver can send upstream queries from the host; a shared
DNS server also loses the originating container's identity. Such queries follow
the resolver's routing, not the container's assigned node. This feature does not
rewrite container DNS settings. Containers kept Direct should receive real DNS
answers rather than FakeIP addresses. Configure the desired resolver separately and
consult [DNS & FakeDNS](dns.md). A container assigned Direct can still depend on
a shared DNS resolver configured to require the proxy.

HooLAN must run in the host namespace and transparent sockets must be reachable
through the host firewall. If proxy routing fails, verify the displayed bridge
and IP, the engine status, and `sudo nft list table inet proxy_tproxy`.
Do not run `flush ruleset`: Docker and the host firewall use the same kernel
ruleset.
