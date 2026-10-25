# Install HooLAN

[Home](../README.md) · [Documentation](../README.md#documentation)

## Requirements and topology

Use Debian, systemd and root access for firewall management.
Install Go and [sing-box with Clash API support](https://sing-box.sagernet.org/installation/package-manager/).
HooLAN targets sing-box 1.14 configuration and owns its child engine process.
Do not run a separate sing-box service on the same listeners.

Examples use a Debian host `192.168.3.5`, upstream router `192.168.3.1`, LAN `192.168.3.0/24`,
interface `eth0`, dashboard `8080`, TPROXY `7892` and Clash `127.0.0.1:9090`.
Substitute your actual values.

## Build

```bash
sudo apt-get update
sudo apt-get install nftables iproute2 procps util-linux ca-certificates curl
CGO_ENABLED=0 go build -trimpath -ldflags='-s -w' -o hoolan ./cmd/server
```

The build targets the machine running Go. For cross-compilation, set `GOOS=linux`
and `GOARCH=amd64` or `GOARCH=arm64` to match the target host. There is no npm step and no
external Go module to download. If a standalone sing-box systemd unit is active,
stop and disable it before letting HooLAN own the engine.

## Install the service files

These commands install the supplied configuration templates. Set secrets and
site values before starting the service.

```bash
sudo install -Dm755 hoolan /opt/hoolan/hoolan
for script in apply.sh remove.sh diagnose.sh install-router.sh; do
  sudo install -Dm755 "scripts/tproxy/$script" "/opt/hoolan/scripts/tproxy/$script"
done
sudo install -Dm644 scripts/tproxy/tproxy.nft.template /opt/hoolan/scripts/tproxy/tproxy.nft.template
sudo install -Dm600 scripts/tproxy/tproxy.conf /opt/hoolan/scripts/tproxy/tproxy.conf
sudo install -d -m700 /var/lib/hoolan /etc/hoolan/singbox
sudo install -m600 deploy/hoolan.env.example /etc/hoolan/env
sudoedit /etc/hoolan/env
sudoedit /opt/hoolan/scripts/tproxy/tproxy.conf
```

Set independent random values for `HOOLAN_TOKEN` (dashboard/API) and
`HOOLAN_CLASH_SECRET` (engine control API).

For example, generate each with
`openssl rand -hex 32` if OpenSSL is installed. `HOOLAN_SUBS` optionally supplies
initial subscription URLs; the UI can manage subscriptions without it.

Use literal assignments in `tproxy.conf`, with no inline comments:

```bash
LAN_IF="eth0"
TPROXY_PORT="7892"
TPROXY_FWMARK="0x1"
TPROXY_TABLE="100"
TPROXY_RULE_PRIORITY="10000"
PI_LAN_IP="192.168.3.5"
SELF_ORIGIN_NETS=""
WG_RP_FILTER="yes"
```

## Establish routing before interception

A LAN client using the Debian host as its gateway needs IPv4 forwarding, an upstream
route and a return route or scoped NAT, even with the proxy engine OFF.

For a **single-interface Debian host with UFW already active**, the supplied installer
requires Python 3 and writes backed-up UFW rules plus persistent sysctls:

```bash
sudo env LAN_IF=eth0 LAN_CIDR=192.168.3.0/24 TPROXY_FWMARK=0x1 \
  bash /opt/hoolan/scripts/tproxy/install-router.sh
```

It configures scoped forwarding/MASQUERADE, marked TCP/UDP INPUT exceptions,
IPv4 forwarding, reverse-path settings and disabled redirects. Use the same
mark as `tproxy.conf`. For two interfaces or another firewall manager, configure
these functions through that firewall instead of running this installer unchanged.
An explicit return route can replace NAT.

Test a single client with the engine OFF before changing DHCP for the whole LAN.

## Start and sign in

```bash
sudo install -m644 deploy/hoolan.service /etc/systemd/system/hoolan.service
sudo systemctl daemon-reload
sudo systemctl enable --now hoolan
```

The supplied unit binds to loopback. From your workstation:

```bash
ssh -N -L 8080:127.0.0.1:8080 user@192.168.3.5
```

Open `http://127.0.0.1:8080/`, sign in with `HOOLAN_TOKEN`, Point DHCP's IPv4 gateway option at the host
only after testing. Advertise the host as DNS only if a resolver listens there.
Plan IPv6 RA/DHCPv6 separately.

## HTTPS access

Use a trusted HTTPS reverse proxy.

Add `-secure-cookies` to the service's `ExecStart` for HTTPS-only browser access.
Reload systemd and restart after editing the unit.

## Updating an installation

Download a backup of your data from the UI.

 build a new executable:
 ```bash
CGO_ENABLED=0 go build -trimpath -ldflags='-s -w' -o hoolan ./cmd/server
```
stop `hoolan`, replace the executable and firewall helpers/template, then start it again:

```bash
sudo systemctl stop hoolan
sudo cp hoolan /opt/hoolan/hoolan
sudo cp scripts/tproxy/* /opt/hoolan/scripts/tproxy/
sudo chmod +x /opt/hoolan/scripts/tproxy/*.sh
sudo systemctl start hoolan
```

 Preserve the live `env`,
`tproxy.conf` and state files. If the unit changes, install it and run:
```bash
systemctl daemon-reload
```

## Docker container management

The Containers tab reads `/var/run/docker.sock` on the local host. The supplied
root systemd service can access the standard socket. Configure another local
socket with `HOOLAN_DOCKER_SOCKET=/absolute/path/docker.sock` in the environment
file, or the `-docker-socket` flag. An empty value disables discovery. Docker
being absent does not prevent the rest of HooLAN from starting.

The gateway must run in the host network namespace; supported containers use
rootful IPv4 bridge networking. Update both firewall helpers and the executable
when installing this feature. Read [Docker containers](containers.md) before
enabling per-container interception.
