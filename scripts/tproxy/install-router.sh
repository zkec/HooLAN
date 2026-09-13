#!/usr/bin/env bash
# One-time persistent single-interface IPv4 router setup for a UFW-managed Pi.
# Does not run from apply/remove: normal forwarding must survive engine OFF.
set -euo pipefail
LAN_IF="${LAN_IF:-eth0}"
LAN_CIDR="${LAN_CIDR:-192.168.3.0/24}"
TPROXY_FWMARK="${TPROXY_FWMARK:-0x1}"
[[ $(id -u) == 0 ]] || { echo 'Run with sudo on the gateway Pi.' >&2; exit 1; }
for tool in python3 ufw sysctl ip; do command -v "$tool" >/dev/null; done
ip link show dev "$LAN_IF" >/dev/null
UFW_STATUS="$(LC_ALL=C ufw status)"
[[ "$UFW_STATUS" == *"Status: active"* ]] || { echo "This installer requires an active UFW firewall." >&2; exit 1; }
python3 - "$LAN_IF" "$LAN_CIDR" "$TPROXY_FWMARK" <<'PY'
import sys,re,ipaddress,pathlib,shutil,datetime
iface,cidr,mark=sys.argv[1:]
if not re.fullmatch(r'(0x[0-9a-fA-F]{1,8}|[1-9][0-9]{0,9})',mark): raise SystemExit('Invalid TPROXY_FWMARK')
mark_number=int(mark,16 if mark.startswith('0x') else 10)
if not 0<mark_number<=0xffffffff: raise SystemExit('Invalid TPROXY_FWMARK')
mark=hex(mark_number)
if not re.fullmatch(r'[A-Za-z0-9_.:-]{1,15}',iface): raise SystemExit('Invalid interface')
net=ipaddress.ip_network(cidr,strict=True)
if net.version!=4 or not net.is_private or net.prefixlen<16: raise SystemExit('Use the actual private IPv4 LAN subnet, /16 or narrower')
p=pathlib.Path('/etc/ufw/before.rules')
s=p.read_text()
shutil.copy2(p,str(p)+'.proxy-manager-'+datetime.datetime.now().strftime('%Y%m%d%H%M%S')+'.bak')
# Remove only our previous managed blocks on reinstallation.
s=re.sub(r'(?ms)^# BEGIN proxy-manager router.*?^# END proxy-manager router\n','',s)
lines=s.splitlines(True);start=next(i for i,l in enumerate(lines) if l.strip()=='*filter')
end=next(i for i in range(start+1,len(lines)) if lines[i].strip()=='COMMIT')
insert=next(i for i in range(start+1,end) if lines[i].startswith('-A '))
rules=f'''# BEGIN proxy-manager router filter
-A ufw-before-input -i {iface} -s {net} -p tcp -m mark --mark {mark}/0xffffffff -j ACCEPT
-A ufw-before-input -i {iface} -s {net} -p udp -m mark --mark {mark}/0xffffffff -j ACCEPT
-A ufw-before-forward -i {iface} -o {iface} -s {net} ! -d {net} -m conntrack --ctstate NEW,ESTABLISHED,RELATED -j ACCEPT
-A ufw-before-forward -i {iface} -o {iface} -d {net} -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT
# END proxy-manager router
'''
lines.insert(insert,rules);s=''.join(lines)
nat=f'''# BEGIN proxy-manager router nat
-A POSTROUTING -s {net} ! -d {net} -o {iface} -j MASQUERADE
# END proxy-manager router
'''
lines=s.splitlines(True)
if any(l.strip()=='*nat' for l in lines):
 start=next(i for i,l in enumerate(lines) if l.strip()=='*nat');end=next(i for i in range(start+1,len(lines)) if lines[i].strip()=='COMMIT');lines.insert(end,nat);s=''.join(lines)
else:s+='\n*nat\n:POSTROUTING ACCEPT [0:0]\n'+nat+'COMMIT\n'
p.write_text(s)
settings=f'''net.ipv4.ip_forward = 1
net.ipv4.conf.all.send_redirects = 0
net.ipv4.conf.default.send_redirects = 0
net.ipv4.conf.{iface}.send_redirects = 0
net.ipv4.conf.all.rp_filter = 0
net.ipv4.conf.{iface}.rp_filter = 0
'''
pathlib.Path('/etc/sysctl.d/90-proxy-manager-router.conf').write_text(settings)
ufw_sysctl=pathlib.Path('/etc/ufw/sysctl.conf')
old=ufw_sysctl.read_text()
shutil.copy2(ufw_sysctl,str(ufw_sysctl)+'.proxy-manager-'+datetime.datetime.now().strftime('%Y%m%d%H%M%S')+'.bak')
old=re.sub(r'(?ms)^# BEGIN proxy-manager router.*?^# END proxy-manager router\n','',old)
ufw_sysctl.write_text(old+'\n# BEGIN proxy-manager router sysctl\n'+settings+'# END proxy-manager router\n')
PY
ufw reload
sysctl -p /etc/sysctl.d/90-proxy-manager-router.conf
echo 'Persistent forwarding/NAT configured. Test a fresh connection with Proxy OFF, then ON.'
echo 'Requires the Pi default route to use the upstream router, not the Pi itself.'
