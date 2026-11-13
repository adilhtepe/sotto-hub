#!/bin/sh
# Secure VBAN over a simulated internet, inside a throwaway VM (virtme-ng):
#   sudo vng -r /boot/vmlinuz-$(uname -r) --memory 2G --cpus 2 --exec "sh $PWD/bench/vm-internet-test.sh <SDK build dir>"
#
#   lanhost 10.0.2.2 --lan-- HUB (root ns) --wan 203.0.113.1-- inet (delay 25 ms +-8 ms, 1 % loss)
#        --198.51.100.1-- natbox 198.51.100.2 [masquerade, UDP mappings expire after 20 s]
#        --192.168.50.1-- remote 192.168.50.2 (a device at home, behind NAT)
#
# The hub runs with -i lan -W wan: plain VBAN on the LAN, secure VBAN only from the internet.
D=$(cd "$(dirname "$0")" && pwd)
HUB=$D/../package/vbanhub/src/vbanhub
SDK=$(cd "$1" && pwd)
T=/tmp/vinet; rm -rf $T; mkdir -p $T; cd $T
modprobe nf_conntrack 2>/dev/null
FAIL=0
check() { if eval "$2"; then echo "PASS $1"; else echo "FAIL $1"; FAIL=1; fi; }
in_() { ns=$1; shift; ip netns exec $ns "$@"; }

ip link set lo up
for n in lanhost inet natbox remote; do ip netns add $n; ip -n $n link set lo up; done
ip link add lan address 02:00:00:00:0a:01 type veth peer name l0 address 02:00:00:00:0a:02 netns lanhost
ip link add wanx address 02:00:00:00:0b:01 type veth peer name i0 address 02:00:00:00:0b:02 netns inet
ip -n inet link add i1 address 02:00:00:00:0c:01 type veth peer name n0 address 02:00:00:00:0c:02 netns natbox
ip -n natbox link add n1 address 02:00:00:00:0d:01 type veth peer name r0 address 02:00:00:00:0d:02 netns remote
ip addr add 10.0.2.1/24 dev lan; ip link set lan up
ip addr add 203.0.113.1/24 dev wanx; ip link set wanx up
in_ lanhost ip addr add 10.0.2.2/24 dev l0; in_ lanhost ip link set l0 up; in_ lanhost ip route add default via 10.0.2.1
in_ inet ip addr add 203.0.113.2/24 dev i0; in_ inet ip link set i0 up
in_ inet ip addr add 198.51.100.1/24 dev i1; in_ inet ip link set i1 up
in_ natbox ip addr add 198.51.100.2/24 dev n0; in_ natbox ip link set n0 up; in_ natbox ip route add default via 198.51.100.1
in_ natbox ip addr add 192.168.50.1/24 dev n1; in_ natbox ip link set n1 up
in_ remote ip addr add 192.168.50.2/24 dev r0; in_ remote ip link set r0 up; in_ remote ip route add default via 192.168.50.1
ip route add 198.51.100.0/24 via 203.0.113.2
for n in inet natbox; do in_ $n sysctl -qw net.ipv4.ip_forward=1; done
cat > nat.nft <<'NFT'
table ip nat {
	chain post {
		type nat hook postrouting priority 100; policy accept;
		oifname "n0" masquerade
	}
}
NFT
in_ natbox nft -f nat.nft || echo "FAIL nat setup"
in_ natbox sysctl -qw net.netfilter.nf_conntrack_udp_timeout=20 net.netfilter.nf_conntrack_udp_timeout_stream=20
# the internet: latency, jitter and loss both ways
in_ inet tc qdisc add dev i0 root netem delay 25ms 8ms distribution normal loss 1%
in_ inet tc qdisc add dev i1 root netem delay 25ms 8ms distribution normal loss 1%
in_ remote ping -c2 -W2 203.0.113.1 >/dev/null && echo "remote reaches the hub through NAT"

# PKI on the hub; device keys and certificates made on the devices, signed by the hub's CA
export VBANHUB_PKI=$T/pki
$HUB cert init "Test CA" 1 "Hub" >/dev/null
$HUB cert export-ca > ca.crt
for d in Mic:tx Listener:rx; do
	n=${d%:*}; r=${d#*:}
	$SDK/vban_cert key $n.key >/dev/null; $SDK/vban_cert req $n.key $n $r $n.req
	$HUB cert sign $n.req 2 > $n.crt
done
chmod 755 $T; chmod 644 $T/*.crt
printf 'master\t100\nroute\t*\tStream1\t10.0.2.2\t17101\tFromInternet\t100\tMic\t\nroute\t10.0.2.2\tLanSrc\t*\t0\tToInternet\t100\t\tListener\n' > hub.conf
$HUB -p 6980 -c hub.conf -s status.json -i lan -W wanx -K $T/pki 2>hub.log &
HUBPID=$!
sleep 0.5

# 1) device behind NAT sends secure audio to a plain receiver on the hub's LAN (with copies -R 4)
in_ lanhost timeout -s INT 9 $SDK/vban_recv -p 17101 -n FromInternet -l 40 > lan.raw 2> lan.err &
sleep 0.3
in_ remote timeout -s INT 7 $SDK/vban_send -i 203.0.113.1 -n Stream1 -R 4 --ca ca.crt --cert Mic.crt --key Mic.key 2> mic.err
sleep 2
tr '\r' '\n' < lan.err | grep -v '^$' | tail -1
python3 -I - lan.raw > lan.res <<'PY'
import struct, sys
d = open(sys.argv[1], 'rb').read(); s = struct.unpack('<%dh' % (len(d) // 2), d)
nz = [x for x in s if x]; print(len(s), len(nz), max(abs(x) for x in s) if s else 0)
PY
read total nz peak < lan.res
check "internet -> NAT -> hub -> LAN (secure in, plain out)" "[ $nz -gt 300000 ] && [ $peak -eq 8192 ]"

# 2) device behind NAT that only receives: keepalives hold the 20 s NAT mapping open for 70 s
in_ remote timeout -s INT 75 $SDK/vban_recv -p 17102 -n ToInternet -q -l 40 --hub 203.0.113.1 \
	--ca ca.crt --cert Listener.crt --key Listener.key > far.raw 2> far.err &
sleep 2
in_ lanhost timeout -s INT 72 $SDK/vban_send -i 10.0.2.1 -n LanSrc >/dev/null 2>&1
sleep 2
python3 -I - far.raw <<'PY' > far.res
import struct, sys
d = open(sys.argv[1], 'rb').read(); s = struct.unpack('<%dh' % (len(d) // 2), d)
sec = 48000 * 2
last = s[-12 * sec:-2 * sec]            # seconds 60..70 of the stream
print(len(s) // sec, sum(1 for x in last if x), max(abs(x) for x in s) if s else 0)
PY
read secs lastnz peak < far.res
echo "far receiver: $secs s of audio, nonzero samples in the last 10 s: $lastnz"
check "receive-only device behind NAT still fed after 70 s (keepalive)" "[ $lastnz -gt 400000 ]"

# 3) the internet cannot use plain VBAN or pings
in_ inet python3 -I - > ping.txt <<'PY'
import socket, struct
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM); s.settimeout(1)
for fc in range(50):
    s.sendto(b"VBAN" + bytes([3, 63, 1, 1]) + b"LanSrc".ljust(16, b"\0") + struct.pack("<I", fc) + bytes(256), ("203.0.113.1", 6980))
s.sendto(b"VBAN" + bytes([0x60, 0, 0, 0]) + b"VBAN Service".ljust(16, b"\0") + struct.pack("<I", 1) + bytes(676), ("203.0.113.1", 6980))
try:
    s.recvfrom(2048); print("ping answered")
except socket.timeout:
    print("ping not answered")
PY
in_ inet true > /dev/null; true
sleep 2.5
# (1 % of these 51 packets may be lost on the simulated internet itself)
check "plain VBAN and pings from the internet refused, none routed" \
	"python3 -I -c \"import json,sys; s=json.load(open('status.json')); r=[x for x in s['routes'] if x['src_cert']==''][0]; sys.exit(0 if 45 <= s['wan_refused'] <= 51 and r['pkts'] > 0 and s['unknown'] == 0 else 1)\" && grep -q 'ping not answered' ping.txt"
python3 -I -c "import json; s=json.load(open('status.json')); print('hub: wan_refused', s['wan_refused'], 'secure', {k: v for k, v in s['secure'].items() if k != 'peers'})"

kill $HUBPID; wait $HUBPID 2>/dev/null
[ $FAIL = 0 ] && echo "ALL PASS" || echo "SOME FAILED"
