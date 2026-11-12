#!/bin/sh
# Correctness of the tc eBPF fast path, inside a throwaway VM (virtme-ng):
#   sudo vng -r /boot/vmlinuz-$(uname -r) --memory 2G --cpus 4 --exec "sh $PWD/bench/vm-ebpf-test.sh"
D=$(cd "$(dirname "$0")" && pwd)
HUB=$D/../package/vbanhub/src
B=$D/hubbench
T=/tmp/vtest; mkdir -p $T; chmod 777 $T
FAIL=0
. $D/vm-net.sh
# The receiver verifies UDP checksums in software (no "hardware already checked it").
ip netns exec dst ethtool -K d0 rx off >/dev/null 2>&1 || true
csumerr() { ip netns exec dst awk '/^Udp:/{n++} n==2 && /^Udp:/{print $8; exit}' /proc/net/snmp; }
gstat() { bpftool map dump pinned /sys/fs/bpf/tc/globals/vbanhub_gstat -j 2>/dev/null | python3 -c "
import json,sys; d=json.load(sys.stdin); n=['rx','tx','slow','nofib','txerr','gso']
print(' '.join('%s=%d'%(n[e['key'] if isinstance(e['key'],int) else int.from_bytes(bytes(int(x,16) for x in e['key']),'little')], sum(v['value'] if isinstance(v['value'],int) else int.from_bytes(bytes(int(x,16) for x in v['value']),'little') for v in e['values'])) for e in d))"; }
check() { # name, condition
	if eval "$2"; then echo "PASS $1"; else echo "FAIL $1"; FAIL=1; fi
}

tc qdisc add dev hs clsact
tc filter add dev hs ingress bpf direct-action obj $HUB/vbanhub.bpf.o sec tc || { echo "FAIL load"; exit 1; }
echo "loaded: $(bpftool prog show | grep -c vbanhub_ingres) program"
{
	printf 'master\t100\n'
	printf 'route\t10.0.1.2\tBench0\t10.0.2.2\t17000\tOut\n'      # rename
	printf 'route\t10.0.1.2\tBench0\t10.0.2.2\t17001\t*\n'        # keep the sender's name
	printf 'route\t10.0.1.2\t*\t10.0.2.2\t17002\tAny\n'           # any-name key, same source
	printf 'route\t*\tBench0\t10.0.2.2\t17003\tWild\n'            # any-source key
	printf 'route\t10.0.1.2\tBench1\t10.0.2.2\t17004\tSlow\t50\n' # gain 50 %: daemon path
} > $T/hub.conf
chmod 644 $T/hub.conf
# as on the router: started as root, runs as nobody keeping only CAP_BPF
$HUB/vbanhub -p 6980 -c $T/hub.conf -s $T/status.json -B /sys/fs/bpf/tc/globals -U nobody &
HUBPID=$!
sleep 1

# 1) fast path, checksums verified by the receiver (sender computes full checksums: tx off)
e0=$(csumerr)
ip netns exec dst $B rx 17000 4 3 Out,Bench0,Any,Wild > $T/rx1.txt &
sleep 0.3; ip netns exec src $B tx 10.0.1.1 6980 1 750 2 > /dev/null; wait $!
sleep 1.5; cat $T/rx1.txt; echo "  kernel: $(gstat)  csum errors: $(( $(csumerr) - e0 ))"
check "fan-out 4 destinations, names per route" "grep -q 'rx: 6004 packets, lost 0, bad name 0' $T/rx1.txt"
check "UDP checksums valid (full-checksum sender)" "[ $(( $(csumerr) - e0 )) -eq 0 ]"
check "handled in the kernel" "gstat | grep -q 'tx=6004'"

# 2) same with checksum offload on the sender (CHECKSUM_PARTIAL skbs)
ip netns exec src ethtool -K s0 tx on >/dev/null 2>&1
ip netns exec dst $B rx 17000 4 3 Out,Bench0,Any,Wild > $T/rx2.txt &
sleep 0.3; ip netns exec src $B tx 10.0.1.1 6980 1 750 2 > /dev/null
sleep 1.5; cat $T/rx2.txt
check "fan-out with offloaded checksums" "grep -q 'rx: 6004 packets, lost 0, bad name 0' $T/rx2.txt"
ip netns exec src ethtool -K s0 tx off >/dev/null 2>&1

# 3) gain route: the daemon handles it (and still delivers)
# (the latency column is meaningless here: the gain scales the timestamp too)
ip netns exec dst $B rx 17004 1 3 Slow > $T/rx3.txt &
sleep 0.3
ip netns exec src python3 - <<'PY'
import socket, struct, time
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
for fc in range(300):
    hdr = b"VBAN" + bytes([3, 63, 1, 1]) + b"Bench1".ljust(16, b"\0") + struct.pack("<I", fc)
    s.sendto(hdr + struct.pack("<QI", time.monotonic_ns(), 0) + bytes(244), ("10.0.1.1", 6980)); time.sleep(0.002)
PY
sleep 2.5; cat $T/rx3.txt
check "gain route served by the daemon" "grep -q 'rx: 300 packets, lost 0, bad name 0' $T/rx3.txt && gstat | grep -q 'slow=300'"

# 4) status JSON merges the kernel's counters
sleep 2.5
python3 - $T/status.json <<'PY' && echo "PASS status merges kernel counters" || { echo "FAIL status"; }
import json, sys
s = json.load(open(sys.argv[1]))
r = {x["dst_port"]: x for x in s["routes"]}
assert r[17000]["pkts"] == 3002 and r[17000]["lost"] == 0 and r[17000]["age"] >= 0, r[17000]
assert r[17004]["pkts"] == 300, r[17004]
st = {x["stream"]: x for x in s["streams"]}
assert st["Bench0"]["pkts"] == 3002 and st["Bench0"]["routed"] == 1 and st["Bench0"]["hz"] == 48000, st["Bench0"]
assert s["fastpath"]["on"] == 1 and s["fastpath"]["to_daemon_gain"] == 300, s["fastpath"]
print("  tx", s["tx"], "rx", s["rx"], "fastpath", s["fastpath"])
PY

# 5) unrouted sender and PING0 still reach the daemon
ip netns exec src python3 - <<'PY'
import socket, struct
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
s.sendto(b"VBAN" + bytes([3, 63, 1, 1]) + b"Nobody".ljust(16, b"\0") + bytes(4) + bytes(64), ("10.0.1.1", 6980))
s.settimeout(2)
ping = b"VBAN" + bytes([0x60, 0, 0, 0]) + b"VBAN Service".ljust(16, b"\0") + struct.pack("<I", 7) + bytes(676)
s.sendto(ping, ("10.0.1.1", 6980))
d, _ = s.recvfrom(2048)
assert d[:4] == b"VBAN" and d[4] == 0x60 and d[5] == 0x80 and d[24:28] == struct.pack("<I", 7), d[:28]
print("PASS PING0 answered by the daemon")
PY
sleep 2.5
check "unrouted sender listed" "grep -q '\"stream\":\"Nobody\"' $T/status.json"

# 6) reload (SIGHUP) swaps the map without losing packets
ip netns exec dst $B rx 17000 1 4 Out > $T/rx6.txt &
sleep 0.3
ip netns exec src $B tx 10.0.1.1 6980 1 750 3 > /dev/null &
TX=$!
for i in 1 2 3 4 5 6 7 8 9 10; do kill -HUP $HUBPID; sleep 0.2; done
# a reload as nobody really rewrote the map: drop the 17003 route, the kernel must stop sending there
grep -v 17003 $T/hub.conf > $T/hub2.conf; cat $T/hub2.conf > $T/hub.conf; kill -HUP $HUBPID; sleep 0.5
wait $TX; sleep 1.5; cat $T/rx6.txt
ip netns exec dst $B rx 17003 1 2 > $T/rx7.txt &
sleep 0.3; ip netns exec src $B tx 10.0.1.1 6980 1 750 1 > /dev/null; sleep 1
check "route removed by a reload (map updated as nobody)" "grep -q 'rx: no packets' $T/rx7.txt" 
check "hub runs as nobody with CAP_BPF only" "[ \"\$(awk '/^Uid/{print \$2}' /proc/$HUBPID/status)\" != 0 ] && grep -q 'CapEff:.*0000008000000000' /proc/$HUBPID/status"
check "10 reloads during streaming, nothing lost" "grep -q 'rx: 2251 packets, lost 0' $T/rx6.txt"

kill $HUBPID; wait $HUBPID 2>/dev/null
tc qdisc del dev hs clsact
dmesg | grep -iE "bug|warn|oops|bpf" | grep -v "BPF JIT\|bpf_jit" | head
[ $FAIL = 0 ] && echo "ALL PASS" || echo "SOME FAILED"
