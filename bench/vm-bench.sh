#!/bin/sh
# Hub latency / CPU benchmark. Runs as root inside a throwaway VM (virtme-ng), never on a real host:
#   sudo vng -r /boot/vmlinuz-$(uname -r) --memory 2G --cpus 4 --exec "sh $PWD/bench/vm-bench.sh [modes]"
# modes: any of "fwd user ebpf" (default: all that are built).
#
# Topology: netns "src" (10.0.1.2) --veth-- hub (root ns: 10.0.1.1 | 10.0.2.1) --veth-- netns "dst" (10.0.2.2).
# fwd  = no hub: the sender sends straight to the receivers and the hub box only IP-forwards (floor).
# user = vbanhub (userspace) on :6980.
# ebpf = vbanhub with the tc eBPF fast path (vbanhub.bpf.o).
set -e
D=$(cd "$(dirname "$0")" && pwd)
HUB=$D/../package/vbanhub/src
B=$D/hubbench
MODES=${1:-"fwd user ebpf"}
T=/tmp/vbench; mkdir -p $T

. $D/vm-net.sh

busy() { awk '/^cpu /{print $2+$3+$4+$7+$8}' /proc/stat; }
softirq() { awk '/^cpu /{print $8}' /proc/stat; }

# conf <streams> <fanout>: stream BenchI from 10.0.1.2 -> 10.0.2.2:17000+j named "Out"
conf() {
	: > $T/hub.conf
	s=0; while [ $s -lt $1 ]; do
		j=0; while [ $j -lt $2 ]; do
			printf 'route\t10.0.1.2\tBench%d\t10.0.2.2\t%d\tOut\n' $s $((17000 + j)) >> $T/hub.conf
			j=$((j + 1)); done
		s=$((s + 1)); done
}

hub_start() { # $1 = user|ebpf
	if [ "$1" = ebpf ]; then
		tc qdisc add dev hs clsact
		tc filter add dev hs ingress bpf direct-action obj $HUB/vbanhub.bpf.o sec tc
		$HUB/vbanhub -p 6980 -c $T/hub.conf -s $T/status.json -B /sys/fs/bpf/tc/globals &
	else
		$HUB/vbanhub -p 6980 -c $T/hub.conf -s $T/status.json &
	fi
	HUBPID=$!
	sleep 0.5
}
hub_stop() {
	kill $HUBPID 2>/dev/null; wait $HUBPID 2>/dev/null || true
	tc qdisc del dev hs clsact 2>/dev/null || true
	rm -rf /sys/fs/bpf/tc/globals/vbanhub_* 2>/dev/null || true
}
hub_cpu() { awk '{print $14+$15}' /proc/$HUBPID/stat; }

# run <mode> <label> <streams> <pps> <fanout> <secs>
run() {
	mode=$1; label=$2; ns=$3; pps=$4; fo=$5; secs=$6
	conf $ns $fo
	if [ $mode = fwd ]; then dport=17000; else dport=6980; hub_start $mode; fi
	ip netns exec dst $B rx 17000 $fo $((secs + 1)) > $T/rx.txt &
	RX=$!
	sleep 0.3
	b0=$(busy); s0=$(softirq); h0=0; [ $mode = fwd ] || h0=$(hub_cpu)
	if [ $mode = fwd ]; then
		# no hub: the sender itself has to send one copy per receiver port
		P=""; j=0; while [ $j -lt $fo ]; do
			ip netns exec src $B tx 10.0.2.2 $((17000 + j)) $ns $pps $secs > /dev/null &
			P="$P $!"; j=$((j + 1)); done
		wait $P
	else
		ip netns exec src $B tx 10.0.1.1 6980 $ns $pps $secs > /dev/null
	fi
	b1=$(busy); s1=$(softirq); h1=0; [ $mode = fwd ] || h1=$(hub_cpu)
	wait $RX || true
	[ $mode = fwd ] || { [ -f $T/status.json ] && grep -o '"tx":[0-9]*' $T/status.json | head -1 > $T/hubtx.txt || true; hub_stop; }
	inpps=$((ns * pps))
	printf '%-5s %-8s in %6d pps x%d | %s | cpu %d%% of 1 core (softirq %d%%), hub proc %d%%\n' \
		$mode $label $inpps $fo "$(cat $T/rx.txt)" \
		$(( (b1 - b0) * 100 / secs / 100 )) $(( (s1 - s0) * 100 / secs / 100 )) $(( (h1 - h0) * 100 / secs / 100 ))
}

for m in $MODES; do
	[ $m = ebpf ] && [ ! -f $HUB/vbanhub.bpf.o ] && continue
	run $m light 1 750 2 10
	run $m medium 8 750 4 10
	run $m heavy 64 750 4 10
done
echo BENCH_DONE
