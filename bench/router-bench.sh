#!/bin/sh
# Hub latency / CPU on the real router, from a wired LAN host (this machine):
#   bench/router-bench.sh [modes] [loads]      e.g.  bench/router-bench.sh "user ebpf" "light medium heavy"
# Sender and receiver are this host (one clock), the hub fans out back to it. Bench routes are
# appended to the daemon's generated config (/var/etc/vbanhub.conf) and SIGHUPed in; the live
# routes keep running, and the original file is restored at the end. UCI is never touched.
# "user" detaches the tc program (the daemon forwards everything), "ebpf" re-attaches it.
set -e
D=$(cd "$(dirname "$0")" && pwd)
HOST=${HOST:-openwrt}
ME=${ME:-$(ip route get 192.168.2.1 | sed -n 's/.* src \([0-9.]*\).*/\1/p')}
HUBIP=${HUBIP:-192.168.2.1}
DEV=${DEV:-br-lan}
MODES=${1:-"user ebpf"}
LOADS=${2:-"light medium heavy"}
B=$D/hubbench
cc -O2 -o $B $D/hubbench.c

r() { ssh -o BatchMode=yes "$HOST" "$@"; }

r "cp /var/etc/vbanhub.conf /tmp/vbanhub.conf.orig"
trap 'r "cp /tmp/vbanhub.conf.orig /var/etc/vbanhub.conf; kill -HUP \$(pidof vbanhub);
	tc filter replace dev '$DEV' ingress pref 49 handle 1 bpf direct-action obj /lib/bpf/vbanhub.o sec tc" >/dev/null 2>&1' EXIT

conf() { # streams fanout
	{
		r "cat /tmp/vbanhub.conf.orig"
		s=0; while [ $s -lt $1 ]; do
			j=0; while [ $j -lt $2 ]; do
				printf 'route\t%s\tBench%d\t%s\t%d\tOut\n' $ME $s $ME $((17000 + j)); j=$((j + 1)); done
			s=$((s + 1)); done
	} > /tmp/router-bench.conf
	r "cat > /var/etc/vbanhub.conf; kill -HUP \$(pidof vbanhub)" < /tmp/router-bench.conf
}

mode() {
	if [ $1 = user ]; then
		r "tc filter del dev $DEV ingress pref 49 2>/dev/null || true"
	else
		r "tc filter replace dev $DEV ingress pref 49 handle 1 bpf direct-action obj /lib/bpf/vbanhub.o sec tc"
	fi
}

# router counters: busy jiffies (user+nice+sys+irq+softirq), softirq, hub process utime+stime, gro fallbacks
snap() {
	r "awk '/^cpu /{print \$2+\$3+\$4+\$7+\$8, \$8}' /proc/stat; awk '{print \$14+\$15}' /proc/\$(pidof vbanhub)/stat;
	   grep -o '\"to_daemon_gro\":[0-9]*' /var/run/vbanhub/status.json | cut -d: -f2" | tr '\n' ' '
}

run() { # mode label streams pps fanout secs
	conf $3 $5
	sleep 2
	$B rx 17000 $5 $(($6 + 2)) Out > /tmp/router-bench.rx &
	RX=$!
	sleep 0.5
	set -- "$@" $(snap)
	$B tx $HUBIP 6980 $3 $4 $6 > /dev/null
	sleep 2.5   # let the status dump catch up
	set -- "$@" $(snap)
	wait $RX || true
	# $7 busy0 $8 sirq0 $9 hub0 ${10} gro0 ${11} busy1 ${12} sirq1 ${13} hub1 ${14} gro1
	printf '%-5s %-7s %3d str x%d (%6d pkt/s out) | %s | router cpu %3d%% of 1 core (softirq %3d%%), daemon %3d%%, gro->daemon %d\n' \
		$1 $2 $3 $5 $(($3 * $4 * $5)) "$(sed 's/^rx: //' /tmp/router-bench.rx)" \
		$(( (${11} - $7) / ($6 + 3) )) $(( (${12} - $8) / ($6 + 3) )) $(( (${13} - $9) / ($6 + 3) )) $(( ${14} - ${10} ))
}

for m in $MODES; do
	mode $m
	for l in $LOADS; do
		case $l in
		light)  run $m light 1 750 2 10 ;;
		medium) run $m medium 8 750 4 10 ;;
		heavy)  run $m heavy 32 750 4 10 ;;
		max)    run $m max 64 750 4 10 ;;
		esac
	done
done
