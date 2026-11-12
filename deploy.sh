#!/bin/sh
# Cross-build (static aarch64) and install vbanhub + LuCI app on the router (ssh alias "openwrt").
# The service is installed DISABLED (/etc/config/vbanhub: enabled '0'); nothing starts until you enable it.
set -e
cd "$(dirname "$0")"
HOST=${HOST:-openwrt}
CC=${CC:-aarch64-linux-gnu-gcc}
P=package/luci-app-vbanhub

mkdir -p build
$CC -Os -static -s -Wall -Wextra -ffunction-sections -fdata-sections -Wl,--gc-sections \
	-o build/vbanhub-aarch64 package/vbanhub/src/vbanhub.c

clang -O2 -g -Wall -target bpfel -I/usr/include/$(uname -m)-linux-gnu -c package/vbanhub/src/vbanhub.bpf.c -o build/vbanhub.bpf.o   # little-endian (aarch64)

scp -O build/vbanhub-aarch64 "$HOST":/usr/sbin/vbanhub.new   # moved into place below (a running binary cannot be overwritten)
# Kernel fast path: used only if the router has tc with eBPF support (tc-bpf / tc-full, kmod-sched-bpf).
ssh "$HOST" 'mkdir -p /lib/bpf' && scp -O build/vbanhub.bpf.o "$HOST":/lib/bpf/vbanhub.o
scp -O package/vbanhub/files/vbanhub.init "$HOST":/etc/init.d/vbanhub
ssh "$HOST" '[ -f /etc/config/vbanhub ]' || scp -O package/vbanhub/files/vbanhub.config "$HOST":/etc/config/vbanhub
ssh "$HOST" 'mkdir -p /www/luci-static/resources/view/vbanhub'
scp -O $P/root/usr/share/luci/menu.d/luci-app-vbanhub.json "$HOST":/usr/share/luci/menu.d/
scp -O $P/root/usr/share/rpcd/acl.d/luci-app-vbanhub.json "$HOST":/usr/share/rpcd/acl.d/
scp -O $P/htdocs/luci-static/resources/view/vbanhub/hub.js "$HOST":/www/luci-static/resources/view/vbanhub/hub.js

ssh "$HOST" 'chmod 755 /usr/sbin/vbanhub.new /etc/init.d/vbanhub &&
	mv /usr/sbin/vbanhub.new /usr/sbin/vbanhub &&
	/etc/init.d/vbanhub enable &&	# start at boot; the UCI "enabled" flag decides whether it runs
	rm -rf /tmp/luci-indexcache* /tmp/luci-modulecache &&
	/etc/init.d/rpcd reload &&
	/etc/init.d/vbanhub restart'   # start_service honours the UCI enabled flag and prunes orphan routes
echo "deployed to $HOST (installed service is enabled at boot; it runs only if UCI vbanhub.main.enabled=1)"
