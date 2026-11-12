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

scp -O build/vbanhub-aarch64 "$HOST":/usr/sbin/vbanhub
scp -O package/vbanhub/files/vbanhub.init "$HOST":/etc/init.d/vbanhub
ssh "$HOST" '[ -f /etc/config/vbanhub ]' || scp -O package/vbanhub/files/vbanhub.config "$HOST":/etc/config/vbanhub
ssh "$HOST" 'mkdir -p /www/luci-static/resources/view/vbanhub'
scp -O $P/root/usr/share/luci/menu.d/luci-app-vbanhub.json "$HOST":/usr/share/luci/menu.d/
scp -O $P/root/usr/share/rpcd/acl.d/luci-app-vbanhub.json "$HOST":/usr/share/rpcd/acl.d/
scp -O $P/htdocs/luci-static/resources/view/vbanhub/hub.js "$HOST":/www/luci-static/resources/view/vbanhub/hub.js

ssh "$HOST" 'chmod 755 /usr/sbin/vbanhub /etc/init.d/vbanhub &&
	rm -rf /tmp/luci-indexcache* /tmp/luci-modulecache &&
	/etc/init.d/rpcd reload'
echo "deployed to $HOST (service disabled)"
