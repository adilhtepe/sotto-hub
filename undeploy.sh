#!/bin/sh
# Remove everything deploy.sh installed (keeps /etc/config/vbanhub unless PURGE=1).
HOST=${HOST:-openwrt}
ssh "$HOST" '/etc/init.d/vbanhub stop 2>/dev/null; /etc/init.d/vbanhub disable 2>/dev/null
	rm -f /usr/sbin/vbanhub /etc/init.d/vbanhub /usr/share/luci/menu.d/luci-app-vbanhub.json \
	      /usr/share/rpcd/acl.d/luci-app-vbanhub.json /etc/umdns/vbanhub.json
	rm -rf /www/luci-static/resources/view/vbanhub /var/run/vbanhub /var/etc/vbanhub.conf
	'"${PURGE:+rm -f /etc/config/vbanhub;}"'
	rm -rf /tmp/luci-indexcache* /tmp/luci-modulecache; /etc/init.d/rpcd reload'
echo "removed from $HOST"
