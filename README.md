# OpenWrt VBAN Hub

A RAM-light VBAN router for OpenWrt. Transmitters send to the router; the router
fans each stream out to any set of receivers, rewriting the VBAN stream name per
receiver. Routing is configured in a LuCI matrix.

## Why there is no "certificate"
VBAN is plain UDP with no handshake, auth or encryption, and existing clients
(VoiceMeeter, VBAN apps) only know IP + port + stream name. So "joining" is:

1. **Enrollment**: you give each endpoint the router IP, hub port and its stream name.
2. **Learn/adopt**: unknown senders appear in LuCI (IP, stream) with an "Adopt" button.
3. **Binding**: a route only matches `(source IP, stream name)`; everything else is
   dropped and shown as "unrouted". For untrusted networks tunnel via WireGuard.

## Boot, port and pings
- The init script is **enabled at boot** (`deploy.sh` / package postinst); whether it actually runs is decided by the UCI `enabled` flag.
- **UDP port in the firewall**: for each selected network the hub opens its port in that network's firewall zone with a managed rule `vbanhub_<zone>` (`open_firewall`, default on). Zones that already ACCEPT input (default `lan`) need none; `wan` and masquerading zones are never opened. Rules are only rewritten when they change and are removed when the hub is disabled.
- **Pings**: full VBAN PING0 requests (header + 676-byte struct) get a reply (device `OpenWrt VBAN hub`, app `vbanhub`, type SERVER). `test/ping_hub.py <ip>` checks it.

## Devices and interfaces in LuCI
- **Listen on networks**: multi-select of your OpenWrt networks (lan, guest, ...).
- **Devices connected to this router**: DHCP/neighbour hosts from `luci-rpc getHostHints`; **Add…** opens a dialog where you set name, role (receiver/transmitter), IP, port and stream name freely.
- Test: `test/test_iface.py <binary>`.

## LAN discovery (VBAN PING0)
The hub can find receivers and transmitters on the LAN using VB-Audio's service/identification ping
(spec rev 13: header sub-protocol 0x60 + 676-byte `tagVBAN_PING0`). Press **Scan LAN** in LuCI (or
`/etc/init.d/vbanhub scan`, or set `scan_interval`). It broadcasts to 255.255.255.255 and the LAN
broadcast address on `scan_ports` (default 6980), plus unicast `scan_target`s for hosts that do not
see broadcasts. Replies must echo the request id and arrive within 5 s, so spoofed unsolicited replies are
ignored. Replies show IP:port, host, application, and type (receiver/transmitter/...), with one-click
**Add as receiver / transmitter**. The hub also answers pings from others (full packets only, 20/s max).
Limits: PING0 does not carry stream names, so receivers get a placeholder `Stream1` to edit; transmitters
reuse the stream name heard in "Unrouted senders" when available. Only devices that implement PING answer.
Test: `test/test_discovery.py <binary>`; demo device: `test/fake_endpoint.py`.

## Layout
- `package/vbanhub/` daemon (C, ~8 KB text, ~50 KB static BSS), UCI config, procd init
- `package/luci-app-vbanhub/` LuCI JS view, menu + ACL
- `test/test_fanout.py` loopback test (fan-out, rewrite, loss counting, learn)

## Data path
`poll` + `recvmmsg` (16 pkts) -> match routes -> `sendmmsg` with iovec
`[rewritten 28-byte header][shared payload]`. No payload copy, no malloc, no audio
decoding, no buffering (receivers keep their own jitter buffers). Outgoing DSCP EF.

## Config flow
UCI `/etc/config/vbanhub` -> init script writes `/var/etc/vbanhub.conf`
(`route <src_ip> <src_stream> <dst_ip> <dst_port> <dst_stream>`) -> `SIGHUP`
reloads without restart. Daemon writes `/var/run/vbanhub.json` (tmpfs) every 2 s;
LuCI reads it for live stats and the learn list.

## Build / test
    make -C package/vbanhub/src && python3 test/test_fanout.py package/vbanhub/src/vbanhub
For OpenWrt: copy `package/*` into a feed or `package/` of the SDK, `make package/vbanhub/compile package/luci-app-vbanhub/compile`.

## Status / known limits
- Daemon built and loopback-tested on x86 glibc. NOT yet tested on OpenWrt hardware/SDK.
- LuCI view and init script are written but untested (only syntax-checked).
- Frame counter is forwarded verbatim; switching a receiver between sources causes a counter jump.
- Many-to-one (mixing) is not implemented; two sources routed to one receiver will interleave.
- Stream names with spaces are unsupported in config. IPv4 only. No sample-rate conversion.
- Uses a single hub UDP port; a receiver on the router itself must use a different port.

## Next
mDNS (`_vban._udp`) + VBAN PING0 reply, per-route enable/disable and rate limit, optional mixer module, QR enrollment profile.

## Security notes
Trust boundary: untrusted UDP on the hub port. VBAN has no auth, so source IP is spoofable on the same L2 segment.
- Listens only on the networks chosen in LuCI (`list network`, default `lan`): the ingress interface of every packet (`IP_PKTINFO`) is checked and anything else is dropped (counted as `filtered`). Fail closed: if no selected interface exists, nothing is accepted. Discovery broadcasts go out only on the selected networks. This replaces the earlier `SO_BINDTODEVICE`, which allowed only one interface; keep WAN input blocked in the firewall (OpenWrt default).
- Runs as `nobody`; only `/var/run/vbanhub/` is writable.
- Routes need a source IP **and** stream name (no wildcards); names with whitespace are rejected.
- Destinations in 0.0.0.0/8, multicast/broadcast, or loopback on the hub port are refused (loop/reflection guard). The router's own LAN IP on the hub port is not yet checked.
- Oversize (>1436 B) and non-VBAN datagrams are dropped, never forwarded.
- Fan-out is capped at 32 destinations per packet. There is no per-source rate limit yet.
- Residual risk: a host on the LAN can spoof an allowed transmitter's IP. Use a dedicated VLAN or WireGuard for untrusted clients.
- Tests (`test/test_fanout.py`) cover source binding, oversize drop and loop refusal. Not run: gitleaks (not installed here), firewall rules, hardware.
