# OpenWrt VBAN Hub

A RAM-light VBAN router for OpenWrt. Transmitters send to the router; the router
fans each stream out to any set of receivers, rewriting the VBAN stream name per
receiver. Routing is configured in a LuCI matrix.

## Certificates: plain VBAN vs secure VBAN
Plain VBAN is UDP with no handshake, authentication or encryption. Existing clients (Voicemeeter,
VBAN apps) know only IP + port + stream name, so for them "joining" is:

1. **Enrollment**: you give each endpoint the router IP, hub port and its stream name.
2. **Learn/adopt**: unknown senders appear in LuCI (IP, stream) with an "Adopt" button.
3. **Binding**: a route only matches `(source IP, stream name)`; everything else is
   dropped and shown as "unrouted". For untrusted networks tunnel via WireGuard.

Devices built on the VBAN SDK can use **secure VBAN** instead: certificates from a CA on this router,
an authenticated and encrypted session with the hub, and routes bound to the certificate rather
than the spoofable IP. See "Secure VBAN" below.

## Stream names and formats
The hub reads the 28-byte header of every stream that reaches it (sent to the router or broadcast on the LAN
to the hub port) and lists it under **Streams heard**: source IP:port, the exact 16-byte stream name
(spaces allowed), sub-protocol (audio/serial/text), sample rate, channels, sample format, codec, packets/s,
unicast/broadcast/multicast and whether it is routed. Known devices and discovered devices show the names heard
from their IP, and **Add as transmitter** pre-fills the exact name (suggestions in the dialog). Receivers' expected
names cannot be learned from traffic, so type them. Limit: only streams sent to the hub or broadcast are visible;
unicast streams between two other LAN hosts never reach the router's IP stack.
The daemon route file is now TAB-separated (`route<TAB>ip<TAB>stream<TAB>ip<TAB>port<TAB>stream`) so names may contain spaces;
`/etc/init.d/vbanhub` generates it. Test: `test/test_streams.py <binary>`.

## Stream names are optional
VBAN receivers filter on the stream name, but the hub does not need you to type one. An **input** (transmitter) with no name accepts any stream from its IP (set a name only to pick one of several streams the same IP sends). An **output** (receiver) with no name gets the name the input used, unchanged (set one only when the receiver accepts just one specific name, then the hub rewrites it). Internally `*` means "any" / "keep"; typing `*` as a name is rejected. If one IP sends several streams to the same unnamed-input route they are all forwarded; name the input to pick one. Test: `test/test_names.py <binary>`.

## LuCI page: three tabs
- **Mixer** (first tab): only the *Inputs* (transmitters) and *Outputs* (receivers), each with its own live state (signal/format/pkt/s or receiving/idle), who it is routed to, and its own volume + mute slider; plus the master volume. Secure endpoints show a lock and their certificate name.
- **Settings**: everything else (hub settings, routes, endpoints, routing matrix, devices on the router, discovery, streams heard, status).
- **Security**: the certificate authority for secure VBAN (next section).

## Volume
Volume exists per input, per output, per route and as a master; the effective level is their product (input x output x route x master; 0-150 % per slider, up to 400 % combined, any mute gives silence). Sliders apply instantly with `/etc/init.d/vbanhub setvol <main|route-id|endpoint-id> <0-200> <0|1>` (validated, committed, config re-read without restart or dropped packets). The hub scales PCM audio: uint8, int16, int24, int32 (fixed point, saturating) and float32/64; serial/text, non-PCM codecs and 12/10-bit data pass through unchanged. At 100 % a packet is forwarded bit-exact without a copy; only scaled routes pay for a payload copy (up to 45 KB of static buffers). UCI: `option gain`/`mute` on `route`, `endpoint` or `main` sections. Tests: `test/test_gain.py`, `node test/test_luci_render.js <hub.js>`.
A device that announces itself with a full PING0 (like `~/vban/PC/vban-pc-tx.py`, every 10 s) is added to Discovered devices automatically, no scan needed.

## Housekeeping (automatic)
- **Orphan routes**: a route whose transmitter or receiver endpoint no longer exists is deleted automatically, on every service start/reload (`/etc/init.d/vbanhub prune` does it by hand) and instantly in LuCI when you remove an endpoint (the matrix refreshes too).
- **Enable in LuCI starts the service**: Save & Apply restarts the service when its settings changed or it was not running; route-only changes just re-read the routes without dropping packets.
- **Scan LAN** is never swallowed: a request within 3 s of the previous scan is deferred, not dropped. LuCI warns when the hub is not running (no status file). Tests: `test/test_scan_defer.py`.

## Boot, port and pings
- The init script is **enabled at boot** (`deploy.sh` / package postinst); whether it actually runs is decided by the UCI `enabled` flag.
- **UDP port in the firewall**: for each selected network the hub opens its port in that network's firewall zone with a managed rule `vbanhub_<zone>` (`open_firewall`, default on). Zones that already ACCEPT input (default `lan`) need none; `wan` and masquerading zones are never opened. Rules are only rewritten when they change and are removed when the hub is disabled.
- **Pings / how apps see the hub**: any VBAN PING0 (unicast or broadcast, full or header-only; limit 20 replies/s) is answered as a SPOT receiver *and* SPOT transmitter (`bitType` 0xF), preferred rate 48 kHz, supported rates 6 kHz-705.6 kHz, with the name from `hub_name` (default `<hostname> VBAN hub`), manufacturer `OpenWrt`, application `vbanhub`, and the request's stream-name label echoed. Apps that list receivers can therefore offer the hub as a destination; point them at the router IP, port 6980, and any stream name. `test/ping_hub.py <ip>` checks it.

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
- `package/vbanhub/` daemon (C, ~8 KB text, ~50 KB static BSS), UCI config, procd init;
  `vbanhub.bpf.c` + `vbanhub_bpf.h`: optional kernel fast path (package `vbanhub-fastpath`)
- `bench/` `hubbench` load/latency generator, `vm-bench.sh` (fwd / userspace / eBPF), `vm-ebpf-test.sh`
- `package/luci-app-vbanhub/` LuCI JS view, menu + ACL
- `test/test_fanout.py` loopback test (fan-out, rewrite, loss counting, learn)

## Data path
`poll` + `recvmmsg` (16 pkts) -> match routes -> `sendmmsg` with iovec
`[rewritten 28-byte header][shared payload]`. No payload copy, no malloc, no audio
decoding, no buffering (receivers keep their own jitter buffers). Outgoing DSCP EF.
With the kernel fast path, routed packets never reach this loop (next section).

## Kernel fast path (eBPF)
Package `vbanhub-fastpath` adds a tc eBPF program (`vbanhub.bpf.c`) on the ingress of each listen
device. For a VBAN packet sent to the hub, it does the same job as the daemon inside the kernel:
- looks up the route (source IP, stream name);
- per receiver, rewrites the Ethernet header, IP addresses, UDP ports and the 16-byte stream name,
  and updates the checksums;
- sends a clone out of the interface a FIB lookup picks, then drops the original.

The packet never reaches a socket: no wake-up, no context switch, no copy to userspace.

**The daemon is still the hub.** It fills the program's maps on start, on every reload, and every
5 s for addresses. It folds the kernel's counters into `status.json`, so LuCI shows the same
numbers. Anything the program does not handle goes up to the daemon unchanged:
- PING0 and other SERVICE packets;
- unrouted senders (so "Streams heard" and learning still work);
- routes whose volume is not 100 %;
- receivers that are local or whose neighbour (ARP) is not resolved yet;
- IP options, fragments and VLAN-tagged frames;
- skbs that GRO merged from several datagrams (see "GRO" below);
- all traffic when IPv4 forwarding is off on the listen interface.

If the object or `tc` is missing, or `option fastpath '0'` is set, the daemon forwards everything as
before.

**Security.** tc ingress runs before netfilter, so forwarded packets skip the firewall. Only pairs
in the route map are forwarded, and only to the receivers the daemon accepted. Those receivers
pass the same checks as before: no broadcast/multicast/reserved destinations, and no loop back to
the hub port. That is stricter than the zone rule that lets VBAN in. The daemon starts as root to
open the pinned maps, then runs as `nobody` keeping only `CAP_BPF`. Kernels before 6.5 refuse map
updates without it when unprivileged BPF is disabled.

**GRO.** Fraglist GRO (`rx-gro-list`) is on by default on every LAN and Wi-Fi port of e.g.
mediatek targets. It merges back-to-back datagrams of one flow into a single skb, which the tc
program cannot rewrite. On the RT-AX52 that was about 30 % of a Voicemeeter stream (packet pairs
of 1052 bytes). Those packets went to the daemon: late, and out of order against the packets the
kernel forwarded. The kernel has no per-flow way out of it.

So with the fast path the init script turns `rx-gro-list` off on the ports of the listen bridges.
It only touches ports where it was on, and restores them on stop. Normal GRO stays on. The cost is
that other bulk traffic the CPU forwards loses fraglist GRO. That is not measured here.
`option fastpath_gro_off '0'` keeps GRO as it is. `status.json` → `fastpath.to_daemon_gro` counts
the fallbacks.

**On the router** (ASUS RT-AX52, MT7981 2× Cortex-A53 1.3 GHz, OpenWrt 25.12, kernel 6.12):
measured with `bench/router-bench.sh` from a wired LAN host that is both sender and receiver.
Latency includes that host's own network stack. Live routes kept running during the tests.

| Load | userspace hub | eBPF hub |
|---|---|---|
| 1 stream × 2 receivers (1.5k pkt/s out): p50 / p99 | 424 / 714 µs | 362 / 641 µs |
| 8 × 4 (24k pkt/s): p50 / p99, lost, router CPU | 444 µs / 2.5 ms, 228 lost, 75 % of a core | 319 / 814 µs, **0 lost**, 31 % |
| 32 × 4 (96k pkt/s) | **overloaded:** 61 % lost, p50 4.1 ms | 99.8 % delivered, p50 423 µs (p99 7 ms, softirq saturates) |
| 64 × 4 (192k pkt/s) | 85 % lost | 42 % lost: beyond this router (~100k pkt/s out) |

- At realistic loads eBPF cuts latency by 15–30 % and the p99 by two thirds, with half the CPU.
- It roughly triples the forwarding capacity: about 35k → about 100k packets/s out.

**In a VM.** These numbers come from `bench/vm-bench.sh` in a 4-vCPU QEMU VM over veth (kernel 7.0). Two runs; values
are one-way latency sender → receiver through the hub box. `fwd` is the floor: no hub, the box only
IP-forwards (the sender itself sends one copy per receiver).

| Load (64-frame stereo packets) | fwd (floor) | userspace hub | eBPF hub |
|---|---|---|---|
| 1 stream, 2 receivers: p50 / p99 | 69–146 / 211–389 µs | 200–336 / 460–541 µs | 107–217 / 239–275 µs |
| 8 streams × 4 receivers (24k pkt/s out): p50 / p99 | 26–28 / 49–66 µs | 56–57 / 108–134 µs | 36–37 / 52–89 µs |
| 64 streams × 4 receivers (192k pkt/s out) | p50 15 µs, 0 lost | **saturated:** 1 core at 100 %, 21–30 % lost, p50 2.8–3.4 ms | p50 27–32 µs, p99 52 µs, ≤ 0.01 % lost |

- **At normal load** the userspace hub adds about 30 µs to the forwarding floor; eBPF adds about 9 µs.
- **At high load** the userspace hub tops out near 120–150k packets/s out per core. The eBPF path
  keeps latency flat and uses no daemon CPU.
- **At very low rates** the numbers are dominated by idle-CPU wake-up in the VM. They vary a lot
  between runs (see the ranges).
- **Caveat:** absolute numbers on a router's ARM/MIPS core and real NICs will differ. The ordering
  should not.

**Tests.** `bench/vm-ebpf-test.sh` runs in a throwaway VM (`sudo vng -r /boot/vmlinuz-$(uname -r)
--memory 2G --cpus 4 --exec "sh $PWD/bench/vm-ebpf-test.sh"`). All of these pass:
- fan-out to 4 receivers with per-route names: rename, keep, any-name and any-source keys;
- UDP checksums verified in software by the receiver, from a full-checksum sender and from a
  checksum-offload sender;
- the gain route is served by the daemon;
- `status.json` merges the kernel counters;
- PING0 is answered and the unrouted sender is listed;
- 10 reloads while streaming lose nothing, and a removed route stops in the kernel;
- the daemon runs as `nobody` with `CAP_BPF` only.

The userspace test suite (`test/test_*.py`, LuCI render) still passes.

Verified on the RT-AX52:
- `deploy.sh`, with `kmod-sched-bpf` and `tc-bpf` installed;
- the verifier accepts the program on 6.12 and JITs it;
- the init script attaches it to `br-lan` and turns `rx-gro-list` off, and stop restores both;
- the daemon runs as `nobody` with `CAP_BPF`;
- a live Voicemeeter route is forwarded entirely in the kernel, with 0 fallbacks.

Switching paths can reorder a packet or two. When a reload briefly hands packets to the daemon,
the next packet through the kernel can overtake them. Receivers' jitter buffers absorb this.

**Not verified yet:** the OpenWrt SDK build of `vbanhub-fastpath` (`bpf.mk`), and kernels 5.15 /
6.6. The object also compiles for big-endian (`bpfeb`, MIPS).

## Secure VBAN
The hub is the responder of the SDK's secure VBAN (ADR-003 in the SDK):
- **Handshake.** `Noise_XX_25519_ChaChaPoly_BLAKE2b` with 168-byte certificates.
- **Packets.** ChaCha20-Poly1305 in VBAN `USER` packets, with replay protection and a rekey every
  2 minutes.
- **Code.** The crypto is the SDK's layer with Monocypher, copied unmodified into
  `package/vbanhub/src/secure/` by `tools/sync-secure.sh`. `SDK_REVISION` records the SDK commit.

**Security tab (LuCI).** It can:
- create a CA on the router, or import one (its certificate, plus the key if the router should
  sign); without the key, the router shows a hub request to sign elsewhere and upload back;
- sign device requests: upload or paste the `.req`, then download the certificate and `ca.crt`;
- list issued certificates, revoke them, and show the connected secure devices.

The PKI lives in `/etc/vbanhub/pki`. Keys are `0600 root`. Uploads from LuCI are written with mode
0600 to `/etc/vbanhub/upload` (root-only, `0700`) and deleted after use. They never go to the shared
`/tmp`, where another local service could pre-create the file and read a CA key. A device name can
hold only one live certificate (`sign` refuses a duplicate until the old one is revoked or expired),
because routes are bound to certificate names. The PKI is kept over sysupgrade
(`/lib/upgrade/keep.d/vbanhub`). The same actions are available on the command line:
`/etc/init.d/vbanhub cert status | init | import | sign | revoke | reset ...`, which runs
`vbanhub cert ...`.

**Endpoints.** An endpoint with a **Certificate (secure)** name is matched by that certificate,
so its IP is optional:
- *As an input:* only packets from that device's authenticated session are routed. Plain packets
  claiming its stream are not, so IP spoofing is gone.
- *As an output:* packets are encrypted into the session the receiver device opened to the hub
  (`vban_recv --hub router-ip ...`). Without a live session they are dropped and counted.
- *Bridging:* secure → plain (e.g. to Voicemeeter), plain → secure and secure → secure all work.
  Volume applies as usual.

**Daemon.**
- `-K <pki dir>` turns secure VBAN on. The daemon reads `hub.key` while still root, then drops to
  `nobody`.
- Reload (`SIGHUP`) re-reads the revocation list and ends the live sessions of revoked devices
  at once.
- Each address may start 3 handshakes per second. There are 64 session slots; a device holds two
  for up to 60 s around each rekey.
- **Floods.** When the 10-per-second handshake budget is used up, a handshake start gets a 44-byte
  COOKIE reply instead of any work: a MAC of its source address under a key that rotates every
  2 minutes. A device that is really at that address resends with the cookie and gets in on a
  second budget. Floods from forged addresses cannot use that second budget. When the table is
  full, the oldest unfinished handshake is evicted; established sessions never are.
- **Measured.** With a flood from 60 source addresses at about 1200 handshakes/s, a real device
  connected in 0.4–2 s, against 4.4–6 s before cookies.
- **Revocation.** The list has no size limit; it is read whole and binary-searched.
- **Roles.** A receive-only certificate cannot feed an input.
- Secure packets always go through the daemon: the eBPF fast path passes them up, and secure
  routes never enter its maps.
- An inner packet may be at most 1420 bytes, so a full-size 1464-byte plain packet cannot go
  to a secure output (`too_big`).

**Tests.**
- `test/test_secure.py <vbanhub> <SDK build>`, on loopback: CA init/sign/revoke; secure → plain,
  secure → secure, plain → secure; plain packets claiming a certificate-bound stream not routed;
  the status lists peers; a revoked sender is cut off.
- `test/test_secure_router.py`, on the RT-AX52, run as a second instance in `/tmp` with a
  throw-away CA. The live hub and `/etc/vbanhub` were not touched. Results:
  - 8 secure transmitters (6000 packets/s in) were decrypted and bridged to a plain receiver, and
    one was re-encrypted to a secure receiver;
  - the daemon used 24 % of an A53 core (about 20 µs more per packet than plain forwarding);
  - running as `nobody`, it cut a revoked transmitter off on reload;
  - 8 devices starting at once from one address hit the 3/s handshake limit; the refused ones got
    in on their 1 s retry.

**Not verified yet.** The LuCI Security tab was checked by the render test only, not clicked
through in a browser on the router. The init-script `cert` commands and the PKI in
`/etc/vbanhub` were not used on the router; the router test called the binary directly. The
OpenWrt SDK package build is also untested.

## Over the internet
Secure VBAN devices can reach the hub from anywhere. The hub then routes their audio like any
other: to plain receivers on the LAN (Voicemeeter), and from LAN sources back out to them.
- **Turning it on.** Opt in under Settings → *Secure devices from the internet*
  (`option internet '1'`, `option internet_network 'wan'`). It needs a CA (Security tab).
  The hub opens its port in that network's firewall zone and starts with `-W <wan device>`.
  On that interface it accepts only authenticated, encrypted packets; plain VBAN and pings from
  the internet are dropped and counted as `wan_refused`.
- **NAT.** Devices always start the session, so a phone or laptop behind any home NAT works
  without port forwarding on its side. A device that only receives sends a 44-byte keepalive every
  15 s, so its NAT mapping stays open. The hub follows a device to a new address (e.g. when it
  changes network) on its next authenticated packet.
- **The hub's address.** The hub needs a public address on its WAN. Behind another router, forward
  UDP 6980 to it. With a changing IP, use dynamic DNS: the SDK tools and `sotto` accept host
  names (`--hub studio.example.net`). IPv4 only, like VBAN.
- **Latency and loss.** Internet jitter is milliseconds, not microseconds. The receivers' jitter
  buffer adapts by itself; start it higher (`-l 40`). Send with redundant copies (`-R 4`). Small
  packets (64 frames, 284 bytes) stay far below any path MTU.

**Tested** with `bench/vm-internet-test.sh`, in a VM with network namespaces. The path was hub WAN →
"internet" (25 ms ± 8 ms delay, 1 % loss each way) → NAT router (UDP mappings expire after 20 s)
→ home device. Results:
- A secure transmitter behind NAT played a clean tone through the hub to a plain LAN receiver.
  With `-R 4`, the redundant copies filled most of the gaps the loss and reordering opened.
- A receive-only device behind NAT still got audio after 70 s: the keepalive held the 20 s
  mapping.
- 51 plain packets and a ping from the internet were refused; nothing was routed or answered.

This has not been tried on a real internet link yet.

## Config flow
UCI `/etc/config/vbanhub` -> init script writes `/var/etc/vbanhub.conf`
(`route <src_ip> <src_stream> <dst_ip> <dst_port> <dst_stream> <gain> <src_cert> <dst_cert>`, TAB-separated) -> `SIGHUP`
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
- Residual risk: a host on the LAN can spoof an allowed **plain** transmitter's IP. Use secure VBAN (certificate-bound endpoints) for SDK devices, and a dedicated VLAN or WireGuard for plain clients on untrusted networks.
- Tests (`test/test_fanout.py`) cover source binding, oversize drop and loop refusal. Not run: gitleaks (not installed here), firewall rules, hardware.
