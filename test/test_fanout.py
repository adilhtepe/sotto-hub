#!/usr/bin/env python3
"""Loopback test: 1 transmitter stream fanned out to 2 receivers with different stream names.
Usage: test_fanout.py <path-to-vbanhub-binary>"""
import os, signal, socket, struct, subprocess, sys, tempfile, time

binp = sys.argv[1]
d = tempfile.mkdtemp()
conf, stat = f"{d}/c", f"{d}/s.json"
HUB = 16980
rx1, rx2 = socket.socket(socket.AF_INET, socket.SOCK_DGRAM), socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
rx1.bind(("127.0.0.1", 0)); rx2.bind(("127.0.0.1", 0))
rx1.settimeout(2); rx2.settimeout(2)
open(conf, "w").write(
    f"route\t127.0.0.1\tMic1\t127.0.0.1\t{rx1.getsockname()[1]}\tStudioA\n"
    f"route\t127.0.0.1\tMic1\t127.0.0.1\t{rx2.getsockname()[1]}\tStudioB\n"
    f"route\t127.0.0.1\tLoop\t127.0.0.1\t{HUB}\tLoop\n")  # must be refused (loop into hub)
p = subprocess.Popen([binp, "-p", str(HUB), "-c", conf, "-s", stat])
time.sleep(0.3)

def pkt(name, fc, payload=b"\x01\x02" * 64):
    return b"VBAN" + bytes([3, 63, 1, 1]) + name.ljust(16, b"\0") + struct.pack("<I", fc) + payload

tx = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
for fc in (0, 1, 5):  # gap of 3 -> lost=3
    tx.sendto(pkt(b"Mic1", fc), ("127.0.0.1", HUB))
tx.sendto(pkt(b"Other", 0), ("127.0.0.1", HUB))   # unknown stream
tx.sendto(b"garbage", ("127.0.0.1", HUB))          # bad
# negative: right stream name from a different source IP must NOT be routed (source binding)
spoof = socket.socket(socket.AF_INET, socket.SOCK_DGRAM); spoof.bind(("127.0.0.2", 0))
spoof.sendto(pkt(b"Mic1", 9), ("127.0.0.1", HUB))
# negative: oversize datagram (>1436) is dropped, not forwarded truncated
tx.sendto(pkt(b"Mic1", 10, b"\0" * 1500), ("127.0.0.1", HUB))
# negative: route whose destination is the hub itself was refused -> packet is unrouted, no loop
tx.sendto(pkt(b"Loop", 0), ("127.0.0.1", HUB))

ok = True
for sock in (rx1, rx2): sock.settimeout(2)
for sock, want in ((rx1, b"StudioA"), (rx2, b"StudioB")):
    for fc in (0, 1, 5):
        data, _ = sock.recvfrom(2048)
        name = data[8:24].rstrip(b"\0")
        good = (data[:4] == b"VBAN" and name == want and data[24:28] == struct.pack("<I", fc)
                and data[28:] == b"\x01\x02" * 64 and data[4:8] == bytes([3, 63, 1, 1]))
        ok &= good
        if not good: print("FAIL", want, data[:30])
time.sleep(2.3)
import json
s = json.load(open(stat))
print(json.dumps(s, indent=1))
ok &= s["rx"] == 8 and s["bad"] == 2 and s["unknown"] == 3 and s["tx"] == 6 and len(s["routes"]) == 2
ok &= all(r["lost"] == 3 for r in s["routes"]) and any(x["stream"] == "Other" and not x["routed"] for x in s["streams"])
p.send_signal(signal.SIGTERM); p.wait()
print("PASS" if ok else "FAILED"); sys.exit(0 if ok else 1)

