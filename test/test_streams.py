#!/usr/bin/env python3
"""Stream-name resolution test. Usage: test_streams.py <vbanhub-binary>
Names with spaces, format decoding (rate/channels/format), rate counter, routed flag."""
import json, signal, socket, struct, subprocess, sys, tempfile, time
binp = sys.argv[1]; d = tempfile.mkdtemp(); conf, stat = f"{d}/c", f"{d}/s.json"; HUB = 16960
rx = socket.socket(socket.AF_INET, socket.SOCK_DGRAM); rx.bind(("127.0.0.1", 0)); rx.settimeout(2)
open(conf, "w").write(f"route\t127.0.0.1\tMic One\t127.0.0.1\t{rx.getsockname()[1]}\tOut Name\n")
p = subprocess.Popen([binp, "-p", str(HUB), "-c", conf, "-s", stat]); time.sleep(0.4)
tx = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
def pkt(name, sr, nbs, nbc, bit, fc, payload=bytes(64)):
    return b"VBAN" + bytes([sr, nbs, nbc, bit]) + name.ljust(16, b"\0") + struct.pack("<I", fc) + payload
ok = True
def check(c, m):
    global ok
    if not c: print("FAIL:", m); ok = False
# routed stream with spaces in both names: 48 kHz (idx 3), 64 samples, 2 ch, int16 -- 100 pkts over ~1 s
for fc in range(100):
    tx.sendto(pkt(b"Mic One", 3, 63, 1, 1, fc), ("127.0.0.1", HUB)); time.sleep(0.01)
data, _ = rx.recvfrom(2048)
check(data[8:24].rstrip(b"\0") == b"Out Name", f"rewritten name {data[8:24]!r}")
# unrouted streams: 44.1 kHz mono float32, and a serial sub-protocol stream, and a 16-char name
tx.sendto(pkt(b"Line In 2", 16, 255, 0, 4, 0, bytes(1024)), ("127.0.0.1", HUB))
tx.sendto(pkt(b"MIDI", 0x20 | 3, 0, 0, 0, 0, bytes(8)), ("127.0.0.1", HUB))
tx.sendto(pkt(b"ABCDEFGHIJKLMNOP", 3, 63, 1, 1, 0), ("127.0.0.1", HUB))
time.sleep(2.3)
s = json.load(open(stat)); by = {x["stream"]: x for x in s["streams"]}
m = by.get("Mic One")
check(m and m["routed"] == 1 and m["hz"] == 48000 and m["samples"] == 64 and m["channels"] == 2 and m["fmt"] == 1 and m["sub"] == 0 and m["codec"] == 0, m)
check(m and m["pkts"] == 100 and m["rate"] >= 20 and m["kind"] == 0 and m["port"] == tx.getsockname()[1], m)
l = by.get("Line In 2")
check(l and l["routed"] == 0 and l["hz"] == 44100 and l["samples"] == 256 and l["channels"] == 1 and l["fmt"] == 4, l)
check(by.get("MIDI") and by["MIDI"]["sub"] == 0x20, by.get("MIDI"))
check("ABCDEFGHIJKLMNOP" in by, list(by))
check(s["unknown"] == 3, s["unknown"])
p.send_signal(signal.SIGTERM); p.wait()
print("PASS" if ok else "FAILED"); sys.exit(0 if ok else 1)
