#!/usr/bin/env python3
"""Discovery test (VBAN PING0). Usage: test_discovery.py <vbanhub-binary>"""
import json, os, signal, socket, struct, subprocess, sys, tempfile, threading, time

binp = sys.argv[1]; d = tempfile.mkdtemp(); conf, stat = f"{d}/c", f"{d}/s.json"
HUB, PR, PT, PD = 16990, 16991, 16992, 16994
SVC = 676

def hdr(fn, fc, name=b"PING"):
    return b"VBAN" + bytes([0x60, fn, 0, 0]) + name.ljust(16, b"\0") + struct.pack("<I", fc)

def ping_struct(btype, dev, app, host):
    s = bytearray(SVC)
    struct.pack_into("<II", s, 0, btype, 1)
    s[164:164 + len(dev)] = dev; s[292:292 + len(app)] = app; s[356:356 + len(host)] = host
    return bytes(s)

seen_requests = []
def endpoint(port, btype, dev, app, host):
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM); s.bind(("127.0.0.1", port)); s.settimeout(8)
    def run():
        try:
            data, src = s.recvfrom(2048)
            seen_requests.append((port, len(data), data[4], data[5], data[6]))
            fc = struct.unpack("<I", data[24:28])[0]
            s.sendto(hdr(0x80, fc) + ping_struct(btype, dev, app, host), src)
        except socket.timeout: pass
    t = threading.Thread(target=run); t.start(); return t

open(conf, "w").write(f"route\t127.0.0.1\tMic1\t127.0.0.1\t{PD}\tStudioA\n")
routed = socket.socket(socket.AF_INET, socket.SOCK_DGRAM); routed.bind(("127.0.0.1", PD)); routed.settimeout(1)
ths = [endpoint(PR, 0x1, b"Speakers", b"Voicemeeter", b"PC-A\xff"),     # receiver (+ non-ascii byte -> '?')
       endpoint(PT, 0x2, b"Mic", b"VBAN Talkie", b"phone")]            # transmitter
p = subprocess.Popen([binp, "-p", str(HUB), "-c", conf, "-s", stat, "-T", "127.0.0.1", "-P", f"{PR},{PT}"])
time.sleep(0.4)
ok = True
def check(c, msg):
    global ok
    if not c: print("FAIL:", msg); ok = False

# unsolicited reply with a wrong request id must be ignored
spoof = socket.socket(socket.AF_INET, socket.SOCK_DGRAM); spoof.bind(("127.0.0.3", 16995))
spoof.sendto(hdr(0x80, 12345) + ping_struct(0x1, b"Evil", b"x", b"x"), ("127.0.0.1", HUB))
# short (header-only) reply must be ignored too
spoof.sendto(hdr(0x80, 1), ("127.0.0.1", HUB))
# service packet whose stream name matches a route must NOT be forwarded
spoof2 = socket.socket(socket.AF_INET, socket.SOCK_DGRAM); spoof2.bind(("127.0.0.1", 0))
spoof2.sendto(hdr(0x00, 7, b"Mic1") + bytes(SVC), ("127.0.0.1", HUB))
try: routed.recv(2048); check(False, "service packet was routed")
except socket.timeout: pass

p.send_signal(signal.SIGUSR1)
for t in ths: t.join()
time.sleep(2.3)
s = json.load(open(stat))
dd = {x["port"]: x for x in s["discovered"]}
check({PR, PT} <= set(dd), f"discovered ports {sorted(dd)}")
# a full PING0 *request* (device announcing itself) is remembered, but a spoofed unsolicited *reply* is not
check(not any(x["ip"] == "127.0.0.3" for x in s["discovered"]), "spoofed reply must not be recorded")
check(dd[PR]["type"] == 1 and dd[PR]["device"] == "Speakers" and dd[PR]["app"] == "Voicemeeter" and dd[PR]["host"] == "PC-A?", dd[PR])
check(dd[PT]["type"] == 2 and dd[PT]["host"] == "phone", dd[PT])
check(all(r[1] == 28 + SVC and r[2] == 0x60 and r[3] == 0 and r[4] == 0 for r in seen_requests), f"request format {seen_requests}")
check(s["scan"]["age"] >= 0, "scan age")

# hub answers a full ping, ignores a short one
c = socket.socket(socket.AF_INET, socket.SOCK_DGRAM); c.bind(("127.0.0.1", 0)); c.settimeout(1)
c.sendto(hdr(0, 4242) + bytes(SVC), ("127.0.0.1", HUB))
data, _ = c.recvfrom(2048)
check(len(data) == 28 + SVC and data[5] == 0x80 and struct.unpack("<I", data[24:28])[0] == 4242, "ping reply")
check(data[28 + 292:28 + 299] == b"vbanhub", "reply app name")
check(struct.unpack("<I", data[28:32])[0] == 0xF, "bitType must be receiver+transmitter (+SPOT): 0xF")
check(data[8:24].rstrip(b"\0") == b"PING", "request stream-name label echoed")
check(struct.unpack("<I", data[28 + 12:28 + 16])[0] == 48000, "preferred rate")
# header-only ping (some apps send only the header) is answered too, and the label is echoed
c.sendto(hdr(0, 99, b"VBAN SPOT PING"), ("127.0.0.1", HUB))
data, _ = c.recvfrom(2048)
check(len(data) == 28 + SVC and data[5] == 0x80 and struct.unpack("<I", data[24:28])[0] == 99 and data[8:22] == b"VBAN SPOT PING", "header-only ping reply")

p.send_signal(signal.SIGTERM); p.wait()
print("PASS" if ok else "FAILED"); sys.exit(0 if ok else 1)
