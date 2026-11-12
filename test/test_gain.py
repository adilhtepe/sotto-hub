#!/usr/bin/env python3
"""Volume (per-route gain, master gain, mute) and 'pinging devices are remembered'. Usage: test_gain.py <binary>"""
import json, math, signal, socket, struct, subprocess, sys, tempfile, time
binp = sys.argv[1]; d = tempfile.mkdtemp(); conf, stat = f"{d}/c", f"{d}/s.json"; HUB = 16950
rxs = {}
def rx(name):
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM); s.bind(("127.0.0.1", 0)); s.settimeout(2); rxs[name] = s; return s.getsockname()[1]
ports = {n: rx(n) for n in ("full", "half", "mute", "boost", "master")}
lines = [f"route\t127.0.0.1\tA\t127.0.0.1\t{ports['full']}\tfull\t100\n",
         f"route\t127.0.0.1\tA\t127.0.0.1\t{ports['half']}\thalf\t50\n",
         f"route\t127.0.0.1\tA\t127.0.0.1\t{ports['mute']}\tmute\t0\n",
         f"route\t127.0.0.1\tA\t127.0.0.1\t{ports['boost']}\tboost\t200\n",
         f"route\t127.0.0.1\tA\t127.0.0.1\t{ports['master']}\tmaster\n"]       # no 7th field = 100 %
open(conf, "w").write("".join(lines))
p = subprocess.Popen([binp, "-p", str(HUB), "-c", conf, "-s", stat]); time.sleep(0.4)
tx = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
ok = True
def check(c, m):
    global ok
    if not c: print("FAIL:", m); ok = False
def hdr(fmt, frames=4, ch=2, sub=0, codec=0, name=b"A"): return b"VBAN" + bytes([3 | sub, frames - 1, ch - 1, fmt | codec]) + name.ljust(16, b"\0") + bytes(4)
def send_get(payload_hdr, payload):
    tx.sendto(payload_hdr + payload, ("127.0.0.1", HUB)); out = {}
    for n, s in rxs.items():
        if n == "master": continue
        d, _ = s.recvfrom(2048); out[n] = d[28:]
    rxs["master"].recvfrom(2048)
    return out

# int16: 8 samples
s16 = [1000, -1000, 30000, -30000, 0, 1, -1, 20000]
o = send_get(hdr(1), struct.pack("<8h", *s16))
get = lambda b: struct.unpack("<8h", b)
check(get(o["full"]) == tuple(s16), "unity must be bit-exact")
check(get(o["half"]) == tuple(int(x * 0.5) if x >= 0 else -int(-x * 0.5) for x in s16) or all(abs(a - b * 0.5) <= 1 for a, b in zip(get(o["half"]), s16)), f"half {get(o['half'])}")
check(get(o["mute"]) == (0,) * 8, "mute")
check(get(o["boost"])[2] == 32767 and get(o["boost"])[3] == -32768 and get(o["boost"])[0] == 2000, f"boost saturates {get(o['boost'])}")
# int24 (fmt 2), float32 (fmt 4), uint8 (fmt 0)
v24 = [100000, -100000, 8000000, -8000000]
b24 = b"".join(struct.pack("<i", v)[:3] for v in v24)
o = send_get(hdr(2, 2, 2), b24)
dec24 = lambda b: [int.from_bytes(b[i:i+3], "little", signed=True) for i in range(0, 12, 3)]
check(dec24(o["half"]) == [50000, -50000, 4000000, -4000000], f"int24 half {dec24(o['half'])}")
check(dec24(o["boost"])[2] == 8388607, "int24 saturates")
f32 = [0.5, -0.25, 1.0, 0.0]
o = send_get(hdr(4, 2, 2), struct.pack("<4f", *f32))
check(all(abs(a - b * 0.5) < 1e-6 for a, b in zip(struct.unpack("<4f", o["half"]), f32)), "float32 half")
check(struct.unpack("<4f", o["mute"]) == (0.0,) * 4, "float32 mute")
u8 = bytes([128, 192, 64, 255])
o = send_get(hdr(0, 2, 2), u8)
check(list(o["half"]) == [128, 160, 96, 191], f"uint8 half {list(o['half'])}")
# serial sub-protocol and a non-PCM codec are never touched
raw = bytes(range(8))
o = send_get(hdr(1, 4, 2, sub=0x20), raw); check(o["mute"] == raw, "serial sub-protocol untouched")
o = send_get(hdr(1, 4, 2, codec=0x10), raw); check(o["mute"] == raw, "non-PCM codec untouched")

# master volume 50 % via reload + route gain 50 -> 25 %
open(conf, "w").write("master\t50\n" + "".join(lines)); p.send_signal(signal.SIGHUP); time.sleep(0.5)
o = send_get(hdr(1), struct.pack("<8h", *s16))
check(abs(get(o["full"])[0] - 500) <= 1 and abs(get(o["half"])[0] - 250) <= 1, f"master 50: full {get(o['full'])[0]} half {get(o['half'])[0]}")

# a device announcing itself with a full PING0 shows up in 'discovered' without a scan
st = bytearray(676); struct.pack_into("<II", st, 0, 0x2, 1); st[164:164 + 7] = b"WinPC-1"; st[292:292 + 6] = b"vbanpc"
png = b"VBAN" + bytes([0x60, 0, 0, 0]) + b"PC".ljust(16, b"\0") + struct.pack("<I", 1) + bytes(st)
c = socket.socket(socket.AF_INET, socket.SOCK_DGRAM); c.bind(("127.0.0.1", 0)); c.sendto(png, ("127.0.0.1", HUB))
time.sleep(2.4)
j = json.load(open(stat))
check(j["master"] == 50, "master in status")
check(any(x["device"] == "WinPC-1" and x["type"] == 2 and x["port"] == c.getsockname()[1] for x in j["discovered"]), f"pinging device remembered: {j['discovered']}")
check({r["dst_stream"]: r["gain"] for r in j["routes"]}["half"] == 50, "route gain in status")
p.send_signal(signal.SIGTERM); p.wait()
print("PASS" if ok else "FAILED"); sys.exit(0 if ok else 1)
