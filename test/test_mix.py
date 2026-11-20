#!/usr/bin/env python3
"""Mixer: a receiver marked 'mixdst' gets ONE stream that is the sum of its inputs. Usage: test_mix.py <binary>"""
import json, signal, socket, struct, subprocess, sys, tempfile, time
binp = sys.argv[1]; d = tempfile.mkdtemp(); conf, stat = f"{d}/c", f"{d}/s.json"; HUB = 16960
rx = socket.socket(socket.AF_INET, socket.SOCK_DGRAM); rx.bind(("127.0.0.1", 0)); rx.setblocking(False)
rport = rx.getsockname()[1]
plain = socket.socket(socket.AF_INET, socket.SOCK_DGRAM); plain.bind(("127.0.0.1", 0)); plain.setblocking(False)
pport = plain.getsockname()[1]
def write_conf(gain_b=100, extra=""):
    open(conf, "w").write(f"mixdst\t127.0.0.1\t{rport}\tMixOut\n"
        f"route\t127.0.0.1\tA\t127.0.0.1\t{rport}\tX\t100\n"
        f"route\t127.0.0.1\tB\t127.0.0.1\t{rport}\tX\t{gain_b}\n"
        f"route\t127.0.0.1\tC\t127.0.0.1\t{rport}\tX\t100\n"
        f"route\t127.0.0.1\tA\t127.0.0.1\t{pport}\tPlain\t100\n" + extra)
write_conf()
p = subprocess.Popen([binp, "-p", str(HUB), "-c", conf, "-s", stat]); time.sleep(0.4)
tx = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
ok = True
def check(c, m):
    global ok
    if not c: print("FAIL:", m); ok = False
def pkt(name, fc, frames, l, r=None, fmt=1, ch=2, sr=3):
    r = l if r is None else r
    if fmt == 1: body = b"".join(struct.pack("<hh", l, r) if ch == 2 else struct.pack("<h", l) for _ in range(frames))
    elif fmt == 4: body = b"".join(struct.pack("<ff", l / 32768, r / 32768) for _ in range(frames))
    return b"VBAN" + bytes([sr, frames - 1, ch - 1, fmt]) + name.encode().ljust(16, b"\0") + struct.pack("<I", fc) + body
def run(secs, senders):
    """senders: {name: (l, r, kwargs)} each sends 256-frame packets every 5.33 ms. returns mixed packets."""
    got, plains, fc, t0 = [], [], 0, time.perf_counter(); n = 0
    while time.perf_counter() - t0 < secs:
        due = t0 + n * 256 / 48000
        while time.perf_counter() < due: pass
        for name, (l, r, kw) in senders.items():
            if kw.get("fmt") == 4:        # 256 f32 stereo frames do not fit one UDP packet: two of 128
                for h in range(2): tx.sendto(pkt(name, n * 2 + h, 128, l, r, **kw), ("127.0.0.1", HUB))
            else:
                tx.sendto(pkt(name, n, 256, l, r, **kw), ("127.0.0.1", HUB))
        n += 1
        for sock, lst in ((rx, got), (plain, plains)):
            try:
                while True: lst.append(sock.recvfrom(4096)[0])
            except BlockingIOError: pass
    time.sleep(0.05)
    for sock, lst in ((rx, got), (plain, plains)):
        try:
            while True: lst.append(sock.recvfrom(4096)[0])
        except BlockingIOError: pass
    return got, plains
def samples(pk): return struct.unpack("<%dh" % ((len(pk) - 28) // 2), pk[28:])
def steady(got): return got[len(got) // 3:-40]      # skip the priming and the drain after the senders stop

# 1. two inputs are summed into one stream, named MixOut, 128 frames, contiguous counter
got, plains = run(1.5, {"A": (1000, -500, {}), "B": (2000, 700, {}), "C": (0, 0, {"fmt": 1})})
check(len(got) > 300, f"mixed packets {len(got)}")
check(all(g[8:24].rstrip(b"\0") == b"MixOut" for g in got), "stream name MixOut on every packet")
check(all(len(g) == 28 + 128 * 4 and g[4] == 3 and g[5] == 127 and g[6] == 1 and g[7] == 1 for g in got), "128-frame 48k stereo s16 header")
fcs = [struct.unpack("<I", g[24:28])[0] for g in got]
check(all(b - a == 1 for a, b in zip(fcs, fcs[1:])), "frame counter contiguous")
s = steady(got)
check(all(samples(g)[0::2] == (3000,) * 128 and samples(g)[1::2] == (200,) * 128 for g in s),
      f"sum L=3000 R=200, got {samples(s[0])[:4]}")
check(len(plains) > 100 and plains[0][8:24].rstrip(b"\0") == b"Plain", "a non-mixed receiver still gets A directly")
j = json.load(open(stat)); m = j["mix"]
check(len(m) == 1 and m[0]["stream"] == "MixOut" and m[0]["inputs"] == 3 and m[0]["pkts"] > 100, f"status mix {m}")

# 2. per-route gain applies to its own input only; saturation
write_conf(gain_b=50); p.send_signal(signal.SIGHUP); time.sleep(0.4)
got, _ = run(1.0, {"A": (1000, 1000, {}), "B": (2000, 2000, {})}); s = steady(got)
check(all(set(samples(g)) == {2000} for g in s), f"gain 50% on B: {set(samples(s[0]))}")
write_conf(gain_b=100); p.send_signal(signal.SIGHUP); time.sleep(0.4)
got, _ = run(1.0, {"A": (30000, 30000, {}), "B": (30000, -30000, {})}); s = steady(got)
check(all(samples(g)[0::2] == (32767,) * 128 and samples(g)[1::2] == (0,) * 128 for g in s), "saturates, cancels")

# 3. mono and float32 inputs are converted
got, _ = run(1.0, {"A": (1000, None, {"ch": 1}), "B": (2000, 2000, {"fmt": 4})}); s = steady(got)
check(all(set(samples(g)) == {3000} for g in s) or all(all(abs(v - 3000) <= 1 for v in samples(g)) for g in s), f"mono+f32 {set(samples(s[0]))}")

# 4. one input alone, and an unsupported rate is counted and not mixed
got, _ = run(1.0, {"A": (1234, 1234, {}), "B": (9999, 9999, {"sr": 2})}); s = steady(got)   # sr 2 = 24 kHz
check(all(set(samples(g)) == {1234} for g in s), f"unsupported rate ignored: {set(samples(s[0]))}")
time.sleep(2.2); m = json.load(open(stat))["mix"][0]
check(m["unsupported"] > 0, "unsupported counted")

# 5. input going quiet: no more packets once the inputs are gone
time.sleep(0.8)
try:
    while True: rx.recvfrom(4096)
except BlockingIOError: pass
time.sleep(0.4)
try: rx.recvfrom(4096); check(False, "mixer keeps sending with no inputs")
except BlockingIOError: pass

# 6. reload keeps the clock: counter continues, no restart
got, _ = run(0.6, {"A": (100, 100, {})}); a = struct.unpack("<I", got[-1][24:28])[0]
p.send_signal(signal.SIGHUP); got, _ = run(0.6, {"A": (100, 100, {})})
check(len(got) > 100 and all(set(samples(g)) <= {0, 100} for g in got[len(got) // 2:]), "audio continues across a reload")

p.terminate(); p.wait()
print("PASS" if ok else "FAIL")
sys.exit(0 if ok else 1)
