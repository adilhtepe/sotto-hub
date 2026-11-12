#!/usr/bin/env python3
"""Over-the-network test against a router running vbanhub on UDP <port>:
sends N packets of stream 'Mic1' to the hub, expects them back here renamed.
Usage: test_router.py <router_ip> <hub_port> <my_ip>  (router must have routes for my_ip/Mic1 -> my_ip:17001 StudioA, :17002 StudioB)"""
import socket, struct, sys, time
rip, hub, me = sys.argv[1], int(sys.argv[2]), sys.argv[3]
r1, r2 = [socket.socket(socket.AF_INET, socket.SOCK_DGRAM) for _ in range(2)]
r1.bind((me, 17001)); r2.bind((me, 17002)); r1.settimeout(2); r2.settimeout(2)
tx = socket.socket(socket.AF_INET, socket.SOCK_DGRAM); tx.bind((me, 0))
N = 200
t0 = time.time(); lat = []
for fc in range(N):
    p = b"VBAN" + bytes([3, 63, 1, 1]) + b"Mic1".ljust(16, b"\0") + struct.pack("<I", fc) + bytes(256)
    ts = time.perf_counter(); tx.sendto(p, (rip, hub))
    ok = True
    for s, w in ((r1, b"StudioA"), (r2, b"StudioB")):
        d, _ = s.recvfrom(2048)
        ok &= d[8:24].rstrip(b"\0") == w and d[24:28] == struct.pack("<I", fc) and len(d) == len(p)
    lat.append((time.perf_counter() - ts) * 1000)
    assert ok, f"bad packet at {fc}"
    time.sleep(0.005)
lat.sort()
print(f"{N} packets x2 receivers OK; round-trip via router ms: median {lat[N//2]:.2f} p95 {lat[int(N*.95)]:.2f} max {lat[-1]:.2f}")
