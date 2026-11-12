#!/usr/bin/env python3
"""Fake VBAN device that answers PING0 on UDP <port> (default 6980) for <secs>. For LAN discovery demos.
Usage: fake_endpoint.py [port] [secs] [type=1] [name]"""
import socket, struct, sys, time
port = int(sys.argv[1]) if len(sys.argv) > 1 else 6980
secs = int(sys.argv[2]) if len(sys.argv) > 2 else 20
btype = int(sys.argv[3]) if len(sys.argv) > 3 else 1
name = (sys.argv[4] if len(sys.argv) > 4 else socket.gethostname()).encode()[:63]
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM); s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
s.bind(("0.0.0.0", port)); s.settimeout(1); end = time.time() + secs
while time.time() < end:
    try: d, src = s.recvfrom(2048)
    except socket.timeout: continue
    if len(d) >= 704 and d[:4] == b"VBAN" and d[4] == 0x60 and d[5] == 0:
        b = bytearray(676); struct.pack_into("<II", b, 0, btype, 1)
        b[164:164+len(name)] = name; b[292:292+11] = b"FakeVBANapp"; b[356:356+len(name)] = name
        s.sendto(d[:4] + bytes([0x60, 0x80, 0, 0]) + d[8:28] + bytes(b), src)
        print("answered ping from", src, flush=True)
