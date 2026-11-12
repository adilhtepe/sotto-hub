#!/usr/bin/env python3
"""Load test against a router hub: <router_ip> <hub_port> <my_ip> <pps> <seconds>
Sends 'Mic1' at the given packets/s (256 B payload), counts what comes back from 2 receivers."""
import socket, struct, sys, threading, time
rip, hub, me, pps, secs = sys.argv[1], int(sys.argv[2]), sys.argv[3], int(sys.argv[4]), int(sys.argv[5])
cnt = [0, 0]; stop = False
def rx(i, port):
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM); s.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 4 << 20)
    s.bind((me, port)); s.settimeout(0.2)
    while not stop:
        try: s.recv(2048); cnt[i] += 1
        except socket.timeout: pass
ts = [threading.Thread(target=rx, args=(i, p)) for i, p in ((0, 17001), (1, 17002))]
[t.start() for t in ts]; time.sleep(0.2)
tx = socket.socket(socket.AF_INET, socket.SOCK_DGRAM); tx.bind((me, 0))
sent = 0; t0 = time.perf_counter(); body = bytes(256)
while time.perf_counter() - t0 < secs:
    due = int((time.perf_counter() - t0) * pps)
    while sent < due:
        tx.sendto(b"VBAN" + bytes([3, 63, 1, 1]) + b"Mic1".ljust(16, b"\0") + struct.pack("<I", sent) + body, (rip, hub)); sent += 1
    time.sleep(0.0005)
time.sleep(0.5); stop = True; [t.join() for t in ts]
print(f"target {pps} pps x {secs}s: sent {sent}, received {cnt[0]}+{cnt[1]} (loss {100*(1-(cnt[0]+cnt[1])/(2*sent)):.2f}%)")
