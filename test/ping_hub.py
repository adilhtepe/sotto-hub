#!/usr/bin/env python3
"""Send a full VBAN PING0 request to <ip> [port] and print the reply fields."""
import socket, struct, sys, time
ip = sys.argv[1]; port = int(sys.argv[2]) if len(sys.argv) > 2 else 6980
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM); s.settimeout(2)
req = b"VBAN" + bytes([0x60, 0, 0, 0]) + b"VBAN SPOT PING".ljust(16, b"\0") + struct.pack("<I", 777) + bytes(676)
t = time.perf_counter(); s.sendto(req, (ip, port))
try:
    d, src = s.recvfrom(2048)
except socket.timeout:
    print("NO REPLY"); sys.exit(1)
ms = (time.perf_counter() - t) * 1000
c = lambda o: d[28+o:28+o+64].split(b"\0")[0].decode(errors="replace")
print(f"reply from {src[0]}:{src[1]} in {ms:.1f} ms, len {len(d)}, reply-bit {bool(d[5]&0x80)}, id {struct.unpack('<I', d[24:28])[0]}, "
      f"type 0x{struct.unpack('<I', d[28:32])[0]:08x}, app '{c(292)}', device '{c(164)}', host '{c(356)}'")
