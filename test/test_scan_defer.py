#!/usr/bin/env python3
"""A scan requested within 3 s of the previous one is deferred, not dropped. Usage: test_scan_defer.py <binary>"""
import signal, socket, subprocess, sys, tempfile, time
binp = sys.argv[1]; d = tempfile.mkdtemp(); conf = f"{d}/c"; open(conf, "w").write("# none\n")
L = socket.socket(socket.AF_INET, socket.SOCK_DGRAM); L.bind(("127.0.0.1", 16981)); L.settimeout(0.2)
p = subprocess.Popen([binp, "-p", "16982", "-c", conf, "-s", f"{d}/s.json", "-T", "127.0.0.1", "-P", "16981"]); time.sleep(0.4)
t0 = time.time(); got = []
p.send_signal(signal.SIGUSR1); time.sleep(0.1); p.send_signal(signal.SIGUSR1)   # second press right after the first
while time.time() - t0 < 6:
    try:
        data, _ = L.recvfrom(2048)
        if len(data) == 704 and data[4] == 0x60: got.append(round(time.time() - t0, 1))
    except socket.timeout: pass
p.send_signal(signal.SIGTERM); p.wait()
ok = len(got) == 2 and 2.5 <= got[1] - got[0] <= 5
print(f"scan requests seen at t={got}", "PASS" if ok else "FAILED"); sys.exit(0 if ok else 1)
