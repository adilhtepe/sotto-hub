#!/usr/bin/env python3
"""Interface selection test. Usage: test_iface.py <vbanhub-binary>
-i lo: traffic on lo is forwarded. -i <nonexistent>: fail closed (nothing forwarded, counted as filtered)."""
import json, signal, socket, struct, subprocess, sys, tempfile, time
binp = sys.argv[1]; d = tempfile.mkdtemp()
def run(ifs, port):
    conf, stat = f"{d}/c{port}", f"{d}/s{port}.json"
    rx = socket.socket(socket.AF_INET, socket.SOCK_DGRAM); rx.bind(("127.0.0.1", 0)); rx.settimeout(1)
    open(conf, "w").write(f"route 127.0.0.1 Mic1 127.0.0.1 {rx.getsockname()[1]} Out\n")
    args = [binp, "-p", str(port), "-c", conf, "-s", stat] + [a for i in ifs for a in ("-i", i)]
    p = subprocess.Popen(args); time.sleep(0.4)
    tx = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    tx.sendto(b"VBAN" + bytes([3, 63, 1, 1]) + b"Mic1".ljust(16, b"\0") + bytes(4) + bytes(64), ("127.0.0.1", port))
    try: rx.recv(2048); got = True
    except socket.timeout: got = False
    time.sleep(2.3); s = json.load(open(stat)); p.send_signal(signal.SIGTERM); p.wait()
    return got, s
ok = True
got, s = run(["lo"], 16970);               ok &= got and s["filtered"] == 0 and s["listen"] == [{"name": "lo", "up": 1}]
got, s = run(["nope0"], 16971);            ok &= (not got) and s["filtered"] == 1 and s["rx"] == 0 and s["listen"][0]["up"] == 0
got, s = run(["nope0", "lo"], 16972);      ok &= got and s["filtered"] == 0
print("PASS" if ok else "FAILED"); sys.exit(0 if ok else 1)
