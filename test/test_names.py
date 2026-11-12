#!/usr/bin/env python3
"""Stream names are optional. Usage: test_names.py <binary>
  input '*'  : any stream from that IP is accepted      output '*' : the sender's name is kept
  named input/output behave as before (match / rewrite)."""
import signal, socket, subprocess, sys, tempfile, time
binp = sys.argv[1]; d = tempfile.mkdtemp(); conf = f"{d}/c"; HUB = 16940
def sock(): s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM); s.bind(("127.0.0.1", 0)); s.settimeout(1); return s
anyrx, namedrx, pickrx = sock(), sock(), sock()
P = lambda s: s.getsockname()[1]
open(conf, "w").write(
    f"route\t127.0.0.1\t*\t127.0.0.1\t{P(anyrx)}\t*\t100\n"            # any stream in, name kept        (no names typed at all)
    f"route\t127.0.0.1\t*\t127.0.0.1\t{P(namedrx)}\tFixed Out\t100\n"   # any stream in, receiver wants one name
    f"route\t127.0.0.1\tPick Me\t127.0.0.1\t{P(pickrx)}\t*\t100\n")      # one chosen stream in, name kept
p = subprocess.Popen([binp, "-p", str(HUB), "-c", conf, "-s", f"{d}/s.json"]); time.sleep(0.4)
tx = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
pkt = lambda n: b"VBAN" + bytes([3, 63, 1, 1]) + n.ljust(16, b"\0") + bytes(4) + bytes(64)
name = lambda d: d[8:24].rstrip(b"\0")
def get(s):
    try: return name(s.recvfrom(2048)[0])
    except socket.timeout: return None
ok = True
def check(c, m):
    global ok
    if not c: print("FAIL:", m); ok = False
tx.sendto(pkt(b"Whatever 1"), ("127.0.0.1", HUB))
check(get(anyrx) == b"Whatever 1", "no names: stream accepted, name unchanged")
check(get(namedrx) == b"Fixed Out", "receiver with a name: rewritten")
check(get(pickrx) is None, "route bound to 'Pick Me' ignores other streams")
tx.sendto(pkt(b"Pick Me"), ("127.0.0.1", HUB))
check(get(anyrx) == b"Pick Me" and get(namedrx) == b"Fixed Out" and get(pickrx) == b"Pick Me", "second stream: chosen route works, others unchanged")
tx.sendto(pkt(b"A name with 16 ch"), ("127.0.0.1", HUB))      # exactly 16 bytes, spaces inside
check(get(anyrx) == b"A name with 16 ch"[:16], "16-byte name with spaces kept intact")
p.send_signal(signal.SIGTERM); p.wait()
print("PASS" if ok else "FAILED"); sys.exit(0 if ok else 1)
