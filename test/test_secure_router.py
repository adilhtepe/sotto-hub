#!/usr/bin/env python3
"""Secure VBAN on the real router, without touching the running hub or /etc/vbanhub.
Usage: test_secure_router.py <ssh host> <hub binary already copied to /tmp/vbanhub-test> <SDK build dir>

A second hub instance runs on the router on port 16980 with a throw-away CA in /tmp/vbsec
(created beforehand with: VBANHUB_PKI=/tmp/vbsec/pki /tmp/vbanhub-test cert init ...). It is
started as root and drops to nobody, like the init script does. This host plays the devices:
N secure transmitters (vban_send), one secure receiver (vban_recv --hub) and one plain receiver.
Reports delivery, the router's CPU, and checks revocation by the unprivileged daemon.
"""
import json, os, signal, socket, struct, subprocess, sys, tempfile, time

host, sdk = sys.argv[1], os.path.abspath(sys.argv[3])
N = int(os.environ.get("STREAMS", "8"))
HUB_IP = os.environ.get("HUB_IP", "192.168.2.1")
ME = subprocess.run(["ip", "route", "get", HUB_IP], capture_output=True, text=True).stdout.split(" src ")[1].split()[0]
PORT, PLAIN = 16980, 17101
T = tempfile.mkdtemp(prefix="vbsec-rt-")
fails = 0


def ssh(cmd, **kw):
    return subprocess.run(["ssh", "-o", "BatchMode=yes", host, cmd], capture_output=True, text=True, **kw)


def check(name, ok, extra=""):
    global fails
    print(("PASS " if ok else "FAIL ") + name + ("" if ok or not extra else " (" + extra + ")"))
    fails += 0 if ok else 1


def device(name, role):
    subprocess.run([f"{sdk}/vban_cert", "key", f"{name}.key"], cwd=T, capture_output=True)
    subprocess.run([f"{sdk}/vban_cert", "req", f"{name}.key", name, role, f"{name}.req"], cwd=T, capture_output=True)
    r = subprocess.run(["ssh", "-o", "BatchMode=yes", host,
                        f"cat > /tmp/vbsec/{name}.req && VBANHUB_PKI=/tmp/vbsec/pki /tmp/vbanhub-test cert sign /tmp/vbsec/{name}.req 2"],
                       stdin=open(os.path.join(T, f"{name}.req")), capture_output=True, text=True)
    open(os.path.join(T, f"{name}.crt"), "w").write(r.stdout)
    return r.returncode == 0


open(os.path.join(T, "ca.crt"), "w").write(ssh("cat /tmp/vbsec/pki/ca.crt").stdout)
check("sign devices on the router", device("Mic", "tx") and device("Listener", "rx"))
mic_serial = [x["serial"] for x in json.loads(ssh("VBANHUB_PKI=/tmp/vbsec/pki /tmp/vbanhub-test cert status").stdout)["issued"]
              if x["name"] == "Mic"][0]
conf = ("master\t100\n"
        f"route\t*\t*\t{ME}\t{PLAIN}\tPlainOut\t100\tMic\t\n"
        f"route\t*\tTx0\t*\t0\tSecOut\t100\tMic\tListener\n")
ssh(f"printf '{conf}' > /tmp/vbsec/hub.conf; chmod 644 /tmp/vbsec/hub.conf; chmod 777 /tmp/vbsec; "
    f"(/tmp/vbanhub-test -p {PORT} -c /tmp/vbsec/hub.conf -s /tmp/vbsec/status.json -K /tmp/vbsec/pki -U nobody "
    f"</dev/null >/tmp/vbsec/hub.log 2>&1 &) ; sleep 0.5; pidof vbanhub-test")

plain = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
plain.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 4 << 20)
plain.bind(("0.0.0.0", PLAIN))
plain.settimeout(0.2)
srx = subprocess.Popen([f"{sdk}/vban_recv", "-p", "17102", "-n", "SecOut", "-q", "--hub", f"{HUB_IP}:{PORT}",
                        "--ca", "ca.crt", "--cert", "Listener.crt", "--key", "Listener.key"],
                       cwd=T, stdout=open(os.path.join(T, "sec.raw"), "wb"), stderr=subprocess.PIPE)
time.sleep(1.5)


def router_cpu():
    o = ssh("awk '/^cpu /{print $2+$3+$4+$7+$8}' /proc/stat; awk '{print $14+$15}' /proc/$(pidof vbanhub-test)/stat").stdout.split()
    return int(o[0]), int(o[1])


txs = [subprocess.Popen([f"{sdk}/vban_send", "-i", HUB_IP, "-p", str(PORT), "-n", f"Tx{i}",
                         "--ca", "ca.crt", "--cert", "Mic.crt", "--key", "Mic.key"], cwd=T,
                        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL) for i in range(N)]
time.sleep(2)
c0, h0, t0 = *router_cpu(), time.time()
n, t_end = 0, time.time() + 10
while time.time() < t_end:
    try:
        plain.recv(2048)
        n += 1
    except socket.timeout:
        pass
c1, h1, dt = *router_cpu(), time.time() - t0
rate = n / 10
check(f"{N} secure streams -> plain receiver through the router", rate > N * 740, f"{rate:.0f} pkt/s")
print(f"  router: {N} x 750 pkt/s encrypted in, {rate:.0f} pkt/s plain out + 750 encrypted out: "
      f"total CPU {(c1 - c0) / dt:.0f} % of a core, hub process {(h1 - h0) / dt:.0f} %")
st = json.loads(ssh("cat /tmp/vbsec/status.json").stdout)
print("  secure:", json.dumps({k: v for k, v in st["secure"].items() if k != "peers"}), "peers", len(st["secure"]["peers"]))
check("hub runs as nobody", ssh("awk '/^Uid/{print $2}' /proc/$(pidof vbanhub-test)/status").stdout.strip() == "65534")

# revocation, applied by the unprivileged daemon on SIGHUP
ssh(f"VBANHUB_PKI=/tmp/vbsec/pki /tmp/vbanhub-test cert revoke {mic_serial} >/dev/null; kill -HUP $(pidof vbanhub-test)")
time.sleep(1)
plain.setblocking(False)
try:
    while True:
        plain.recv(2048)
except BlockingIOError:
    pass
plain.settimeout(0.2)
n2, t_end = 0, time.time() + 3
while time.time() < t_end:
    try:
        plain.recv(2048)
        n2 += 1
    except socket.timeout:
        pass
check("revoked transmitter cut off (as nobody)", n2 < 50, f"{n2} packets")

for p in txs + [srx]:
    p.send_signal(signal.SIGINT)
for p in txs + [srx]:
    p.wait(5)
raw = open(os.path.join(T, "sec.raw"), "rb").read()
s = struct.unpack("<%dh" % (len(raw) // 2), raw[: len(raw) // 2 * 2])
check("secure receiver got Tx0 re-encrypted by the router", sum(1 for x in s if x) > 48000, f"{len(s)} samples")
print(ssh("cat /tmp/vbsec/hub.log").stdout.strip())
ssh("kill $(pidof vbanhub-test) 2>/dev/null; true")
print("ALL PASS" if not fails else f"{fails} FAILED")
sys.exit(1 if fails else 0)
