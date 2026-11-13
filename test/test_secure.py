#!/usr/bin/env python3
"""Secure VBAN through the hub, on 127.0.0.1. Usage: test_secure.py <vbanhub binary> <SDK build dir>

Devices are the SDK tools (vban_cert, vban_send, vban_recv --hub). Checks:
  - `vbanhub cert init / sign / revoke / status` (the router's CA)
  - secure sender -> hub -> plain receiver (bridge to Voicemeeter-style receivers)
  - secure sender -> hub -> secure receiver (re-encrypted per receiver)
  - plain sender  -> hub -> secure receiver
  - plain packets naming a certificate-bound stream are not routed (no IP spoofing)
  - status.json lists the secure peers
  - revoking the sender's serial + SIGHUP cuts its live session and refuses a new one
"""
import json, os, signal, socket, struct, subprocess, sys, tempfile, time

hub_bin, sdk = os.path.abspath(sys.argv[1]), os.path.abspath(sys.argv[2])
T = tempfile.mkdtemp(prefix="vbsec-")
PKI = os.path.join(T, "pki")
env = dict(os.environ, VBANHUB_PKI=PKI)
HUB_PORT, PLAIN_RX, SEC_RX_PORT = 16980, 17101, 17102
fails = 0


def check(name, ok, extra=""):
    global fails
    print(("PASS " if ok else "FAIL ") + name + (" (" + extra + ")" if extra and not ok else ""))
    fails += 0 if ok else 1


def run(*a, **kw):
    return subprocess.run(a, capture_output=True, text=True, env=env, cwd=T, **kw)


def device(name, role):
    run(f"{sdk}/vban_cert", "key", f"{name}.key")
    run(f"{sdk}/vban_cert", "req", f"{name}.key", name, role, f"{name}.req")
    r = run(hub_bin, "cert", "sign", f"{name}.req", "30")
    open(os.path.join(T, f"{name}.crt"), "w").write(r.stdout)
    return r


# ---- the router's CA ----
r = run(hub_bin, "cert", "init", "Test CA", "5", "Test hub")
st = json.loads(r.stdout) if r.returncode == 0 else {}
check("cert init", st.get("ca", {}).get("name") == "Test CA" and st.get("hub", {}).get("valid") == 1, r.stderr)
check("CA key is 0600", oct(os.stat(os.path.join(PKI, "ca.key")).st_mode & 0o777) == "0o600")
check("init refuses a second CA", run(hub_bin, "cert", "init", "Again", "5", "Hub").returncode != 0)
open(os.path.join(T, "ca.crt"), "w").write(run(hub_bin, "cert", "export-ca").stdout)
check("sign a transmitter", device("Mic", "tx").returncode == 0)
check("sign a receiver", device("Listener", "rx").returncode == 0)
run(f"{sdk}/vban_cert", "key", "bad.key")
run(f"{sdk}/vban_cert", "req", "bad.key", "Rogue hub", "hub", "bad.req")
check("refuse to sign a hub role for a device", run(hub_bin, "cert", "sign", "bad.req", "30").returncode != 0)
run(f"{sdk}/vban_cert", "key", "dup.key")
run(f"{sdk}/vban_cert", "req", "dup.key", "Mic", "tx", "dup.req")
r = run(hub_bin, "cert", "sign", "dup.req", "30")
check("refuse a second live certificate with the same name", r.returncode != 0 and "already exists" in r.stderr, r.stderr)
st = json.loads(run(hub_bin, "cert", "status").stdout)
mic_serial = [x["serial"] for x in st["issued"] if x["name"] == "Mic"][0]
check("status lists issued certificates", sorted(x["name"] for x in st["issued"]) == ["Listener", "Mic"])

# ---- hub config: TAB format with src_cert / dst_cert ----
conf = os.path.join(T, "hub.conf")
open(conf, "w").write(
    "master\t100\n"
    f"route\t*\tStream1\t127.0.0.1\t{PLAIN_RX}\tPlainOut\t100\tMic\t\n"        # secure -> plain
    f"route\t*\tStream1\t*\t0\tSecOut\t100\tMic\tListener\n"                 # secure -> secure
    f"route\t127.0.0.1\tPlainSrc\t*\t0\tSecOut\t100\t\tListener\n")          # plain -> secure
status = os.path.join(T, "status.json")
hub = subprocess.Popen([hub_bin, "-p", str(HUB_PORT), "-c", conf, "-s", status, "-K", PKI],
                       stderr=subprocess.PIPE, text=True)
time.sleep(0.5)

plain = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
plain.bind(("127.0.0.1", PLAIN_RX))
plain.settimeout(0.2)

# secure receiver connects to the hub
srx = subprocess.Popen([f"{sdk}/vban_recv", "-p", str(SEC_RX_PORT), "-n", "SecOut", "-q", "--hub", f"127.0.0.1:{HUB_PORT}",
                        "--ca", "ca.crt", "--cert", "Listener.crt", "--key", "Listener.key"],
                       cwd=T, stdout=open(os.path.join(T, "sec.raw"), "wb"), stderr=subprocess.PIPE)
time.sleep(1.0)
stx = subprocess.Popen([f"{sdk}/vban_send", "-i", "127.0.0.1", "-p", str(HUB_PORT), "-n", "Stream1",
                        "--ca", "ca.crt", "--cert", "Mic.crt", "--key", "Mic.key"], cwd=T, stderr=subprocess.PIPE)

# collect the plain bridge output for ~2.5 s
names, n_plain, t0 = set(), 0, time.time()
while time.time() - t0 < 2.5:
    try:
        d = plain.recv(2048)
        n_plain += 1
        names.add(d[8:24].rstrip(b"\0"))
    except socket.timeout:
        pass
check("secure sender -> plain receiver (bridge)", n_plain > 1500 and names == {b"PlainOut"}, f"{n_plain} {names}")

# spoof: plain packets claiming the secure stream from the same IP
spoof = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
before = n_plain
for fc in range(50):
    spoof.sendto(b"VBAN" + bytes([3, 63, 1, 1]) + b"Stream1".ljust(16, b"\0") + struct.pack("<I", fc) + bytes(256),
                 ("127.0.0.1", HUB_PORT))
# plain sender -> secure receiver
for fc in range(300):
    spoof.sendto(b"VBAN" + bytes([3, 63, 1, 1]) + b"PlainSrc".ljust(16, b"\0") + struct.pack("<I", fc) + bytes(256),
                 ("127.0.0.1", HUB_PORT))
    time.sleep(0.002)
time.sleep(2.5)
st = json.load(open(status))
routes = st["routes"]
check("plain packets do not match certificate-bound routes", routes[0]["pkts"] > 1500 and routes[2]["pkts"] == 300,
      str([r["pkts"] for r in routes]))
check("secure -> secure and plain -> secure delivered", routes[1]["pkts"] > 1500 and st["secure"]["no_peer"] < 5,
      json.dumps(st["secure"]))
peers = sorted(p["name"] for p in st["secure"]["peers"])
check("status lists the secure peers", peers == ["Listener", "Mic"], str(peers))

# revoke the transmitter after 300 other revocations (no list size limit): its session ends at
# the next reload, and it cannot come back
with open(os.path.join(PKI, "revoked"), "a") as f:
    for k in range(300):
        f.write("%d\n" % (10**12 + k))
r = run(hub_bin, "cert", "revoke", mic_serial)
check("revoke", r.returncode == 0 and any(x["revoked"] for x in json.loads(r.stdout)["issued"]))
hub.send_signal(signal.SIGHUP)
time.sleep(0.5)
plain.setblocking(False)
try:
    while True:
        plain.recv(2048)            # drop what queued up while this script was not reading
except BlockingIOError:
    pass
plain.settimeout(0.2)
n_after, t0 = 0, time.time()
while time.time() - t0 < 2.5:
    try:
        plain.recv(2048)
        n_after += 1
    except socket.timeout:
        pass
check("revoked sender is cut off", n_after < 20, f"{n_after} packets after revocation")

for p in (stx, srx):
    p.send_signal(signal.SIGINT)
    p.wait(5)
hub.terminate()
hub.wait(5)
raw = open(os.path.join(T, "sec.raw"), "rb").read()
samples = struct.unpack("<%dh" % (len(raw) // 2), raw[: len(raw) // 2 * 2])
nz = sum(1 for x in samples if x)
check("secure receiver got the tone through the hub", nz > 48000 and max(abs(x) for x in samples) == 8192,
      f"nonzero {nz}")
print("ALL PASS" if not fails else f"{fails} FAILED")
sys.exit(1 if fails else 0)
