# Sourced by the VM scripts: netns src (10.0.1.2) -- hub (10.0.1.1 | 10.0.2.1) -- netns dst (10.0.2.2).
ip link set lo up
ip netns add src; ip netns add dst
# Fixed MACs: udev in the VM otherwise rewrites veth MACs after creation and stale neighbour
# entries make the forwarded baseline drop everything as OTHERHOST.
ip link add hs address 02:00:00:00:01:01 type veth peer name s0 address 02:00:00:00:01:02 netns src
ip link add hd address 02:00:00:00:02:01 type veth peer name d0 address 02:00:00:00:02:02 netns dst
ip addr add 10.0.1.1/24 dev hs; ip link set hs up
ip addr add 10.0.2.1/24 dev hd; ip link set hd up
ip -n src addr add 10.0.1.2/24 dev s0; ip -n src link set s0 up; ip -n src link set lo up
ip -n dst addr add 10.0.2.2/24 dev d0; ip -n dst link set d0 up; ip -n dst link set lo up
ip -n src route add default via 10.0.1.1
ip -n dst route add default via 10.0.2.1
# Real UDP checksums end to end (veth would otherwise leave them to "hardware" and nobody checks).
ip netns exec src ethtool -K s0 tx off >/dev/null 2>&1 || true
echo 1 > /proc/sys/net/ipv4/ip_forward
ip netns exec src ping -c1 -W1 10.0.2.2 >/dev/null   # resolve neighbours

