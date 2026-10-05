#!/usr/bin/env bash
set -euo pipefail

# Axonwall Network Namespace Lab
# Creates isolated namespaces to test real Linux nftables firewall rulesets in CI or local dev

COMMAND="${1:-setup}"

cleanup() {
  echo "[netns-lab] Cleaning up namespaces..."
  ip netns del axon-wan 2>/dev/null || true
  ip netns del axon-router 2>/dev/null || true
  ip netns del axon-lan 2>/dev/null || true
  ip link del veth-wan-host 2>/dev/null || true
  ip link del veth-lan-host 2>/dev/null || true
  echo "[netns-lab] Cleanup complete."
}

if [ "$COMMAND" = "teardown" ]; then
  cleanup
  exit 0
fi

cleanup

echo "[netns-lab] Creating network namespaces..."
ip netns add axon-wan
ip netns add axon-router
ip netns add axon-lan

echo "[netns-lab] Creating veth pairs..."
# WAN veth pair: veth-wan-host <-> veth-wan-rtr
ip link add veth-wan-host type veth peer name veth-wan-rtr
ip link set veth-wan-host netns axon-wan
ip link set veth-wan-rtr netns axon-router
ip netns exec axon-router ip link set veth-wan-rtr name eth0

# LAN veth pair: veth-lan-host <-> veth-lan-rtr
ip link add veth-lan-host type veth peer name veth-lan-rtr
ip link set veth-lan-host netns axon-lan
ip link set veth-lan-rtr netns axon-router
ip netns exec axon-router ip link set veth-lan-rtr name eth1

echo "[netns-lab] Configuring IP addressing..."
# WAN namespace (Simulates upstream Internet / ISP)
ip netns exec axon-wan ip addr add 192.168.1.1/24 dev veth-wan-host
ip netns exec axon-wan ip link set veth-wan-host up
ip netns exec axon-wan ip link set lo up

# Router namespace (Axonwall appliance)
ip netns exec axon-router ip addr add 192.168.1.100/24 dev eth0
ip netns exec axon-router ip addr add 192.168.100.1/24 dev eth1
ip netns exec axon-router ip link set eth0 up
ip netns exec axon-router ip link set eth1 up
ip netns exec axon-router ip link set lo up
ip netns exec axon-router sysctl -w net.ipv4.ip_forward=1 >/dev/null

# Set default route in router out eth0
ip netns exec axon-router ip route add default via 192.168.1.1 dev eth0

# LAN namespace (Simulates client machine)
ip netns exec axon-lan ip addr add 192.168.100.50/24 dev veth-lan-host
ip netns exec axon-lan ip link set veth-lan-host up
ip netns exec axon-lan ip link set lo up
ip netns exec axon-lan ip route add default via 192.168.100.1 dev veth-lan-host

echo "[netns-lab] Network topology established:"
echo "  [axon-lan: 192.168.100.50] ---> [axon-router: eth1 192.168.100.1 | eth0 192.168.1.100] ---> [axon-wan: 192.168.1.1]"
