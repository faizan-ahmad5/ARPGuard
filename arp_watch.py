"""
Passively monitors ARP traffic on a network interface, learns trusted
IP -> MAC mappings, and raises an alert the moment an IP address starts
claiming a different MAC address than the one it was first seen with.

Usage:
    sudo python3 arp_watch.py

Requires:
    - Python 3.8+
    - Scapy (pip3 install scapy)
    - Root/sudo privileges (needed for raw packet capture)


For educational / defensive research use only. See README.md for the
ethical use disclaimer before running this against any network.
"""

from scapy.all import sniff, ARP

# --- Configuration ---------------------------------------------------------
# Set this to your network interface name. Run `ip a` to find it
# (e.g. "eth0", "ens33", "wlan0").
INTERFACE = "ens33"
# ----------------------------------------------------------------------------

# Trusted memory: { "ip_address": "mac_address" }
ip_mac_table = {}


def handle_packet(packet):
    """Runs once for every captured packet. Filters for ARP replies only,
    then either learns a new device or flags a mismatch."""

    # Only look at ARP packets, and only at replies (op == 2).
    # Replies are the only packets that assert "this IP belongs to me" --
    # exactly the claim an attacker forges.
    if packet.haslayer(ARP) and packet[ARP].op == 2:
        sender_ip = packet[ARP].psrc
        sender_mac = packet[ARP].hwsrc

        if sender_ip in ip_mac_table:
            known_mac = ip_mac_table[sender_ip]
            if known_mac != sender_mac:
                print("[ALERT] Possible ARP Spoofing detected!")
                print(f"        IP {sender_ip} was known as {known_mac}")
                print(f"        but now claims to be {sender_mac}")
            # If it matches, do nothing -- this is normal, expected traffic.
        else:
            # First time seeing this IP -- trust it and store it.
            ip_mac_table[sender_ip] = sender_mac
            print(f"[INFO] Learned new device: {sender_ip} -> {sender_mac}")


if __name__ == "__main__":
    print(f"[*] ARPGuard starting on interface '{INTERFACE}'...")
    print("[*] Listening for ARP traffic. Press Ctrl+C to stop.\n")
    sniff(iface=INTERFACE, filter="arp", prn=handle_packet, store=0)
