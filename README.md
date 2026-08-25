# ARPGuard — Real-Time ARP Spoofing Detection Tool

A lightweight, passive Python tool that detects ARP Spoofing / MITM attacks on a local network in real time — built and tested in an isolated VM lab using Kali Linux (attacker) and Ubuntu Server (victim/detector).

> Built as a hands-on cybersecurity project to understand ARP-layer attacks from both the offensive and defensive side.

---

## The Problem

ARP (Address Resolution Protocol) has no built-in authentication. Any device on a network can falsely claim to own an IP address it doesn't, tricking other devices into sending their traffic to the wrong place. This is called **ARP Spoofing**, and it's the foundation of most local-network Man-in-the-Middle (MITM) attacks — it's trivial to perform, invisible to the victim, and most home/small-office networks have zero visibility into it.

## The Solution

**ARPGuard** passively sniffs ARP traffic, learns which MAC address each IP address belongs to, and instantly raises an alert if that mapping ever changes — which is exactly the fingerprint an ARP spoofing attack leaves behind.

```
[INFO] Learned new device: 192.168.100.1 -> 00:50:56:c0:00:01
[INFO] Learned new device: 192.168.100.131 -> 00:0c:29:c9:2e:db
[ALERT] Possible ARP Spoofing detected!
        IP 192.168.100.1 was known as 00:50:56:c0:00:01
        but now claims to be 00:0c:29:c9:2e:db
```

---

## How It Works

1. **Listen** — passively sniffs ARP traffic on a chosen network interface using [Scapy](https://scapy.net/). No packets are injected, so there is zero impact on the network.
2. **Learn** — the first time an IP address is seen, its MAC address is trusted and stored in memory (`IP → MAC`).
3. **Compare** — every subsequent ARP reply for that IP is checked against the stored MAC.
4. **Alert** — if the MAC address ever changes for an IP already known, the tool immediately prints a timestamped alert identifying the spoofed IP, the expected MAC, and the fraudulent MAC.

For the full line-by-line code walkthrough and a worked example, see [`docs/ARP_Spoofing_Detector_Report.docx`](docs/ARP_Spoofing_Detector_Report.docx).

---

## Lab Setup Used for Testing

| Role              | OS                       | Network Mode         | IP              |
| ----------------- | ------------------------ | -------------------- | --------------- |
| Attacker          | Kali Linux               | Host-only (isolated) | 192.168.100.131 |
| Victim / Detector | Ubuntu Server            | Host-only (isolated) | 192.168.100.130 |
| Gateway (virtual) | VMware Host-only gateway | -                    | 192.168.100.1   |

All testing was performed inside an isolated **Host-only virtual network** in VMware Workstation Pro, so no real device or network was ever affected. See the full report for the complete setup walkthrough.

---

## Requirements

- Python 3.8+
- [Scapy](https://scapy.net/)
- Linux (tested on Ubuntu Server 24.04 / Kali Linux)
- Root/sudo privileges (required for raw packet capture)

Install dependencies:

```bash
sudo apt update
sudo apt install python3 python3-pip -y
pip3 install -r requirements.txt --break-system-packages
```

---

## Usage

1. Find your network interface name:

```bash
ip a
```

2. Edit `arp_watch.py` and set the `iface` value to match your interface (e.g. `"eth0"` or `"ens33"`):

```python
sniff(iface="ens33", filter="arp", prn=handle_packet, store=0)
```

3. Run the detector (requires root):

```bash
sudo python3 arp_watch.py
```

4. Let it run for a minute to learn the network's normal IP–MAC mappings, then leave it running. Any ARP spoofing attempt will trigger an immediate `[ALERT]` in the terminal.

---

## Attack Simulation (for testing, lab use only)

To reproduce the detection in your own isolated lab:

```bash
# On the attacker machine
echo 1 | sudo tee /proc/sys/net/ipv4/ip_forward
sudo apt install dsniff -y
sudo arpspoof -i eth0 -t <victim_ip> <gateway_ip>
```

**Only run this against machines and networks you own or have explicit written authorization to test.** ARP spoofing on networks you don't control is illegal in most jurisdictions. See [Ethical Use](#-ethical-use--disclaimer) below.

---

## Repository Structure

```
arpguard/
├── arp_watch.py              # Main detection script
├── requirements.txt          # Python dependencies
├── README.md                 # This file
├── LICENSE                   # MIT License
├── .gitignore
└── docs/
    └── ARP_Spoofing_Detector_Report.docx   # Full project report (setup, screenshots, mechanism explained)
```

---

## Roadmap / Future Improvements

- [ ] Reduce alert noise — group repeated forged packets from the same attack into a single alert with a live counter
- [ ] Persistent logging to file/CSV with timestamps for post-incident review
- [ ] Automated mitigation — restore correct static ARP entries or block the attacker's MAC via firewall rules
- [ ] Web-based live dashboard (Flask) for non-technical users
- [ ] Extend detection to DNS spoofing and rogue DHCP server detection using the same passive-monitoring approach

---

## Ethical Use & Disclaimer

This project was built and tested exclusively inside an isolated virtual lab (Host-only network) consisting of machines under the author's own control, for educational and defensive research purposes only.

ARP spoofing and other Man-in-the-Middle techniques are **illegal to perform against any network or device without explicit authorization** (e.g. under the Computer Fraud and Abuse Act in the US, and equivalent laws elsewhere). The author and contributors of this repository accept no responsibility for misuse of this tool. Use it only on networks you own or are explicitly authorized to test.

---

## License

This project is licensed under the MIT License — see [LICENSE](LICENSE) for details.

---

## Author

Built as a personal cybersecurity learning project — exploring ARP-layer attacks and detection from both the attacker's and defender's perspective, as a step toward SOC Analyst / Blue Team work.

Feel free to open an issue or pull request if you'd like to contribute an improvement from the roadmap above.
