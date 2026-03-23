# 🔍 Network Recon Toolkit

> Python scripts for network reconnaissance and scanning — built for ethical security assessments.

![Python](https://img.shields.io/badge/python-3.8%2B-blue)
![Security](https://img.shields.io/badge/use-ethical__only-red)

## 📁 Project Structure

```
network-recon-toolkit/
├── scripts/
│   ├── host_discovery.py      # ICMP ping sweep to find live hosts
│   ├── port_scanner.py        # Multi-threaded TCP port scanner
│   └── service_fingerprint.py # Banner grabbing & service identification
├── requirements.txt
└── README.md
```

## 🛠️ Usage

```bash
# Discover live hosts on a subnet
python scripts/host_discovery.py --network 192.168.1.0/24

# Scan ports on a target
python scripts/port_scanner.py --target 192.168.1.1 --ports 1-1024

# Fingerprint services on specific ports
python scripts/service_fingerprint.py --target 192.168.1.1 --ports 22,80,443
```

## ⚠️ Disclaimer

These tools are intended for **authorized security testing only**.
Always ensure you have **explicit written permission** before scanning any network or system.

## 👤 Author

[chetan-1702](https://github.com/chetan-1702) · Porto Business School — Business Analytics & AI
