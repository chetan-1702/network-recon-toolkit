#!/usr/bin/env python3
"""
Multi-threaded TCP Port Scanner
Scans a target host for open TCP ports using concurrent connections.

Usage:
    python port_scanner.py --target 192.168.1.1 --ports 1-1024
    python port_scanner.py --target 192.168.1.1 --ports 80,443,8080,8443
"""

import argparse
import socket
import concurrent.futures
from datetime import datetime

COMMON_SERVICES = {
    21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP",
    53: "DNS", 80: "HTTP", 110: "POP3", 143: "IMAP",
    443: "HTTPS", 445: "SMB", 3306: "MySQL", 3389: "RDP",
    5432: "PostgreSQL", 6379: "Redis", 8080: "HTTP-Alt",
    8443: "HTTPS-Alt", 27017: "MongoDB", 9200: "Elasticsearch"
}


def scan_port(target: str, port: int, timeout: float = 1.0) -> tuple:
    """Attempt a TCP connection and return (port, is_open, service)."""
    try:
        with socket.create_connection((target, port), timeout=timeout):
            return port, True, COMMON_SERVICES.get(port, "unknown")
    except (socket.timeout, ConnectionRefusedError, OSError):
        return port, False, ""


def parse_ports(port_str: str) -> list:
    """Parse port string like '1-1024' or '80,443,8080' into a list."""
    ports = []
    for part in port_str.split(","):
        part = part.strip()
        if "-" in part:
            start, end = part.split("-")
            ports.extend(range(int(start), int(end) + 1))
        else:
            ports.append(int(part))
    return sorted(set(ports))


def scan_target(target: str, ports: list, threads: int = 200) -> list:
    """
    Scan a target for open ports.

    Args:
        target:  IP address or hostname
        ports:   List of port numbers to scan
        threads: Number of concurrent threads

    Returns:
        Sorted list of dicts with open port details
    """
    print(f"[*] Target:    {target}")
    print(f"[*] Ports:     {min(ports)}-{max(ports)} ({len(ports)} total)")
    print(f"[*] Threads:   {threads}")
    print(f"[*] Started:   {datetime.now().strftime('%H:%M:%S')}\n")
    print(f"{'PORT':<12} {'STATE':<10} {'SERVICE'}")
    print("-" * 40)

    open_ports = []

    with concurrent.futures.ThreadPoolExecutor(max_workers=threads) as executor:
        futures = {executor.submit(scan_port, target, p): p for p in ports}
        for future in concurrent.futures.as_completed(futures):
            port, is_open, service = future.result()
            if is_open:
                open_ports.append({"port": port, "service": service})
                print(f"{str(port) + '/tcp':<12} {'open':<10} {service}")

    open_ports.sort(key=lambda x: x["port"])
    print(f"\n[*] Done. {len(open_ports)} open port(s) found on {target}.")
    return open_ports


def main():
    parser = argparse.ArgumentParser(description="Multi-threaded TCP port scanner")
    parser.add_argument("--target", "-t", required=True, help="Target IP or hostname")
    parser.add_argument(
        "--ports", "-p", default="1-1024",
        help="Ports to scan: range '1-1024' or list '80,443,8080' (default: 1-1024)"
    )
    parser.add_argument(
        "--threads", "-T", type=int, default=200,
        help="Concurrent threads (default: 200)"
    )
    args = parser.parse_args()
    scan_target(args.target, parse_ports(args.ports), args.threads)


if __name__ == "__main__":
    main()
