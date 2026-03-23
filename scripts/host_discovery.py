#!/usr/bin/env python3
"""
Host Discovery Script
Discovers live hosts on a network using concurrent ICMP ping sweep.

Usage:
    python host_discovery.py --network 192.168.1.0/24
    python host_discovery.py --network 10.0.0.0/16 --threads 200
"""

import argparse
import ipaddress
import subprocess
import concurrent.futures
from datetime import datetime


def ping_host(ip: str, timeout: int = 1) -> tuple:
    """Send a single ICMP ping to a host and return (ip, is_alive)."""
    try:
        result = subprocess.run(
            ["ping", "-c", "1", "-W", str(timeout), str(ip)],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            timeout=timeout + 1
        )
        return str(ip), result.returncode == 0
    except Exception:
        return str(ip), False


def discover_hosts(network: str, threads: int = 100) -> list:
    """
    Discover live hosts in a network using concurrent ping sweep.

    Args:
        network: CIDR notation network (e.g. 192.168.1.0/24)
        threads: Number of concurrent threads

    Returns:
        Sorted list of live host IP addresses
    """
    try:
        net = ipaddress.ip_network(network, strict=False)
    except ValueError as e:
        print(f"[!] Invalid network: {e}")
        return []

    hosts = list(net.hosts())
    live_hosts = []

    print(f"[*] Scanning {len(hosts)} hosts in {network}")
    print(f"[*] Using {threads} threads")
    print(f"[*] Started at {datetime.now().strftime('%H:%M:%S')}\n")

    with concurrent.futures.ThreadPoolExecutor(max_workers=threads) as executor:
        futures = {executor.submit(ping_host, str(ip)): ip for ip in hosts}
        for future in concurrent.futures.as_completed(futures):
            ip, is_alive = future.result()
            if is_alive:
                print(f"[+] Host UP: {ip}")
                live_hosts.append(ip)

    print(f"\n[*] Scan complete. Found {len(live_hosts)} live host(s).")
    return sorted(live_hosts, key=lambda x: list(map(int, x.split("."))))


def main():
    parser = argparse.ArgumentParser(
        description="Network host discovery via ICMP ping sweep"
    )
    parser.add_argument(
        "--network", "-n",
        required=True,
        help="Target network in CIDR notation (e.g. 192.168.1.0/24)"
    )
    parser.add_argument(
        "--threads", "-t",
        type=int, default=100,
        help="Number of concurrent threads (default: 100)"
    )
    args = parser.parse_args()
    live = discover_hosts(args.network, args.threads)

    if live:
        print("\n[*] Live hosts:")
        for host in live:
            print(f"    {host}")


if __name__ == "__main__":
    main()
