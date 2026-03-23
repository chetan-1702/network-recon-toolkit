#!/usr/bin/env python3
"""
Service Fingerprinting Tool
Grabs banners from open ports to identify running services and versions.

Usage:
    python service_fingerprint.py --target 192.168.1.1
    python service_fingerprint.py --target 192.168.1.1 --ports 22,80,443,21
"""

import argparse
import socket
import ssl
import re

HTTP_PORTS  = {80, 8080, 8000, 8888}
HTTPS_PORTS = {443, 8443}
SMTP_PORTS  = {25, 465, 587}


def grab_banner(target: str, port: int, timeout: float = 3.0):
    """Connect to a port and attempt banner retrieval. Returns banner string or None."""
    try:
        if port in HTTPS_PORTS:
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            with socket.create_connection((target, port), timeout=timeout) as raw:
                with ctx.wrap_socket(raw, server_hostname=target) as sock:
                    sock.send(b"GET / HTTP/1.0\r\nHost: " + target.encode() + b"\r\n\r\n")
                    return sock.recv(2048).decode("utf-8", errors="ignore")

        with socket.create_connection((target, port), timeout=timeout) as sock:
            if port in HTTP_PORTS:
                sock.send(b"GET / HTTP/1.0\r\nHost: " + target.encode() + b"\r\n\r\n")
            elif port in SMTP_PORTS:
                sock.send(b"EHLO probe\r\n")
            else:
                sock.send(b"\r\n")
            return sock.recv(2048).decode("utf-8", errors="ignore")
    except Exception:
        return None


def identify_service(banner: str, port: int) -> str:
    """Extract service/version info from a banner string."""
    if not banner:
        return "No banner received"

    patterns = [
        (r"(SSH-[\d.]+-\S+)",          "SSH"),
        (r"(OpenSSH[_\S ]+)",            "OpenSSH"),
        (r"HTTP/[\d.]+ (\d+)",          "HTTP"),
        (r"Server: ([^\r\n]+)",         "Server"),
        (r"(Apache/[\d.]+)",             "Apache"),
        (r"(nginx/[\d.]+)",              "Nginx"),
        (r"220[- ]([^\r\n]{1,60})",     "SMTP/FTP"),
    ]
    for pattern, label in patterns:
        m = re.search(pattern, banner, re.IGNORECASE)
        if m:
            return f"{label}: {m.group(1).strip()}"

    first_line = banner.strip().split("\n")[0][:80].strip()
    return first_line if first_line else "Unknown service"


def fingerprint(target: str, ports: list) -> None:
    """Run banner grabbing across a list of ports and print results."""
    print(f"[*] Fingerprinting {target}\n")
    print(f"{'PORT':<12} {'STATUS':<8} {'SERVICE / BANNER'}")
    print("-" * 72)

    for port in sorted(ports):
        banner  = grab_banner(target, port)
        info    = identify_service(banner, port) if banner else "No response"
        status  = "open" if banner is not None else "filtered"
        print(f"{str(port)+'/tcp':<12} {status:<8} {info}")

    print(f"\n[*] Fingerprinting complete for {len(ports)} port(s).")


def main():
    parser = argparse.ArgumentParser(description="Service fingerprinting via banner grabbing")
    parser.add_argument("--target", "-t", required=True, help="Target IP or hostname")
    parser.add_argument(
        "--ports", "-p", default="21,22,25,80,443,8080",
        help="Comma-separated ports (default: 21,22,25,80,443,8080)"
    )
    args = parser.parse_args()
    fingerprint(args.target, [int(p) for p in args.ports.split(",")])


if __name__ == "__main__":
    main()
