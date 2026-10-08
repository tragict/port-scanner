#!/usr/bin/env python3
"""
portscan.py -- fast multithreaded TCP port scanner for authorized
bug-bounty reconnaissance.

LEGAL: only scan targets you own or have explicit permission to test
(e.g. within a bug bounty program's scope). Unauthorized scanning
may be illegal in your jurisdiction.

Usage:
    python3 portscan.py 192.168.1.1
    python3 portscan.py example.com -p 80,443,8000-8100
    python3 portscan.py 10.0.0.0/24 -p 1-1000 -t 200
    python3 portscan.py target.com -p 1-65535 -o results.json

Stdlib only -- no dependencies.
"""

import argparse
import concurrent.futures
import ipaddress
import json
import socket
import sys
import time

# Common ports worth checking first in a bounty context
TOP_PORTS = [
    21, 22, 23, 25, 53, 80, 81, 88, 110, 111, 135, 139, 143, 443, 445,
    465, 514, 515, 993, 995, 1080, 1433, 1521, 1723, 2049, 2121, 2181,
    2375, 2376, 3000, 3306, 3389, 3632, 4369, 4444, 4567, 5000, 5060,
    5432, 5632, 5672, 5900, 5985, 5986, 6379, 6443, 7001, 8000, 8008,
    8080, 8081, 8443, 8888, 9000, 9001, 9042, 9090, 9100, 9200, 9300,
    11211, 27017, 27018, 50070,
]


def parse_ports(spec):
    """'80,443,8000-8100' -> sorted list of valid ports."""
    ports = set()
    for part in spec.split(","):
        part = part.strip()
        if not part:
            continue
        if "-" in part:
            a, b = part.split("-", 1)
            lo, hi = int(a), int(b)
            if lo > hi:
                lo, hi = hi, lo
            ports.update(range(lo, hi + 1))
        else:
            ports.add(int(part))
    ports = sorted(p for p in ports if 1 <= p <= 65535)
    if not ports:
        raise ValueError("no valid ports in %r" % spec)
    return ports


def expand_targets(target):
    """IP, hostname, or CIDR -> list of target strings."""
    try:
        net = ipaddress.ip_network(target, strict=False)
        hosts = [str(h) for h in net.hosts()]
        return hosts or [str(net.network_address)]
    except ValueError:
        return [target]  # plain IP or hostname


def service_name(port):
    try:
        return socket.getservbyport(port, "tcp")
    except OSError:
        return "?"


def grab_banner(sock, timeout=1.5):
    """Try a passive read, then nudge quiet services (e.g. HTTP)."""
    sock.settimeout(timeout)
    try:
        data = sock.recv(2048)
        if data:
            return data
    except (socket.timeout, OSError):
        pass
    try:
        sock.sendall(b"HEAD / HTTP/1.0\r\nHost: scan\r\n\r\n")
        return sock.recv(2048)
    except (socket.timeout, OSError):
        return b""


def scan_port(ip, port, timeout):
    """Returns a result dict if open, else None."""
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(timeout)
    try:
        s.connect((ip, port))
    except (socket.timeout, OSError):
        s.close()
        return None
    try:
        banner = grab_banner(s)
    finally:
        s.close()
    text = banner.decode("utf-8", "replace").split("\n")[0].strip()[:120]
    return {"port": port, "service": service_name(port), "banner": text}


def scan_host(host, ports, timeout, threads):
    try:
        ip = socket.gethostbyname(host)
    except socket.gaierror:
        return {"target": host, "ip": None, "error": "could not resolve", "open": []}
    found = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=threads) as ex:
        futs = {ex.submit(scan_port, ip, p, timeout): p for p in ports}
        try:
            for fut in concurrent.futures.as_completed(futs):
                r = fut.result()
                if r:
                    found.append(r)
                    b = ("  " + r["banner"]) if r["banner"] else ""
                    print(f"  [+] {host} ({ip}):{r['port']:<6} {r['service']}{b}",
                          flush=True)
        except KeyboardInterrupt:
            ex.shutdown(wait=False, cancel_futures=True)
            raise
    found.sort(key=lambda r: r["port"])
    return {"target": host, "ip": ip, "open": found}


def main():
    ap = argparse.ArgumentParser(
        description="Fast multithreaded TCP port scanner. "
                    "Only scan targets you are authorized to test.")
    ap.add_argument("target", help="IP, hostname, or CIDR (e.g. 10.0.0.0/24)")
    ap.add_argument("-p", "--ports", default=",".join(map(str, TOP_PORTS)),
                    help="ports: '80,443' or '1-1000' (default: common list)")
    ap.add_argument("-t", "--threads", type=int, default=100,
                    help="concurrent connections (default: 100)")
    ap.add_argument("--timeout", type=float, default=1.0,
                    help="seconds per connection attempt (default: 1.0)")
    ap.add_argument("-o", "--output",
                    help="write results to file (.json for JSON, else text)")
    args = ap.parse_args()

    try:
        ports = parse_ports(args.ports)
    except ValueError as e:
        sys.exit(f"error: {e}")

    targets = expand_targets(args.target)
    print(f"[*] scanning {len(targets)} host(s) x {len(ports)} ports "
          f"({args.threads} threads, {args.timeout}s timeout)")
    t0 = time.time()

    results = []
    try:
        for i, host in enumerate(targets, 1):
            if len(targets) > 1:
                print(f"[*] [{i}/{len(targets)}] {host}")
            results.append(scan_host(host, ports, args.timeout, args.threads))
    except KeyboardInterrupt:
        print("\n[!] interrupted by user")

    elapsed = time.time() - t0
    total_open = sum(len(r["open"]) for r in results)
    print(f"\n[*] done in {elapsed:.1f}s -- "
          f"{total_open} open port(s) on {len(results)} host(s)")

    if args.output:
        if args.output.endswith(".json"):
            with open(args.output, "w") as f:
                json.dump(results, f, indent=2)
        else:
            with open(args.output, "w") as f:
                for r in results:
                    f.write(f"# {r['target']} ({r.get('ip') or r.get('error')})\n")
                    for p in r["open"]:
                        f.write(f"{p['port']}/tcp  {p['service']}  {p['banner']}\n")
        print(f"[*] results written to {args.output}")


if __name__ == "__main__":
    main()
