# portscan.py

Fast multithreaded TCP port scanner for authorized bug-bounty reconnaissance.
Pure Python stdlib — no dependencies, runs anywhere Python 3 does.

## Features

- Scan a single IP, hostname, or full CIDR range (`10.0.0.0/24`)
- Sensible common-port list by default, or custom ranges (`-p 80,443,8000-8100`, `-p 1-65535`)
- Banner grabbing for service fingerprinting
- Threaded scanning (tunable with `-t`), per-connection timeout (`--timeout`)
- Results to console, JSON (`-o results.json`), or text

## Usage

```bash
python3 portscan.py target.com
python3 portscan.py 192.168.1.1 -p 22,80,443,8080
python3 portscan.py 10.0.0.0/24 -p 1-1000 -t 200 -o results.json
python3 portscan.py target.com -p 1-65535 --timeout 0.5 -o full.json
```

## Legal

Only scan targets you own or have explicit permission to test (e.g. within a
bug bounty program's scope). Unauthorized port scanning may be illegal in your
jurisdiction. You are responsible for how you use this tool.
