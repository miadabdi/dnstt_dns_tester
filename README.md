# dnstt DNS Tester

A two-stage toolkit for finding DNS servers that work with [dnstt](https://www.bamsoftware.com/software/dnstt/) — a DNS tunnel for censorship circumvention.

## Overview

| Stage | Script                  | Purpose                                                                              |
| ----- | ----------------------- | ------------------------------------------------------------------------------------ |
| 1     | `dnstt-dns-liveness.py` | Filter a large list of DNS IPs down to those that respond with **valid DNS replies** |
| 2     | `dnstt-dns-tester.py`   | Test each alive DNS server for end-to-end **dnstt** tunnel connectivity              |

Stage 1 validates responses properly (transaction ID, QR bit, RCODE, answer records) — not just "did something reply on port 53".

## Cross-Platform Support

Both scripts run on **Linux**, **macOS**, and **Windows**. Platform-specific
details (process management, file-descriptor limits, temp paths) are handled
automatically.

> On macOS or Windows you must compile or download the appropriate `dnstt-client`
> binary yourself and pass it via `--dnstt`.

## Requirements

- Python 3.7+
- `requests` with SOCKS support (`pip install requests[socks]`)
- A compiled `dnstt-client` binary for your platform
- A working dnstt server with its public key and domain

## Installation

Two install modes are supported:

- Online (preferred): installs from PyPI using `requirements.txt`.

```bash
python3 -m pip install -r requirements.txt
```

- Offline (no internet): use the bundled wheels in `vendor/`.

```bash
 # Unix
 bash install_deps.sh

 # Windows (cmd.exe)
 install_deps.bat
```

The installer scripts will try an online `pip install -r requirements.txt` first and automatically fall back to the `vendor/` wheels if offline.

## Quick Start

### Stage 1 — DNS Liveness Check

Filter your DNS list to only those servers that respond with valid DNS replies:

```bash
python3 dnstt-dns-liveness.py \
    --dns-list all_dns.txt \
    --output alive_dns.txt \
    --concurrent 200 \
    --timeout 5
```

Key options:

| Flag            | Default                 | Description                            |
| --------------- | ----------------------- | -------------------------------------- |
| `--dns-list`    | `dns-servers.txt`       | Input file with DNS IPs (one per line) |
| `--output`      | `alive_dns_servers.txt` | Output file for alive IPs              |
| `--output-json` | _(none)_                | Save full results as JSON              |
| `--concurrent`  | 50                      | Max parallel checks                    |
| `--timeout`     | 5.0                     | Seconds per query                      |
| `--attempts`    | 2                       | Retries per server                     |
| `--show-failed` | off                     | Show failed servers in output          |
| `--no-color`    | off                     | Disable colored terminal output        |

### Stage 2 — dnstt Connectivity Test

Test alive servers for actual dnstt tunnel connectivity:

```bash
python3 dnstt-dns-tester.py \
    --dnstt PATH_TO_DNSTT_BINARY \
    --dns-list alive_dns.txt \
    --pubkey YOUR_PUBLIC_KEY \
    --domain your.dnstt.domain \
    --max-concurrent 10 \
    --attempts 2
```

Key options:

| Flag               | Default                                | Description                       |
| ------------------ | -------------------------------------- | --------------------------------- |
| `--dnstt`          | `./dnstt-client-linux-amd64`           | Path to dnstt-client binary       |
| `--dns-list`       | `dns-servers.txt`                      | Input file with DNS IPs           |
| `--pubkey`         | _(required)_                           | dnstt server public key           |
| `--domain`         | _(required)_                           | dnstt domain                      |
| `--dns-port`       | 53                                     | DNS port                          |
| `--protocol`       | `udp`                                  | Transport: `udp`, `dot`, or `doh` |
| `--max-concurrent` | 3                                      | Parallel tests                    |
| `--attempts`       | 2                                      | HTTP attempts per server          |
| `--test-timeout`   | 90.0                                   | Overall timeout per server        |
| `--output`         | `dns_test_results.json`                | Full results JSON                 |
| `--output-working` | `working_dns_servers.txt`              | Working server IPs                |
| `--test-url`       | `https://www.gstatic.com/generate_204` | URL for connectivity test         |
| `--show-failed`    | off                                    | Show failed servers in output     |
| `--no-color`       | off                                    | Disable colored terminal output   |

## Terminal UI

Both scripts feature a clean terminal interface:

- **Live progress bar** with percentage, counts, elapsed time, and ETA
- **Color-coded output** — green for OK/alive, red for FAIL/dead (auto-disabled when piped)
- **Failures hidden by default** — only working servers are printed; use `--show-failed` to see everything
- **Graceful Ctrl+C** — any working servers discovered so far are saved before exiting

Example output during a run:

```
  OK        8.8.8.8  | 2/2 | Avg: 1.23s
  OK        1.1.1.1  | 2/2 | Avg: 0.98s
 █████░░░░░░░░░░░░░░░░░░░░  20% 1400/6968 | 12 OK | 1388 FAIL | 4m32s | ETA: 18m05s
```

## High Concurrency Notes

The liveness script is designed to handle 500+ concurrent checks:

- **File descriptor limit** is automatically raised at startup
- **Random jitter** prevents UDP burst congestion that causes false timeouts
- **2 attempts by default** compensate for single-packet UDP loss
- **Per-socket receive buffer** increased to reduce kernel drops

For best results at very high concurrency (500+), also raise the system UDP buffer:

```bash
sudo sysctl -w net.core.rmem_max=2097152
```

## Typical Workflow

```bash
# 1. Start with a large public DNS list
wc -l all_dns.txt          # e.g. 116k servers

# 2. Find which ones are alive (valid DNS responders)
python3 dnstt-dns-liveness.py --dns-list all_dns.txt --output alive_dns.txt

# 3. Test alive servers with dnstt
python3 dnstt-dns-tester.py --dns-list alive_dns.txt \
    --pubkey <key> --domain <domain> --output-working working.txt

# 4. Use a working server
# working.txt now has DNS IPs you can use with dnstt-client
```

## License

MIT
