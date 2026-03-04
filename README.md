# dnstt DNS Tester

A two-stage toolkit for finding DNS servers that work with [dnstt](https://www.bamsoftware.com/software/dnstt/) — a DNS tunnel for censorship circumvention.

## Overview

| Stage | Script                  | Purpose                                                                       |
| ----- | ----------------------- | ----------------------------------------------------------------------------- |
| 1     | `dnstt-dns-liveness.py` | Filter a large list of DNS IPs down to those that actually respond to queries |
| 2     | `dnstt-dns-tester.py`   | Test each alive DNS server for end-to-end **dnstt** connectivity              |

## Requirements

- Python 3.7+
- `requests` with SOCKS support (`pip install requests[socks]`)
- A compiled `dnstt-client` binary (included: `dnstt-client-linux-amd64`)
- A working dnstt server with its public key and domain

## Quick Start

### Stage 1 — DNS Liveness Check

Filter your DNS list to only those servers that respond:

```bash
python3 dnstt-dns-liveness.py \
    --dns-list all_dns.txt \
    --output alive_dns.txt \
    --batch 200 \
    --concurrent 50 \
    --timeout 5 \
    --hide-failed
```

Key options:

| Flag            | Default                 | Description                            |
| --------------- | ----------------------- | -------------------------------------- |
| `--dns-list`    | `dns-servers.txt`       | Input file with DNS IPs (one per line) |
| `--output`      | `alive_dns_servers.txt` | Output file for alive IPs              |
| `--output-json` | _(none)_                | Save full results as JSON              |
| `--batch`       | 30                      | IPs per batch                          |
| `--concurrent`  | 15                      | Max parallel checks                    |
| `--timeout`     | 5.0                     | Seconds per query                      |
| `--attempts`    | 1                       | Retries per server                     |
| `--hide-failed` | off                     | Suppress failed-server output          |

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

## Graceful Interruption

Both scripts handle **Ctrl+C** gracefully — any working servers discovered so far are saved to the output files before exiting.

## Typical Workflow

```bash
# 1. Start with a large public DNS list
wc -l all_dns.txt          # e.g. 116k servers

# 2. Find which ones are alive
python3 dnstt-dns-liveness.py --dns-list all_dns.txt --output alive_dns.txt

# 3. Test alive servers with dnstt
python3 dnstt-dns-tester.py --dns-list alive_dns.txt \
    --pubkey <key> --domain <domain> --output-working working.txt

# 4. Use a working server
# working.txt now has DNS IPs you can use with dnstt-client
```

## License

MIT
