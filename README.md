# dnstt DNS Tester

Two-stage toolkit for finding DNS resolvers that work with [dnstt](https://www.bamsoftware.com/software/dnstt/) tunneling.

## Scripts

| Script | Role |
| ----- | ---- |
| `dnstt-dns-liveness.py` | Stage 1: find resolvers that return valid DNS responses, with optional extended checks |
| `dnstt-dns-tester.py` | Stage 2: start `dnstt-client` per resolver and test end-to-end connectivity through SOCKS |
| `subtract_ips.py` | Utility: subtract one IP list from another (`A - B`) |

## Requirements

- Python 3.7+
- `dnstt-client` binary for your platform
- `requests`, `PySocks` and dependencies listed in `requirements.txt`
- dnstt server `--pubkey` and `--domain` for Stage 2

## Install Dependencies

Online:

```bash
python3 -m pip install -r requirements.txt
```

Offline fallback using bundled wheels:

```bash
# Linux/macOS
bash install_deps.sh

# Windows (cmd.exe)
install_deps.bat
```

## Stage 1: DNS Liveness

Basic run:

```bash
python3 dnstt-dns-liveness.py \
  --dns-list all_dns.txt \
  --output alive_dns.txt
```

Extended checks example:

```bash
python3 dnstt-dns-liveness.py \
  --dns-list all_dns.txt \
  --output alive_dns.txt \
  --check-nxdomain \
  --check-edns \
  --check-censorship \
  --censorship-domain facebook.com \
  --censorship-prefix 10.10.
```

Stage 1 options:

| Flag | Default | Description |
| ---- | ------- | ----------- |
| `--dns-list` | `dns-servers.txt` | Input IP list (one per line) |
| `--dns-port` | `53` | DNS port |
| `--concurrent` | `50` | Max concurrent checks |
| `--timeout` | `5.0` | Query timeout in seconds |
| `--attempts` | `2` | Retries per resolver |
| `--output` | `alive_dns_servers.txt` | Alive resolver output |
| `--output-json` | none | Full JSON results (auto-set when extended checks are enabled) |
| `--check-nxdomain` | off | NXDOMAIN hijack detection |
| `--check-edns` | off | EDNS support test (512/900/1232) |
| `--check-delegation` | off | Delegation recursion check for tunnel domain |
| `--domain` | none | Domain used by `--check-delegation` |
| `--filter-delegation` | off | Keep only delegation-passing resolvers |
| `--check-censorship` | off | Detect blocked-prefix DNS answers |
| `--censorship-domain` | `facebook.com` | Domain used for censorship check |
| `--censorship-prefix` | `10.10.` | Blocked IP prefix marker |
| `--filter-censorship` | off | Keep only non-censored resolvers |
| `--show-failed` | off | Print failed resolver rows |
| `--no-color` | off | Disable ANSI colors |

Stage 1 always writes extra category files derived from `--output`:

- `*_alive_only.txt`
- `*_clean.txt`
- `*_nx_ok.txt`
- `*_ns_ok.txt`

## Stage 2: dnstt Connectivity

```bash
python3 dnstt-dns-tester.py \
  --dnstt ./dnstt-client-linux-amd64 \
  --dns-list alive_dns.txt \
  --pubkey YOUR_PUBLIC_KEY \
  --domain your.dnstt.domain \
  --protocol udp \
  --max-concurrent 3
```

Stage 2 options:

| Flag | Default | Description |
| ---- | ------- | ----------- |
| `--dnstt` | `./dnstt-client-linux-amd64` | Path to `dnstt-client` binary |
| `--dns-list` | `dns-servers.txt` | Input IP list |
| `--pubkey` | required | dnstt server pubkey |
| `--domain` | required | dnstt server domain |
| `--dns-port` | `53` | Resolver DNS port |
| `--protocol` | `udp` | `udp`, `dot`, or `doh` |
| `--startup-wait` | `2.0` | Wait before considering startup failure |
| `--http-timeout` | `15.0` | HTTP request timeout |
| `--max-concurrent` | `3` | Parallel resolver tests |
| `--test-timeout` | `90.0` | Per-resolver overall timeout |
| `--attempts` | `2` | HTTP attempts per resolver |
| `--test-url` | `https://www.gstatic.com/generate_204` | Connectivity URL |
| `--output` | `dns_test_results.json` | Full JSON results |
| `--output-working` | `working_dns_servers.txt` | Working resolver IPs |
| `--show-failed` | off | Print failed resolver rows |
| `--no-color` | off | Disable ANSI colors |

## Utility: subtract IP lists

```bash
python3 subtract_ips.py <file_A> <file_B> <output_file>
```

It loads both files as sets and writes sorted `A - B` into `output_file`.

## Typical Workflow

```bash
# 1) Liveness + optional filtering
python3 dnstt-dns-liveness.py --dns-list all_dns.txt --output alive_dns.txt

# 2) dnstt functional test
python3 dnstt-dns-tester.py \
  --dns-list alive_dns.txt \
  --dnstt ./dnstt-client-linux-amd64 \
  --pubkey <pubkey> \
  --domain <domain> \
  --output-working working_dns_servers.txt

# 3) Optional list subtraction
python3 subtract_ips.py alive_dns.txt working_dns_servers.txt remaining.txt
```

## Notes

- Both Stage 1 and Stage 2 raise file descriptor limits on POSIX when possible.
- `dnstt-dns-tester.py` currently prints two debug lines after argument parsing.

## License

MIT
