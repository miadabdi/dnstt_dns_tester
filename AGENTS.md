# AGENTS Guide

This file is for coding agents working in this repository.

## Project Summary

`dnstt_dns_tester` is a two-stage toolkit:

1. `dnstt-dns-liveness.py`: validates DNS resolvers and optionally runs extended checks (NXDOMAIN hijack, EDNS support, delegation, censorship detection).
2. `dnstt-dns-tester.py`: runs `dnstt-client` against candidate resolvers and verifies real tunnel connectivity via SOCKS + HTTP requests.

Utility script:

- `subtract_ips.py`: computes set subtraction of IP lists (`A - B`).

## Repository Map

- `dnstt-dns-liveness.py`: Stage 1 scanner + filters + category outputs.
- `dnstt-dns-tester.py`: Stage 2 functional tester.
- `subtract_ips.py`: list-diff helper.
- `README.md`: English docs.
- `README.fa.md`: Persian docs.
- `requirements.txt`: Python dependencies.
- `install_deps.sh`, `install_deps.bat`: online install with offline `vendor/` fallback.
- `vendor/`: bundled wheels for offline installation.
- `all_dns.txt`: large resolver dataset.

## Environment And Dependencies

- Python 3.7+.
- External binary requirement: `dnstt-client` (path configurable with `--dnstt`).
- Python dependencies are installed from `requirements.txt`.

Install commands:

```bash
python3 -m pip install -r requirements.txt
```

Offline fallback:

```bash
bash install_deps.sh
```

## Standard Workflow

1. Stage 1: produce alive resolver list.
2. Stage 2: test alive resolvers with real dnstt connectivity.
3. Optional: use `subtract_ips.py` for list operations.

Typical commands:

```bash
python3 dnstt-dns-liveness.py --dns-list all_dns.txt --output alive_dns.txt
python3 dnstt-dns-tester.py --dns-list alive_dns.txt --dnstt ./dnstt-client-linux-amd64 --pubkey <pubkey> --domain <domain> --output-working working_dns_servers.txt
python3 subtract_ips.py alive_dns.txt working_dns_servers.txt remaining.txt
```

## Implementation Constraints

- Keep scripts cross-platform (Linux/macOS/Windows). Do not remove `_IS_WIN` branches.
- Preserve CLI compatibility unless the user explicitly asks for breaking changes.
- Keep default file names and output contracts stable:
  - Stage 1 output + derived files (`*_alive_only.txt`, `*_clean.txt`, `*_nx_ok.txt`, `*_ns_ok.txt`).
  - Stage 2 JSON output and `working_dns_servers.txt`.
- Avoid unnecessary rewrites of `all_dns.txt` because it is large.
- If changing documented behavior, update both `README.md` and `README.fa.md`.

## Validation Checklist

There are no formal unit tests. Run lightweight checks after code edits:

```bash
python3 -m py_compile dnstt-dns-liveness.py dnstt-dns-tester.py subtract_ips.py
python3 dnstt-dns-liveness.py --help
python3 dnstt-dns-tester.py --help
```

If behavior changes, run a small real smoke test with a short DNS list before finalizing.

## Operational Notes

- Both main scripts try to raise file descriptor limits on POSIX systems.
- `dnstt-dns-tester.py` currently prints debug lines after parsing CLI args; keep or remove only when requested.
- Runtime/output files in the repo root may be user-generated; do not delete or rewrite them unless asked.
