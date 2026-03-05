#!/usr/bin/env python3
"""
Stage 1: DNS liveness checker.

Reads a list of DNS server IPs and sends a simple UDP DNS query to each one.
Servers that respond are written to an output file (one IP per line) which can
then be fed into dnstt-dns-tester.py for Stage 2 (dnstt connectivity testing).
"""

import argparse
import json
import random
import shutil
import socket
import struct
import sys
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Dict, List, Optional

_IS_WIN = sys.platform == "win32"

# ---------------------------------------------------------------------------
# DNS liveness helpers
# ---------------------------------------------------------------------------


def _build_dns_query(domain: str = "www.gstatic.com", qtype: int = 1) -> tuple:
    """Build a minimal DNS A-record query packet.

    Returns (packet_bytes, transaction_id).
    """
    tx_id = random.randint(0, 0xFFFF)
    flags = 0x0100  # standard query, recursion desired
    header = struct.pack(">HHHHHH", tx_id, flags, 1, 0, 0, 0)
    question = b""
    for label in domain.split("."):
        question += bytes([len(label)]) + label.encode()
    question += b"\x00"
    question += struct.pack(">HH", qtype, 1)  # A record, IN class
    return header + question, tx_id


def _validate_dns_response(data: bytes, expected_tx_id: int) -> Optional[str]:
    """Validate that *data* is a well-formed DNS response.

    Returns ``None`` on success or an error string describing the problem.
    """
    if len(data) < 12:
        return "response too short"

    tx_id, flags, qd_count, an_count, ns_count, ar_count = struct.unpack(
        ">HHHHHH", data[:12]
    )

    # Transaction-ID must match the query we sent
    if tx_id != expected_tx_id:
        return f"tx-id mismatch (got 0x{tx_id:04x}, expected 0x{expected_tx_id:04x})"

    # QR bit (bit 15) must be 1 → this is a response
    if not (flags & 0x8000):
        return "QR bit not set (not a DNS response)"

    # RCODE is the low 4 bits of the flags field
    rcode = flags & 0x000F
    if rcode not in (0, 3):  # NOERROR or NXDOMAIN are both valid DNS behaviour
        rcode_names = {1: "FORMERR", 2: "SERVFAIL", 4: "NOTIMP", 5: "REFUSED"}
        name = rcode_names.get(rcode, f"RCODE={rcode}")
        return f"DNS error: {name}"

    # For NOERROR we expect at least one answer (NXDOMAIN may have zero answers)
    if rcode == 0 and an_count == 0 and qd_count > 0:
        return "no answer records in NOERROR response"

    return None  # all good


def dns_liveness_check(
    dns_server: str,
    dns_port: int = 53,
    timeout: float = 5.0,
    query_domain: str = "www.google.com",
) -> Dict:
    """
    Send a UDP DNS query and validate that the response is a correct DNS reply.

    Checks performed on the response:
      - Transaction-ID matches the query
      - QR bit is set (it is a response, not another query)
      - RCODE is acceptable (NOERROR or NXDOMAIN)
      - For NOERROR responses, at least one answer record exists

    Returns a dict with 'alive', 'response_time', 'error'.
    """
    packet, tx_id = _build_dns_query(query_domain)
    start = time.time()
    sock: socket.socket | None = None
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(timeout)
        # Increase receive buffer to reduce drops under high concurrency
        try:
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 65536)
        except OSError:
            pass
        sock.sendto(packet, (dns_server, dns_port))
        data, _ = sock.recvfrom(1024)
        elapsed = time.time() - start

        err = _validate_dns_response(data, tx_id)
        if err is None:
            return {"alive": True, "response_time": elapsed, "error": None}
        return {"alive": False, "response_time": elapsed, "error": err}
    except socket.timeout:
        return {"alive": False, "response_time": None, "error": "timeout"}
    except Exception as e:
        return {"alive": False, "response_time": None, "error": str(e)[:120]}
    finally:
        try:
            if sock is not None:
                sock.close()
        except Exception:
            pass


# ---------------------------------------------------------------------------
# TUI helpers
# ---------------------------------------------------------------------------


class _Colors:
    """ANSI color helper — disabled when output is not a terminal."""

    def __init__(self, enabled: bool = True):
        self.enabled = enabled
        # Enable ANSI escape processing on Windows 10+
        if enabled and _IS_WIN:
            try:
                import ctypes

                k32 = ctypes.windll.kernel32  # type: ignore[attr-defined]
                h = k32.GetStdHandle(-11)  # STD_OUTPUT_HANDLE
                mode = ctypes.c_ulong()
                k32.GetConsoleMode(h, ctypes.byref(mode))
                k32.SetConsoleMode(
                    h, mode.value | 0x0004
                )  # ENABLE_VIRTUAL_TERMINAL_PROCESSING
            except Exception:
                self.enabled = False  # fallback: disable colors

    def _w(self, code: str, text: str) -> str:
        return f"\033[{code}m{text}\033[0m" if self.enabled else str(text)

    def green(self, t):
        return self._w("32", t)

    def red(self, t):
        return self._w("31", t)

    def yellow(self, t):
        return self._w("33", t)

    def bold(self, t):
        return self._w("1", t)

    def dim(self, t):
        return self._w("2", t)


def _format_duration(seconds: float) -> str:
    """Human-readable duration string."""
    s = int(seconds)
    if s < 60:
        return f"{s}s"
    if s < 3600:
        return f"{s // 60}m{s % 60:02d}s"
    h = s // 3600
    m = (s % 3600) // 60
    return f"{h}h{m:02d}m"


# ---------------------------------------------------------------------------
# Tester class
# ---------------------------------------------------------------------------


class DnsLivenessTester:
    def __init__(
        self,
        dns_list_path: str,
        dns_port: int = 53,
        concurrent: int = 15,
        timeout: float = 5.0,
        attempts: int = 2,
        show_failed: bool = False,
        use_color: bool = True,
    ):
        self.dns_list_path = dns_list_path
        self.dns_port = dns_port
        self.concurrent = concurrent
        self.timeout = timeout
        self.attempts = attempts
        self.show_failed = show_failed
        self.use_color = use_color and sys.stdout.isatty()

        self.dns_servers = self._load_dns_servers()

    def _load_dns_servers(self) -> List[str]:
        servers = []
        with open(self.dns_list_path, "r") as f:
            for line in f:
                line = line.strip()
                if not line or line.startswith("#"):
                    continue
                servers.append(line)
        return servers

    def _test_single(self, dns_server: str) -> Dict:
        # Random jitter (0-50ms) to avoid UDP burst congestion at high concurrency
        time.sleep(random.uniform(0, 0.05))

        best_time: Optional[float] = None
        last_error: Optional[str] = None

        for attempt in range(self.attempts):
            # Small delay between retries to avoid hitting the same congestion
            if attempt > 0:
                time.sleep(random.uniform(0.1, 0.5))
            result = dns_liveness_check(
                dns_server,
                dns_port=self.dns_port,
                timeout=self.timeout,
            )
            if result["alive"]:
                t = result["response_time"]
                if best_time is None or (t is not None and t < best_time):
                    best_time = t
                return {
                    "dns_server": dns_server,
                    "alive": True,
                    "dns_response_time": best_time,
                    "error": None,
                }
            last_error = result["error"]

        return {
            "dns_server": dns_server,
            "alive": False,
            "dns_response_time": None,
            "error": last_error,
        }

    @property
    def partial_results(self) -> List[Dict]:
        """Return results collected so far (useful when interrupted)."""
        return list(self._all_results)

    def run(self) -> List[Dict]:
        total = len(self.dns_servers)
        C = _Colors(self.use_color)
        is_tty = sys.stdout.isatty()
        term_width = shutil.get_terminal_size((80, 24)).columns

        print(f"DNS liveness check on {C.bold(str(total))} servers")
        print(f"  DNS port:    {self.dns_port}")
        print(f"  Concurrent:  {self.concurrent}")
        print(f"  Timeout:     {self.timeout}s")
        print(f"  Attempts:    {self.attempts}")
        print("=" * 70)

        self._all_results: List[Dict] = []
        all_results = self._all_results
        completed = 0
        total_alive = 0
        total_dead = 0
        start_time = time.time()

        def _progress_line() -> str:
            elapsed = time.time() - start_time
            elapsed_str = _format_duration(elapsed)
            if 0 < completed < total:
                eta_str = _format_duration(elapsed * (total - completed) / completed)
            elif completed >= total:
                eta_str = "done"
            else:
                eta_str = "..."
            bar_w = 25
            filled = int(bar_w * completed / total) if total else 0
            bar = "\u2588" * filled + "\u2591" * (bar_w - filled)
            pct = int(100 * completed / total) if total else 0
            return (
                f" {bar} {pct:3d}% {completed}/{total}"
                f" | {C.green(f'{total_alive} alive')}"
                f" | {C.red(f'{total_dead} dead')}"
                f" | {elapsed_str}"
                f" | ETA: {eta_str}"
            )

        def _update_progress():
            if is_tty:
                sys.stdout.write(f"\r{' ' * term_width}\r{_progress_line()}")
                sys.stdout.flush()

        def _print_above(text: str):
            if is_tty:
                sys.stdout.write(f"\r{' ' * term_width}\r")
            print(text)
            _update_progress()

        _update_progress()

        with ThreadPoolExecutor(max_workers=self.concurrent) as executor:
            futures = {
                executor.submit(self._test_single, s): s for s in self.dns_servers
            }
            for future in as_completed(futures):
                dns = futures[future]
                try:
                    r = future.result(timeout=self.timeout + 5)
                except Exception as e:
                    r = {
                        "dns_server": dns,
                        "alive": False,
                        "dns_response_time": None,
                        "error": str(e)[:120],
                    }

                all_results.append(r)
                completed += 1

                if r["alive"]:
                    total_alive += 1
                    t = (
                        f"{r['dns_response_time']:.3f}s"
                        if r["dns_response_time"]
                        else "N/A"
                    )
                    _print_above(
                        f"  {C.green('OK')}   {r['dns_server']:>18}  DNS reply in {t}"
                    )
                else:
                    total_dead += 1
                    if self.show_failed:
                        err_msg = r.get("error", "") or ""
                        if len(err_msg) > 80:
                            err_msg = err_msg[:77] + "..."
                        _print_above(
                            f"  {C.red('FAIL')} {r['dns_server']:>18}"
                            + (f"  {C.dim(err_msg)}" if err_msg else "")
                        )
                    else:
                        _update_progress()

        # Clear progress bar
        if is_tty:
            sys.stdout.write(f"\r{' ' * term_width}\r")
            sys.stdout.flush()

        elapsed = time.time() - start_time
        print(f"\nCompleted in {C.bold(_format_duration(elapsed))}")
        print("=" * 70)
        print(
            f"TOTAL: {C.green(f'{total_alive} alive')},"
            f" {C.red(f'{total_dead} dead')}"
            f" out of {total}"
        )
        print("=" * 70)

        return all_results

    @staticmethod
    def save_alive(results: List[Dict], path: str):
        alive = [r["dns_server"] for r in results if r["alive"]]
        with open(path, "w") as f:
            for ip in alive:
                f.write(ip + "\n")
        print(f"Alive servers saved to {path} ({len(alive)} servers)")

    @staticmethod
    def save_json(results: List[Dict], path: str):
        with open(path, "w") as f:
            json.dump(results, f, indent=2)
        print(f"Full results saved to {path}")


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------


def main():
    # Raise open file limit (Linux/macOS only)
    if not _IS_WIN:
        try:
            import resource as _resource

            soft, hard = _resource.getrlimit(_resource.RLIMIT_NOFILE)
            desired = min(hard, max(65536, soft))
            _resource.setrlimit(_resource.RLIMIT_NOFILE, (desired, hard))
            print(f"File descriptor limit: {desired} (was {soft})")
        except Exception as e:
            print(f"Warning: could not raise file descriptor limit: {e}")

    p = argparse.ArgumentParser(
        description="Stage 1: DNS liveness checker — test which DNS servers respond to queries"
    )
    p.add_argument(
        "--dns-list",
        default="dns-servers.txt",
        help="Text file with DNS server IPs, one per line (default: dns-servers.txt)",
    )
    p.add_argument(
        "--dns-port",
        type=int,
        default=53,
        help="DNS port (default: 53)",
    )
    p.add_argument(
        "--concurrent",
        type=int,
        default=50,
        help="Max concurrent checks (default: 50)",
    )
    p.add_argument(
        "--timeout",
        type=float,
        default=5.0,
        help="Timeout per DNS query (default: 5.0s)",
    )
    p.add_argument(
        "--attempts",
        type=int,
        default=2,
        help="Number of query attempts per server (default: 2)",
    )
    p.add_argument(
        "--output",
        default="alive_dns_servers.txt",
        help="Output file for alive server IPs (default: alive_dns_servers.txt)",
    )
    p.add_argument(
        "--output-json",
        default=None,
        help="Optional: save full results as JSON",
    )
    p.add_argument(
        "--show-failed",
        action="store_true",
        default=False,
        help="Show failed DNS servers in output (hidden by default)",
    )
    p.add_argument(
        "--no-color",
        action="store_true",
        default=False,
        help="Disable colored output",
    )

    args = p.parse_args()

    tester = DnsLivenessTester(
        dns_list_path=args.dns_list,
        dns_port=args.dns_port,
        concurrent=args.concurrent,
        timeout=args.timeout,
        attempts=args.attempts,
        show_failed=args.show_failed,
        use_color=not args.no_color,
    )

    try:
        results = tester.run()
    except KeyboardInterrupt:
        if sys.stdout.isatty():
            w = shutil.get_terminal_size((80, 24)).columns
            sys.stdout.write(f"\r{' ' * w}\r")
            sys.stdout.flush()
        results = tester.partial_results
        print(
            f"\nInterrupted! Saving {sum(1 for r in results if r['alive'])} alive servers found so far..."
        )

    tester.save_alive(results, args.output)
    if args.output_json:
        tester.save_json(results, args.output_json)


if __name__ == "__main__":
    main()
