#!/usr/bin/env python3
"""
Stage 1: DNS liveness checker.

Reads a list of DNS server IPs and sends a simple UDP DNS query to each one.
Servers that respond are written to an output file (one IP per line) which can
then be fed into dnstt-dns-tester.py for Stage 2 (dnstt connectivity testing).
"""

import argparse
import json
import socket
import struct
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Dict, List, Optional

# ---------------------------------------------------------------------------
# DNS liveness helpers
# ---------------------------------------------------------------------------


def _build_dns_query(domain: str = "www.gstatic.com", qtype: int = 1) -> bytes:
    """Build a minimal DNS A-record query packet."""
    import random

    tx_id = random.randint(0, 0xFFFF)
    flags = 0x0100  # standard query, recursion desired
    header = struct.pack(">HHHHHH", tx_id, flags, 1, 0, 0, 0)
    question = b""
    for label in domain.split("."):
        question += bytes([len(label)]) + label.encode()
    question += b"\x00"
    question += struct.pack(">HH", qtype, 1)  # A record, IN class
    return header + question


def dns_liveness_check(
    dns_server: str,
    dns_port: int = 53,
    timeout: float = 5.0,
    query_domain: str = "www.gstatic.com",
) -> Dict:
    """
    Send a simple UDP DNS query and wait for *any* response.
    Returns a dict with 'alive', 'response_time', 'error'.
    """
    packet = _build_dns_query(query_domain)
    start = time.time()
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(timeout)
        sock.sendto(packet, (dns_server, dns_port))
        data, _ = sock.recvfrom(1024)
        elapsed = time.time() - start
        if len(data) >= 12:
            return {"alive": True, "response_time": elapsed, "error": None}
        return {"alive": False, "response_time": elapsed, "error": "response too short"}
    except socket.timeout:
        return {"alive": False, "response_time": None, "error": "timeout"}
    except Exception as e:
        return {"alive": False, "response_time": None, "error": str(e)[:120]}
    finally:
        try:
            sock.close()
        except Exception:
            pass


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
        attempts: int = 1,
        hide_failed: bool = False,
    ):
        self.dns_list_path = dns_list_path
        self.dns_port = dns_port
        self.concurrent = concurrent
        self.timeout = timeout
        self.attempts = attempts
        self.hide_failed = hide_failed

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
        best_time: Optional[float] = None
        last_error: Optional[str] = None

        for _ in range(self.attempts):
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
        print(f"DNS liveness check on {total} servers")
        print(f"  DNS port:    {self.dns_port}")
        print(f"  Concurrent:  {self.concurrent}")
        print(f"  Timeout:     {self.timeout}s")
        print(f"  Attempts:    {self.attempts}")
        print(f"  Hide failed: {self.hide_failed}")
        print("=" * 70)

        self._all_results: List[Dict] = []
        all_results = self._all_results
        completed = 0
        total_alive = 0

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
                    print(
                        f"[{completed:5d}/{total}]  OK   {r['dns_server']:>18}"
                        f"  DNS reply in {t}"
                    )
                else:
                    if not self.hide_failed:
                        print(
                            f"[{completed:5d}/{total}]  FAIL {r['dns_server']:>18}"
                            f"  {r['error']}"
                        )

        total_dead = total - total_alive
        print("\n" + "=" * 70)
        print(f"TOTAL: {total_alive} alive, {total_dead} dead out of {total}")
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
        default=1,
        help="Number of query attempts per server (default: 1)",
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
        "--hide-failed",
        action="store_true",
        default=False,
        help="Do not log failed DNS servers",
    )

    args = p.parse_args()

    tester = DnsLivenessTester(
        dns_list_path=args.dns_list,
        dns_port=args.dns_port,
        concurrent=args.concurrent,
        timeout=args.timeout,
        attempts=args.attempts,
        hide_failed=args.hide_failed,
    )

    try:
        results = tester.run()
    except KeyboardInterrupt:
        results = tester.partial_results
        print(
            f"\n\nInterrupted! Saving {sum(1 for r in results if r['alive'])} alive servers found so far..."
        )

    tester.save_alive(results, args.output)
    if args.output_json:
        tester.save_json(results, args.output_json)


if __name__ == "__main__":
    main()
