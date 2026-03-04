#!/usr/bin/env python3
"""
Test different DNS servers for dnstt-client connectivity.
For each DNS server, starts a dnstt-client SOCKS proxy and tests
if traffic can flow through it.
"""

import json
import os
import resource
import signal
import socket
import subprocess
import sys
import time
from concurrent.futures import ThreadPoolExecutor, TimeoutError, as_completed
from typing import Dict, List

import requests
from requests.adapters import HTTPAdapter


class TimeoutHTTPAdapter(HTTPAdapter):
    def __init__(self, *args, **kwargs):
        self.timeout = kwargs.pop("timeout")
        super().__init__(*args, **kwargs)

    def send(self, request, **kwargs):
        kwargs["timeout"] = self.timeout
        return super().send(request, **kwargs)


class DnsttDnsTester:
    def __init__(
        self,
        dnstt_path: str,
        dns_list_path: str,
        pubkey: str,
        domain: str,
        dns_port: int = 53,
        protocol: str = "udp",
        startup_wait: float = 4.0,
        http_timeout: float = 15.0,
        max_concurrent: int = 3,
        test_timeout: float = 90.0,
        attempts: int = 2,
        test_url: str = "https://www.gstatic.com/generate_204",
    ):
        self.dnstt_path = os.path.abspath(dnstt_path)
        self.dns_list_path = dns_list_path
        self.pubkey = pubkey
        self.domain = domain
        self.dns_port = dns_port
        self.protocol = protocol
        self.startup_wait = startup_wait
        self.http_timeout = http_timeout
        self.max_concurrent = max_concurrent
        self.test_timeout = test_timeout
        self.attempts = attempts
        self.test_url = test_url

        self.dns_servers = self._load_dns_servers()

    def _load_dns_servers(self) -> List[str]:
        """Load DNS server IPs from a text file, one IP per line."""
        servers = []
        with open(self.dns_list_path, "r") as f:
            for line in f:
                line = line.strip()
                if not line or line.startswith("#"):
                    continue
                servers.append(line)
        return servers

    def _is_port_open(self, port: int, timeout: float = 2.0) -> bool:
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(timeout)
            result = sock.connect_ex(("127.0.0.1", port))
            sock.close()
            return result == 0
        except Exception:
            return False

    def _wait_for_port(
        self, port: int, timeout: float = 10.0, interval: float = 0.5
    ) -> bool:
        """Poll until the port is open or timeout is reached."""
        deadline = time.time() + timeout
        while time.time() < deadline:
            if self._is_port_open(port, timeout=1.0):
                return True
            time.sleep(interval)
        return False

    def test_single_dns(self, test_id: int, dns_server: str) -> Dict:
        socks_port = 40000 + test_id
        dnstt_process = None
        session = None
        stderr_file = None

        dns_target = f"{dns_server}:{self.dns_port}"

        try:
            # Build dnstt-client command
            cmd = [
                self.dnstt_path,
                f"-{self.protocol}",
                dns_target,
                "-pubkey",
                self.pubkey,
                self.domain,
                f"127.0.0.1:{socks_port}",
            ]

            # Use a temp file for stderr to avoid pipe FD leaks
            stderr_file = open(f"/tmp/dnstt_stderr_{test_id}.log", "w+b")

            dnstt_process = subprocess.Popen(
                cmd,
                stdout=subprocess.DEVNULL,
                stderr=stderr_file,
                preexec_fn=os.setsid,
            )

            # Wait for dnstt-client to start up and open the SOCKS port
            port_ready = self._wait_for_port(socks_port, timeout=self.startup_wait + 5)

            if dnstt_process.poll() is not None:
                stderr_out = ""
                try:
                    stderr_file.seek(0)
                    stderr_out = stderr_file.read(1000).decode(
                        "utf-8", errors="replace"
                    )
                except Exception:
                    pass
                return {
                    "dns_server": dns_server,
                    "success": False,
                    "attempts": 0,
                    "successful_attempts": 0,
                    "error": f"dnstt-client died immediately: {stderr_out}",
                    "response_time": None,
                    "response_times": [],
                    "min_time": None,
                    "max_time": None,
                }

            if not port_ready:
                return {
                    "dns_server": dns_server,
                    "success": False,
                    "attempts": 0,
                    "successful_attempts": 0,
                    "error": "SOCKS port not ready after startup wait",
                    "response_time": None,
                    "response_times": [],
                    "min_time": None,
                    "max_time": None,
                }

            # Create session with SOCKS proxy
            session = requests.Session()
            adapter = TimeoutHTTPAdapter(
                timeout=(5.0, self.http_timeout),
                pool_connections=1,
                pool_maxsize=1,
            )
            session.mount("https://", adapter)
            session.mount("http://", adapter)

            proxies = {
                "http": f"socks5h://127.0.0.1:{socks_port}",
                "https": f"socks5h://127.0.0.1:{socks_port}",
            }

            response_times = []
            errors = []
            successful_attempts = 0

            for i in range(self.attempts):
                start = time.time()
                try:
                    r = session.get(
                        self.test_url,
                        proxies=proxies,
                    )
                    elapsed = time.time() - start
                    if r.status_code in (200, 204):
                        response_times.append(elapsed)
                        successful_attempts += 1
                    else:
                        errors.append(f"HTTP {r.status_code}")
                except requests.RequestException as e:
                    errors.append(str(e)[:120])

                if i < self.attempts - 1:
                    time.sleep(2)

            success = successful_attempts > 0
            avg = sum(response_times) / len(response_times) if response_times else None

            return {
                "dns_server": dns_server,
                "success": success,
                "attempts": self.attempts,
                "successful_attempts": successful_attempts,
                "error": errors[0] if errors else None,
                "response_time": avg,
                "response_times": response_times,
                "min_time": min(response_times) if response_times else None,
                "max_time": max(response_times) if response_times else None,
            }

        finally:
            if session:
                try:
                    session.close()
                except Exception:
                    pass

            if dnstt_process and dnstt_process.poll() is None:
                try:
                    os.killpg(os.getpgid(dnstt_process.pid), signal.SIGTERM)
                    try:
                        dnstt_process.wait(timeout=3)
                    except subprocess.TimeoutExpired:
                        os.killpg(os.getpgid(dnstt_process.pid), signal.SIGKILL)
                        dnstt_process.wait(timeout=2)
                except Exception:
                    try:
                        dnstt_process.kill()
                        dnstt_process.wait(timeout=2)
                    except Exception:
                        pass

            # Close stderr temp file to release FD
            if stderr_file:
                try:
                    stderr_file.close()
                except Exception:
                    pass
                try:
                    os.unlink(f"/tmp/dnstt_stderr_{test_id}.log")
                except Exception:
                    pass

            time.sleep(0.3)

    def run_tests(self) -> List[Dict]:
        total = len(self.dns_servers)
        print(f"Testing {total} DNS servers against dnstt")
        print(f"  Domain:     {self.domain}")
        print(f"  Protocol:   {self.protocol}")
        print(f"  DNS port:   {self.dns_port}")
        print(f"  Concurrent: {self.max_concurrent}")
        print(f"  Attempts:   {self.attempts}")
        print(f"  Test URL:   {self.test_url}")
        print(f"  Timeout:    {self.test_timeout}s per DNS server")
        print("-" * 80)

        self._results: List[Dict] = []
        results = self._results
        completed = 0

        with ThreadPoolExecutor(max_workers=self.max_concurrent) as executor:
            futures = {
                executor.submit(self.test_single_dns, i, dns): dns
                for i, dns in enumerate(self.dns_servers)
            }

            for future in as_completed(futures):
                dns = futures[future]
                try:
                    result = future.result(timeout=self.test_timeout)
                except TimeoutError:
                    result = {
                        "dns_server": dns,
                        "success": False,
                        "attempts": 0,
                        "successful_attempts": 0,
                        "error": f"Overall timeout after {self.test_timeout}s",
                        "response_time": None,
                        "response_times": [],
                        "min_time": None,
                        "max_time": None,
                    }
                except Exception as e:
                    result = {
                        "dns_server": dns,
                        "success": False,
                        "attempts": 0,
                        "successful_attempts": 0,
                        "error": str(e)[:150],
                        "response_time": None,
                        "response_times": [],
                        "min_time": None,
                        "max_time": None,
                    }

                results.append(result)
                completed += 1

                status = "OK" if result["success"] else "FAIL"
                rate = f"{result['successful_attempts']}/{result['attempts']}"
                avg = (
                    f"{result['response_time']:.2f}s"
                    if result["response_time"]
                    else "N/A"
                )
                err = ""
                if not result["success"] and result.get("error"):
                    err = f" | {result['error']}"

                print(
                    f"[{completed:3d}/{total}] {status:4s} {result['dns_server']:>18} | "
                    f"{rate} | Avg: {avg}{err}"
                )

        # Sort: successful first (by avg response time), then failed
        results.sort(
            key=lambda r: (
                not r["success"],
                r["response_time"] if r["response_time"] is not None else float("inf"),
            )
        )

        return results

    @property
    def partial_results(self) -> List[Dict]:
        """Return results collected so far (useful when interrupted)."""
        return list(getattr(self, "_results", []))

    def print_summary(self, results: List[Dict]):
        successful = [r for r in results if r["success"]]
        failed = [r for r in results if not r["success"]]

        print("\n" + "=" * 80)
        print("SUMMARY")
        print("=" * 80)
        print(f"Total tested:  {len(results)}")
        print(f"Working:       {len(successful)}")
        print(f"Failed:        {len(failed)}")

        if successful:
            print("\nWorking DNS servers (sorted by speed):")
            print(
                f"{'DNS Server':>20}  {'Avg':>8}  {'Min':>8}  {'Max':>8}  {'Rate':>6}"
            )
            print("-" * 60)
            for r in successful:
                avg = f"{r['response_time']:.2f}s" if r["response_time"] else "N/A"
                mn = f"{r['min_time']:.2f}s" if r["min_time"] else "N/A"
                mx = f"{r['max_time']:.2f}s" if r["max_time"] else "N/A"
                rate = f"{r['successful_attempts']}/{r['attempts']}"
                print(f"{r['dns_server']:>20}  {avg:>8}  {mn:>8}  {mx:>8}  {rate:>6}")

    def save_results(self, results: List[Dict], path: str):
        with open(path, "w") as f:
            json.dump(results, f, indent=2)
        print(f"\nResults saved to {path}")

    def save_working_servers(self, results: List[Dict], path: str):
        """Save just the working DNS server IPs to a text file."""
        working = [r["dns_server"] for r in results if r["success"]]
        with open(path, "w") as f:
            for ip in working:
                f.write(ip + "\n")
        print(f"Working servers saved to {path} ({len(working)} servers)")


def main():
    import argparse

    # Raise open file limit to handle many concurrent subprocesses
    try:
        soft, hard = resource.getrlimit(resource.RLIMIT_NOFILE)
        desired = min(hard, max(65536, soft))
        resource.setrlimit(resource.RLIMIT_NOFILE, (desired, hard))
        print(f"File descriptor limit: {desired} (was {soft})")
    except Exception as e:
        print(f"Warning: could not raise file descriptor limit: {e}")

    p = argparse.ArgumentParser(
        description="Test DNS servers for dnstt-client connectivity"
    )
    p.add_argument(
        "--dnstt",
        default="./dnstt-client-linux-amd64",
        help="Path to dnstt-client binary (default: ./dnstt-client-linux-amd64)",
    )
    p.add_argument(
        "--dns-list",
        default="dns-servers.txt",
        help="Text file with DNS server IPs, one per line (default: dns-servers.txt)",
    )
    p.add_argument(
        "--pubkey",
        required=True,
        help="dnstt server public key",
    )
    p.add_argument(
        "--domain",
        required=True,
        help="dnstt domain (e.g. n.mlfrontier.store)",
    )
    p.add_argument(
        "--dns-port",
        type=int,
        default=53,
        help="DNS port to use (default: 53)",
    )
    p.add_argument(
        "--protocol",
        choices=["udp", "dot", "doh"],
        default="udp",
        help="DNS transport protocol (default: udp)",
    )
    p.add_argument(
        "--startup-wait",
        type=float,
        default=4.0,
        help="Seconds to wait for dnstt-client startup (default: 4.0)",
    )
    p.add_argument(
        "--http-timeout",
        type=float,
        default=15.0,
        help="HTTP request timeout in seconds (default: 15.0)",
    )
    p.add_argument(
        "--max-concurrent",
        type=int,
        default=3,
        help="Max concurrent tests (default: 3)",
    )
    p.add_argument(
        "--test-timeout",
        type=float,
        default=90.0,
        help="Overall timeout per DNS server test (default: 90.0)",
    )
    p.add_argument(
        "--attempts",
        type=int,
        default=2,
        help="Number of HTTP attempts per DNS server (default: 2)",
    )
    p.add_argument(
        "--test-url",
        default="https://www.gstatic.com/generate_204",
        help="URL to test connectivity (default: gstatic generate_204)",
    )
    p.add_argument(
        "--output",
        default="dns_test_results.json",
        help="Output JSON file (default: dns_test_results.json)",
    )
    p.add_argument(
        "--output-working",
        default="working_dns_servers.txt",
        help="Output file for working DNS server IPs (default: working_dns_servers.txt)",
    )

    args = p.parse_args()

    if not os.path.isfile(args.dnstt):
        print(f"Error: dnstt binary not found: {args.dnstt}")
        sys.exit(1)

    if not os.access(args.dnstt, os.X_OK):
        print(f"Error: dnstt binary is not executable: {args.dnstt}")
        sys.exit(1)

    tester = DnsttDnsTester(
        dnstt_path=args.dnstt,
        dns_list_path=args.dns_list,
        pubkey=args.pubkey,
        domain=args.domain,
        dns_port=args.dns_port,
        protocol=args.protocol,
        startup_wait=args.startup_wait,
        http_timeout=args.http_timeout,
        max_concurrent=args.max_concurrent,
        test_timeout=args.test_timeout,
        attempts=args.attempts,
        test_url=args.test_url,
    )

    try:
        results = tester.run_tests()
    except KeyboardInterrupt:
        results = tester.partial_results
        print(
            f"\n\nInterrupted! Saving {sum(1 for r in results if r['success'])} working servers found so far..."
        )

    tester.print_summary(results)
    tester.save_results(results, args.output)
    tester.save_working_servers(results, args.output_working)


if __name__ == "__main__":
    main()
