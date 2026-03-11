#!/usr/bin/env python3
"""
Test different DNS servers for dnstt-client connectivity.
For each DNS server, starts a dnstt-client SOCKS proxy and tests
if traffic can flow through it.
"""

import json
import os
import shutil
import signal
import socket
import subprocess
import sys
import tempfile
import threading
import time
from concurrent.futures import ThreadPoolExecutor, TimeoutError, as_completed
from typing import Dict, List

_IS_WIN = sys.platform == "win32"

import requests
from requests.adapters import HTTPAdapter


class TimeoutHTTPAdapter(HTTPAdapter):
    def __init__(self, *args, **kwargs):
        self.timeout = kwargs.pop("timeout")
        super().__init__(*args, **kwargs)

    def send(self, request, **kwargs):
        kwargs["timeout"] = self.timeout
        return super().send(request, **kwargs)


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
# Tester
# ---------------------------------------------------------------------------


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
        show_failed: bool = False,
        use_color: bool = True,
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
        self.show_failed = show_failed
        self.use_color = use_color and sys.stdout.isatty()
        self._results: List[Dict] = []
        self._stop_event = threading.Event()
        self._active_processes = set()
        self._active_processes_lock = threading.Lock()

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

    _port_lock = threading.Lock()
    _reserved_ports: set = set()

    def _interrupted_result(self, dns_server: str) -> Dict:
        return {
            "dns_server": dns_server,
            "success": False,
            "attempts": 0,
            "successful_attempts": 0,
            "error": "Interrupted",
            "response_time": None,
            "response_times": [],
            "min_time": None,
            "max_time": None,
        }

    def _register_process(self, process: subprocess.Popen):
        with self._active_processes_lock:
            self._active_processes.add(process)

    def _unregister_process(self, process: subprocess.Popen):
        with self._active_processes_lock:
            self._active_processes.discard(process)

    def _terminate_process(self, process: subprocess.Popen):
        if not process or process.poll() is not None:
            return

        try:
            if _IS_WIN:
                process.terminate()
                try:
                    process.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    process.kill()
                    process.wait(timeout=2)
            else:
                os.killpg(os.getpgid(process.pid), signal.SIGTERM)
                try:
                    process.wait(timeout=3)
                except subprocess.TimeoutExpired:
                    os.killpg(os.getpgid(process.pid), signal.SIGKILL)
                    process.wait(timeout=2)
        except Exception:
            try:
                process.kill()
                process.wait(timeout=2)
            except Exception:
                pass

    def stop(self):
        self._stop_event.set()
        with self._active_processes_lock:
            processes = list(self._active_processes)
        for process in processes:
            self._terminate_process(process)

    @classmethod
    def _find_free_port(cls) -> int:
        """Ask the OS for a free TCP port on 127.0.0.1, ensuring no two
        threads get the same port before dnstt-client can bind it."""
        with cls._port_lock:
            for _ in range(50):
                with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                    s.bind(("127.0.0.1", 0))
                    port = s.getsockname()[1]
                if port not in cls._reserved_ports:
                    cls._reserved_ports.add(port)
                    return port
            # fallback: return whatever the OS gives, even if duplicated
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.bind(("127.0.0.1", 0))
                port = s.getsockname()[1]
            cls._reserved_ports.add(port)
            return port

    @classmethod
    def _release_port(cls, port: int):
        with cls._port_lock:
            cls._reserved_ports.discard(port)

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
            if self._stop_event.is_set():
                return False
            if self._is_port_open(port, timeout=1.0):
                return True
            if self._stop_event.wait(timeout=interval):
                return False
        return False

    def test_single_dns(self, dns_server: str) -> Dict:
        socks_port = self._find_free_port()
        dnstt_process = None
        session = None
        stderr_file = None
        stderr_path = ""

        dns_target = f"{dns_server}:{self.dns_port}"

        try:
            if self._stop_event.is_set():
                return self._interrupted_result(dns_server)

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
            stderr_path = os.path.join(
                tempfile.gettempdir(), f"dnstt_stderr_{socks_port}.log"
            )
            stderr_file = open(stderr_path, "w+b")

            popen_kwargs: Dict = dict(
                stdout=subprocess.DEVNULL,
                stderr=stderr_file,
            )
            if _IS_WIN:
                popen_kwargs["creationflags"] = subprocess.CREATE_NEW_PROCESS_GROUP
            else:
                popen_kwargs["preexec_fn"] = os.setsid

            dnstt_process = subprocess.Popen(cmd, **popen_kwargs)
            self._register_process(dnstt_process)

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

            if self._stop_event.is_set():
                return self._interrupted_result(dns_server)

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
                if self._stop_event.is_set():
                    return self._interrupted_result(dns_server)
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
                    if self._stop_event.wait(timeout=2):
                        return self._interrupted_result(dns_server)

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
                self._terminate_process(dnstt_process)
            if dnstt_process:
                self._unregister_process(dnstt_process)

            # Close stderr temp file to release FD
            if stderr_file:
                try:
                    stderr_file.close()
                except Exception:
                    pass
                try:
                    os.unlink(stderr_path)
                except Exception:
                    pass

            # Release port reservation so other threads can reuse it
            self._release_port(socks_port)

            self._stop_event.wait(timeout=0.3)

    def run_tests(self) -> List[Dict]:
        total = len(self.dns_servers)
        C = _Colors(self.use_color)
        is_tty = sys.stdout.isatty()
        term_width = shutil.get_terminal_size((80, 24)).columns

        print(f"Testing {C.bold(str(total))} DNS servers against dnstt")
        print(f"  Domain:     {self.domain}")
        print(f"  Protocol:   {self.protocol}")
        print(f"  DNS port:   {self.dns_port}")
        print(f"  Concurrent: {self.max_concurrent}")
        print(f"  Attempts:   {self.attempts}")
        print(f"  Test URL:   {self.test_url}")
        print(f"  Timeout:    {self.test_timeout}s per DNS server")
        print("-" * 80)

        self._stop_event.clear()
        self._results = []
        results = self._results
        completed = 0
        ok_count = 0
        fail_count = 0
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
                f" | {C.green(f'{ok_count} OK')}"
                f" | {C.red(f'{fail_count} FAIL')}"
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

        executor = ThreadPoolExecutor(max_workers=self.max_concurrent)
        futures = {}
        try:
            futures = {
                executor.submit(self.test_single_dns, dns): dns
                for dns in self.dns_servers
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

                if result["success"]:
                    ok_count += 1
                    rate = f"{result['successful_attempts']}/{result['attempts']}"
                    avg = (
                        f"{result['response_time']:.2f}s"
                        if result["response_time"]
                        else "N/A"
                    )
                    _print_above(
                        f"  {C.green('OK')}   {result['dns_server']:>18}"
                        f" | {rate} | Avg: {avg}"
                    )
                else:
                    fail_count += 1
                    if self.show_failed:
                        err_msg = result.get("error", "") or ""
                        if len(err_msg) > 80:
                            err_msg = err_msg[:77] + "..."
                        _print_above(
                            f"  {C.red('FAIL')} {result['dns_server']:>18}"
                            + (f" | {C.dim(err_msg)}" if err_msg else "")
                        )
                    else:
                        _update_progress()
        except KeyboardInterrupt:
            self.stop()
            for future in futures:
                future.cancel()
            raise
        finally:
            executor.shutdown(wait=True, cancel_futures=True)

        # Clear progress bar
        if is_tty:
            sys.stdout.write(f"\r{' ' * term_width}\r")
            sys.stdout.flush()

        elapsed = time.time() - start_time
        print(f"\nCompleted in {C.bold(_format_duration(elapsed))}")

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
        C = _Colors(self.use_color)
        successful = [r for r in results if r["success"]]
        failed = [r for r in results if not r["success"]]

        print("\n" + "=" * 80)
        print(C.bold("SUMMARY"))
        print("=" * 80)
        print(f"Total tested:  {len(results)}")
        print(f"Working:       {C.green(str(len(successful)))}")
        print(f"Failed:        {C.red(str(len(failed)))}")

        if successful:
            print(f"\n{C.bold('Working DNS servers (sorted by speed):')}")
            print(
                f"{'DNS Server':>20}  {'Avg':>8}  {'Min':>8}  {'Max':>8}  {'Rate':>6}"
            )
            print("-" * 60)
            for r in successful:
                avg = f"{r['response_time']:.2f}s" if r["response_time"] else "N/A"
                mn = f"{r['min_time']:.2f}s" if r["min_time"] else "N/A"
                mx = f"{r['max_time']:.2f}s" if r["max_time"] else "N/A"
                rate = f"{r['successful_attempts']}/{r['attempts']}"
                ip = f"{r['dns_server']:>20}"
                print(f"{C.green(ip)}  {avg:>8}  {mn:>8}  {mx:>8}  {rate:>6}")

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
        help="dnstt domain",
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
        default=2.0,
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

    # DEBUG: verify parsed values
    print(f"[DEBUG] Parsed args: max_concurrent={args.max_concurrent}, test_timeout={args.test_timeout}")
    print(f"[DEBUG] Script location: {os.path.abspath(__file__)}")

    if not os.path.isfile(args.dnstt):
        print(f"Error: dnstt binary not found: {args.dnstt}")
        sys.exit(1)

    if not _IS_WIN and not os.access(args.dnstt, os.X_OK):
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
        show_failed=args.show_failed,
        use_color=not args.no_color,
    )

    try:
        results = tester.run_tests()
    except KeyboardInterrupt:
        tester.stop()
        if sys.stdout.isatty():
            w = shutil.get_terminal_size((80, 24)).columns
            sys.stdout.write(f"\r{' ' * w}\r")
            sys.stdout.flush()
        results = tester.partial_results
        print(
            f"\nInterrupted! Saving {sum(1 for r in results if r['success'])} working servers found so far..."
        )

    tester.print_summary(results)
    tester.save_results(results, args.output)
    tester.save_working_servers(results, args.output_working)


if __name__ == "__main__":
    main()
