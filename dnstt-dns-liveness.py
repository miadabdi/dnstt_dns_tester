#!/usr/bin/env python3
"""
Stage 1: DNS liveness checker with optional extended checks.

Reads a list of DNS server IPs and sends a simple UDP DNS query to each one.
Servers that respond are written to an output file.

Optional extended checks (off by default):
  --check-nxdomain    Detect resolvers that hijack NXDOMAIN responses
  --check-edns        Test EDNS payload size support (512/900/1232)
  --check-delegation  Test NS delegation for a tunnel domain (requires --domain)
  --filter-delegation Only include servers that pass NS delegation in output
  --check-censorship  Detect resolvers returning censored IPs for a filtered domain
  --filter-censorship Only include servers that return non-censored IPs

Also writes category files derived from --output:
  *_alive_only.txt, *_clean.txt, *_nx_ok.txt, *_ns_ok.txt
"""

import argparse
import json
import os
import queue as _queue
import random
import shutil
import socket
import struct
import sys
import threading
import time
from concurrent.futures import Future, ThreadPoolExecutor
from typing import Dict, List, Optional, Tuple

_IS_WIN = sys.platform == "win32"

_RCODE_NAMES = {
    0: "NOERROR",
    1: "FORMERR",
    2: "SERVFAIL",
    3: "NXDOMAIN",
    4: "NOTIMP",
    5: "REFUSED",
}


# ---------------------------------------------------------------------------
# DNS packet helpers
# ---------------------------------------------------------------------------


def _encode_dns_name(domain: str) -> bytes:
    """Encode a domain name into DNS wire format."""
    out = b""
    for label in domain.split("."):
        out += bytes([len(label)]) + label.encode()
    out += b"\x00"
    return out


def _build_dns_query(
    domain: str = "www.gstatic.com", qtype: int = 1, edns_payload: int = 0
) -> Tuple[bytes, int]:
    """Build a DNS query packet and return (packet, tx_id)."""
    tx_id = random.randint(0, 0xFFFF)
    flags = 0x0100  # standard query + recursion desired
    ar_count = 1 if edns_payload > 0 else 0

    header = struct.pack(">HHHHHH", tx_id, flags, 1, 0, 0, ar_count)
    question = _encode_dns_name(domain) + struct.pack(">HH", qtype, 1)
    packet = header + question

    if edns_payload > 0:
        # OPT RR: root name, type=41, class=udp payload size, ttl=0, rdlength=0
        packet += b"\x00"
        packet += struct.pack(">HH", 41, edns_payload)
        packet += struct.pack(">IH", 0, 0)

    return packet, tx_id


def _parse_response_header(data: bytes) -> Optional[Tuple[int, int, int, int, int, int]]:
    """Parse DNS header and return (tx_id, flags, qd, an, ns, ar)."""
    if len(data) < 12:
        return None
    return struct.unpack(">HHHHHH", data[:12])


def _skip_dns_name(data: bytes, offset: int) -> int:
    """Skip one DNS name (handles compression pointers)."""
    while offset < len(data):
        length = data[offset]
        if length == 0:
            return offset + 1
        if (length & 0xC0) == 0xC0:
            return offset + 2
        offset += 1 + length
    return offset


def _parse_a_records(data: bytes) -> List[str]:
    """Extract IPv4 strings from A records in answer section."""
    if len(data) < 12:
        return []

    _, _, qd_count, an_count, _, _ = struct.unpack(">HHHHHH", data[:12])
    offset = 12

    for _ in range(qd_count):
        offset = _skip_dns_name(data, offset)
        if offset + 4 > len(data):
            return []
        offset += 4

    ips: List[str] = []
    for _ in range(an_count):
        if offset >= len(data):
            break
        offset = _skip_dns_name(data, offset)
        if offset + 10 > len(data):
            break

        rtype, rclass, ttl, rdlength = struct.unpack(">HHIH", data[offset : offset + 10])
        offset += 10

        if rtype == 1 and rdlength == 4 and offset + 4 <= len(data):
            ips.append(
                f"{data[offset]}.{data[offset + 1]}.{data[offset + 2]}.{data[offset + 3]}"
            )
        offset += rdlength

    return ips


def _validate_dns_response(data: bytes, expected_tx_id: int) -> Optional[str]:
    """Validate core DNS response correctness. Returns None when valid."""
    parsed = _parse_response_header(data)
    if parsed is None:
        return "response too short"

    tx_id, flags, qd_count, an_count, ns_count, ar_count = parsed
    if tx_id != expected_tx_id:
        return f"tx-id mismatch (got 0x{tx_id:04x}, expected 0x{expected_tx_id:04x})"

    if not (flags & 0x8000):
        return "QR bit not set (not a DNS response)"

    rcode = flags & 0x000F
    if rcode not in (0, 3):  # NOERROR or NXDOMAIN
        return f"DNS error: {_RCODE_NAMES.get(rcode, f'RCODE={rcode}')}"

    if rcode == 0 and an_count == 0 and qd_count > 0:
        return "no answer records in NOERROR response"

    return None


def _send_udp_query(
    dns_server: str,
    packet: bytes,
    dns_port: int = 53,
    timeout: float = 5.0,
    recv_size: int = 1024,
) -> bytes:
    """Send UDP DNS packet and return raw response bytes."""
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        sock.settimeout(timeout)
        try:
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 65536)
        except OSError:
            pass
        sock.sendto(packet, (dns_server, dns_port))
        data, _ = sock.recvfrom(recv_size)
        return data
    finally:
        try:
            sock.close()
        except Exception:
            pass


# ---------------------------------------------------------------------------
# Checks
# ---------------------------------------------------------------------------


def dns_liveness_check(
    dns_server: str,
    dns_port: int = 53,
    timeout: float = 5.0,
    query_domain: str = "www.google.com",
) -> Dict:
    """Send one DNS query and validate the response."""
    packet, tx_id = _build_dns_query(query_domain)
    start = time.time()

    try:
        data = _send_udp_query(dns_server, packet, dns_port, timeout)
        elapsed = time.time() - start

        error = _validate_dns_response(data, tx_id)
        if error is None:
            return {
                "alive": True,
                "response_time": elapsed,
                "error": None,
                "data": data,
            }

        return {
            "alive": False,
            "response_time": elapsed,
            "error": error,
            "data": data,
        }
    except socket.timeout:
        return {"alive": False, "response_time": None, "error": "timeout", "data": None}
    except Exception as exc:
        return {
            "alive": False,
            "response_time": None,
            "error": str(exc)[:120],
            "data": None,
        }


def nxdomain_check(
    dns_server: str,
    dns_port: int = 53,
    timeout: float = 5.0,
) -> Dict:
    """Check whether non-existent names correctly return NXDOMAIN."""
    label = "".join(random.choices("abcdefghijklmnopqrstuvwxyz0123456789", k=16))
    fake_domain = f"{label}.nxdomain-test.invalid"

    packet, tx_id = _build_dns_query(fake_domain, qtype=1)
    try:
        data = _send_udp_query(dns_server, packet, dns_port, timeout)
    except socket.timeout:
        return {"nxdomain_ok": False, "hijack": False, "error": "timeout"}
    except Exception as exc:
        return {"nxdomain_ok": False, "hijack": False, "error": str(exc)[:120]}

    parsed = _parse_response_header(data)
    if parsed is None:
        return {"nxdomain_ok": False, "hijack": False, "error": "response too short"}

    tx_id_resp, flags, qd_count, an_count, ns_count, ar_count = parsed
    if tx_id_resp != tx_id:
        return {"nxdomain_ok": False, "hijack": False, "error": "tx-id mismatch"}
    if not (flags & 0x8000):
        return {"nxdomain_ok": False, "hijack": False, "error": "not a response"}

    rcode = flags & 0x000F
    if rcode == 3 and an_count == 0:
        return {"nxdomain_ok": True, "hijack": False, "error": None}
    if rcode == 0 and an_count > 0:
        return {
            "nxdomain_ok": False,
            "hijack": True,
            "error": f"hijack detected: NOERROR with {an_count} answers for non-existent domain",
        }
    if rcode == 0 and an_count == 0:
        return {
            "nxdomain_ok": False,
            "hijack": False,
            "error": "NOERROR with 0 answers (expected NXDOMAIN)",
        }

    return {
        "nxdomain_ok": False,
        "hijack": False,
        "error": f"DNS error: {_RCODE_NAMES.get(rcode, f'RCODE={rcode}')}",
    }


def censorship_check(
    dns_server: str,
    domain: str = "facebook.com",
    blocked_prefix: str = "10.10.",
    dns_port: int = 53,
    timeout: float = 5.0,
) -> Dict:
    """Check if resolver returns blocked-prefix A records for a known filtered domain."""
    packet, tx_id = _build_dns_query(domain, qtype=1)
    try:
        data = _send_udp_query(dns_server, packet, dns_port, timeout)
    except socket.timeout:
        return {"censorship_clean": False, "resolved_ips": [], "error": "timeout"}
    except Exception as exc:
        return {
            "censorship_clean": False,
            "resolved_ips": [],
            "error": str(exc)[:120],
        }

    parsed = _parse_response_header(data)
    if parsed is None:
        return {
            "censorship_clean": False,
            "resolved_ips": [],
            "error": "response too short",
        }

    resp_tx_id, flags, qd_count, an_count, ns_count, ar_count = parsed
    if resp_tx_id != tx_id:
        return {
            "censorship_clean": False,
            "resolved_ips": [],
            "error": "tx-id mismatch",
        }
    if not (flags & 0x8000):
        return {
            "censorship_clean": False,
            "resolved_ips": [],
            "error": "not a response",
        }

    rcode = flags & 0x000F
    if rcode != 0:
        return {
            "censorship_clean": False,
            "resolved_ips": [],
            "error": f"DNS error: {_RCODE_NAMES.get(rcode, f'RCODE={rcode}')}",
        }

    ips = _parse_a_records(data)
    if not ips:
        return {
            "censorship_clean": False,
            "resolved_ips": [],
            "error": "no A records in response",
        }

    blocked_ips = [ip for ip in ips if ip.startswith(blocked_prefix)]
    return {
        "censorship_clean": len(blocked_ips) == 0,
        "resolved_ips": ips,
        "error": None if not blocked_ips else f"censored IP: {', '.join(blocked_ips)}",
    }


def edns_check(
    dns_server: str,
    domain: str = "www.google.com",
    dns_port: int = 53,
    timeout: float = 5.0,
    sizes: Tuple[int, ...] = (1232, 900, 512),
) -> Dict:
    """Find supported EDNS UDP payload sizes."""
    sizes_ok: List[int] = []
    last_error: Optional[str] = None

    for payload_size in sorted(sizes, reverse=True):
        packet, tx_id = _build_dns_query(domain, qtype=1, edns_payload=payload_size)
        try:
            data = _send_udp_query(
                dns_server,
                packet,
                dns_port,
                timeout,
                recv_size=max(4096, payload_size + 512),
            )
        except socket.timeout:
            last_error = f"timeout at {payload_size}"
            continue
        except Exception as exc:
            last_error = str(exc)[:120]
            continue

        parsed = _parse_response_header(data)
        if parsed is None:
            last_error = f"short response at {payload_size}"
            continue

        resp_tx_id, flags, qd_count, an_count, ns_count, ar_count = parsed
        if resp_tx_id != tx_id:
            last_error = f"tx-id mismatch at {payload_size}"
            continue
        if not (flags & 0x8000):
            last_error = f"not a response at {payload_size}"
            continue

        rcode = flags & 0x000F
        if rcode in (0, 3):
            sizes_ok.append(payload_size)

    return {
        "edns_max": max(sizes_ok) if sizes_ok else None,
        "edns_sizes_ok": sorted(sizes_ok, reverse=True),
        "error": None if sizes_ok else last_error,
    }


def ns_delegation_check(
    dns_server: str,
    tunnel_domain: str,
    dns_port: int = 53,
    timeout: float = 5.0,
) -> Dict:
    """Check whether resolver can recurse for a random subdomain of tunnel_domain."""
    label = "".join(random.choices("abcdefghijklmnopqrstuvwxyz0123456789", k=12))
    test_domain = f"{label}.{tunnel_domain}"

    packet, tx_id = _build_dns_query(test_domain, qtype=1)
    try:
        data = _send_udp_query(dns_server, packet, dns_port, timeout)
    except socket.timeout:
        return {
            "delegation_ok": False,
            "delegation_rcode": None,
            "error": "timeout - resolver could not reach authoritative NS",
        }
    except Exception as exc:
        return {
            "delegation_ok": False,
            "delegation_rcode": None,
            "error": str(exc)[:120],
        }

    parsed = _parse_response_header(data)
    if parsed is None:
        return {
            "delegation_ok": False,
            "delegation_rcode": None,
            "error": "response too short",
        }

    resp_tx_id, flags, qd_count, an_count, ns_count, ar_count = parsed
    if resp_tx_id != tx_id:
        return {
            "delegation_ok": False,
            "delegation_rcode": None,
            "error": "tx-id mismatch",
        }
    if not (flags & 0x8000):
        return {
            "delegation_ok": False,
            "delegation_rcode": None,
            "error": "not a response",
        }

    rcode = flags & 0x000F
    rcode_name = _RCODE_NAMES.get(rcode, f"RCODE={rcode}")

    if rcode == 5:  # REFUSED
        return {
            "delegation_ok": False,
            "delegation_rcode": rcode_name,
            "error": "REFUSED - resolver won't recurse for this domain",
        }

    # Any non-REFUSED response means the resolver tried to follow delegation.
    return {"delegation_ok": True, "delegation_rcode": rcode_name, "error": None}


# ---------------------------------------------------------------------------
# Terminal UI helpers
# ---------------------------------------------------------------------------


class _Colors:
    """Small ANSI color wrapper that gracefully disables itself."""

    def __init__(self, enabled: bool = True):
        self.enabled = enabled

        if enabled and _IS_WIN:
            try:
                import ctypes

                k32 = ctypes.windll.kernel32  # type: ignore[attr-defined]
                handle = k32.GetStdHandle(-11)  # STD_OUTPUT_HANDLE
                mode = ctypes.c_ulong()
                k32.GetConsoleMode(handle, ctypes.byref(mode))
                k32.SetConsoleMode(handle, mode.value | 0x0004)
            except Exception:
                self.enabled = False

    def _wrap(self, code: str, text: str) -> str:
        return f"\033[{code}m{text}\033[0m" if self.enabled else str(text)

    def green(self, text: str) -> str:
        return self._wrap("32", text)

    def red(self, text: str) -> str:
        return self._wrap("31", text)

    def yellow(self, text: str) -> str:
        return self._wrap("33", text)

    def cyan(self, text: str) -> str:
        return self._wrap("36", text)

    def dim(self, text: str) -> str:
        return self._wrap("2", text)

    def bold(self, text: str) -> str:
        return self._wrap("1", text)


def _format_duration(seconds: float) -> str:
    """Render seconds as short human-friendly duration."""
    s = int(seconds)
    if s < 60:
        return f"{s}s"
    if s < 3600:
        return f"{s // 60}m{s % 60:02d}s"
    h = s // 3600
    m = (s % 3600) // 60
    return f"{h}h{m:02d}m"


# ---------------------------------------------------------------------------
# Main tester
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
        check_nxdomain: bool = False,
        check_edns: bool = False,
        check_delegation: bool = False,
        tunnel_domain: str = "",
        filter_delegation: bool = False,
        check_censorship: bool = False,
        censorship_domain: str = "facebook.com",
        censorship_prefix: str = "10.10.",
        filter_censorship: bool = False,
    ):
        self.dns_list_path = dns_list_path
        self.dns_port = dns_port
        self.concurrent = concurrent
        self.timeout = timeout
        self.attempts = attempts
        self.show_failed = show_failed
        self.use_color = use_color and sys.stdout.isatty()

        self.check_nxdomain = check_nxdomain
        self.check_edns = check_edns
        self.check_delegation = check_delegation
        self.tunnel_domain = tunnel_domain
        self.filter_delegation = filter_delegation

        self.check_censorship = check_censorship
        self.censorship_domain = censorship_domain
        self.censorship_prefix = censorship_prefix
        self.filter_censorship = filter_censorship

        self.dns_servers = self._load_dns_servers()
        self._all_results: List[Dict] = []

    def _load_dns_servers(self) -> List[str]:
        servers: List[str] = []
        with open(self.dns_list_path, "r") as f:
            for line in f:
                line = line.strip()
                if not line or line.startswith("#"):
                    continue
                servers.append(line)
        return servers

    def _query_domain_for_liveness(self) -> str:
        # Reuse the liveness response for censorship checks to avoid extra query.
        return self.censorship_domain if self.check_censorship else "www.google.com"

    def _run_censorship_from_data(self, response_data: Optional[bytes]) -> Dict:
        if not response_data:
            return {
                "censorship_clean": False,
                "resolved_ips": [],
                "censorship_error": "no response data",
            }

        parsed = _parse_response_header(response_data)
        if parsed is None:
            return {
                "censorship_clean": False,
                "resolved_ips": [],
                "censorship_error": "could not parse response",
            }

        tx_id, flags, qd_count, an_count, ns_count, ar_count = parsed
        if not (flags & 0x8000):
            return {
                "censorship_clean": False,
                "resolved_ips": [],
                "censorship_error": "not a response",
            }

        rcode = flags & 0x000F
        if rcode != 0:
            return {
                "censorship_clean": False,
                "resolved_ips": [],
                "censorship_error": f"DNS error: {_RCODE_NAMES.get(rcode, f'RCODE={rcode}')}",
            }

        ips = _parse_a_records(response_data)
        if not ips:
            return {
                "censorship_clean": False,
                "resolved_ips": [],
                "censorship_error": "no A records in response",
            }

        blocked_ips = [ip for ip in ips if ip.startswith(self.censorship_prefix)]
        out = {
            "censorship_clean": len(blocked_ips) == 0,
            "resolved_ips": ips,
        }
        if blocked_ips:
            out["censorship_error"] = f"censored IP: {', '.join(blocked_ips)}"
        return out

    def _test_single(self, dns_server: str) -> Dict:
        """Run liveness + enabled optional checks for one resolver."""
        time.sleep(random.uniform(0, 0.05))  # reduce initial burst load

        best_time: Optional[float] = None
        best_data: Optional[bytes] = None
        last_error: Optional[str] = None

        for attempt in range(self.attempts):
            if attempt > 0:
                time.sleep(random.uniform(0.1, 0.5))

            check = dns_liveness_check(
                dns_server,
                dns_port=self.dns_port,
                timeout=self.timeout,
                query_domain=self._query_domain_for_liveness(),
            )
            if check["alive"]:
                t = check["response_time"]
                if best_time is None or (t is not None and t < best_time):
                    best_time = t
                    best_data = check.get("data")
                break

            last_error = check["error"]

        if best_time is None:
            return {
                "dns_server": dns_server,
                "alive": False,
                "dns_response_time": None,
                "error": last_error,
            }

        entry: Dict = {
            "dns_server": dns_server,
            "alive": True,
            "dns_response_time": best_time,
            "error": None,
        }

        if self.check_nxdomain:
            nx = nxdomain_check(dns_server, dns_port=self.dns_port, timeout=self.timeout)
            entry["nxdomain_ok"] = nx["nxdomain_ok"]
            entry["hijack"] = nx["hijack"]
            if nx["error"]:
                entry["nxdomain_error"] = nx["error"]

        if self.check_edns:
            ed = edns_check(dns_server, dns_port=self.dns_port, timeout=self.timeout)
            entry["edns_max"] = ed["edns_max"]
            entry["edns_sizes_ok"] = ed["edns_sizes_ok"]
            if ed["error"]:
                entry["edns_error"] = ed["error"]

        if self.check_delegation and self.tunnel_domain:
            dl = ns_delegation_check(
                dns_server,
                self.tunnel_domain,
                dns_port=self.dns_port,
                timeout=self.timeout,
            )
            entry["delegation_ok"] = dl["delegation_ok"]
            entry["delegation_rcode"] = dl["delegation_rcode"]
            if dl["error"]:
                entry["delegation_error"] = dl["error"]

        if self.check_censorship:
            entry.update(self._run_censorship_from_data(best_data))

        return entry

    @property
    def partial_results(self) -> List[Dict]:
        """Results collected so far (used when interrupted)."""
        return list(self._all_results)

    def _enabled_checks_summary(self) -> List[str]:
        checks: List[str] = []
        if self.check_nxdomain:
            checks.append("nxdomain")
        if self.check_edns:
            checks.append("edns")
        if self.check_delegation:
            checks.append(f"delegation({self.tunnel_domain})")
        if self.check_censorship:
            checks.append(
                f"censorship({self.censorship_domain} != {self.censorship_prefix}*)"
            )
        return checks

    def run(self) -> List[Dict]:
        total = len(self.dns_servers)
        colors = _Colors(self.use_color)
        is_tty = sys.stdout.isatty()
        term_width = shutil.get_terminal_size((80, 24)).columns

        print(f"DNS liveness check on {colors.bold(str(total))} servers")
        print(f"  DNS port:    {self.dns_port}")
        print(f"  Concurrent:  {self.concurrent}")
        print(f"  Timeout:     {self.timeout}s")
        print(f"  Attempts:    {self.attempts}")

        checks = self._enabled_checks_summary()
        if checks:
            print(f"  Checks:      {', '.join(checks)}")
        if self.filter_delegation:
            print("  Filter:      exclude servers failing NS delegation")
        if self.filter_censorship:
            print("  Filter:      exclude servers returning censored IPs")
        print("=" * 70)

        self._all_results = []
        all_results = self._all_results

        completed = 0
        total_alive = 0
        total_dead = 0
        total_hijack = 0
        total_deleg_ok = 0
        total_deleg_fail = 0
        total_censor_clean = 0
        total_censor_dirty = 0
        start_time = time.time()

        def progress_line() -> str:
            elapsed = time.time() - start_time
            elapsed_str = _format_duration(elapsed)

            if 0 < completed < total:
                eta = _format_duration(elapsed * (total - completed) / completed)
            elif completed >= total:
                eta = "done"
            else:
                eta = "..."

            bar_w = 25
            filled = int(bar_w * completed / total) if total else 0
            bar = "\u2588" * filled + "\u2591" * (bar_w - filled)
            pct = int(100 * completed / total) if total else 0

            extra = ""
            if self.check_nxdomain and total_hijack:
                extra += f" | {colors.yellow(f'{total_hijack} hijack')}"
            if self.check_delegation:
                extra += f" | {colors.cyan(f'{total_deleg_ok} deleg')}"
            if self.check_censorship:
                extra += f" | {colors.green(f'{total_censor_clean} clean')}"

            return (
                f" {bar} {pct:3d}% {completed}/{total}"
                f" | {colors.green(f'{total_alive} alive')}"
                f" | {colors.red(f'{total_dead} dead')}"
                f"{extra}"
                f" | {elapsed_str}"
                f" | ETA: {eta}"
            )

        def update_progress() -> None:
            if is_tty:
                sys.stdout.write(f"\r{' ' * term_width}\r{progress_line()}")
                sys.stdout.flush()

        def print_above(text: str) -> None:
            if is_tty:
                sys.stdout.write(f"\r{' ' * term_width}\r")
            print(text)
            update_progress()

        update_progress()

        with ThreadPoolExecutor(max_workers=self.concurrent) as executor:
            sem = threading.Semaphore(self.concurrent)
            result_q: _queue.Queue[Tuple[str, Future]] = _queue.Queue()

            def worker(server: str) -> Dict:
                try:
                    return self._test_single(server)
                finally:
                    sem.release()

            def producer() -> None:
                for server in self.dns_servers:
                    sem.acquire()
                    fut = executor.submit(worker, server)
                    fut.add_done_callback(lambda f, srv=server: result_q.put((srv, f)))

            producer_thread = threading.Thread(target=producer, daemon=True)
            producer_thread.start()

            for _ in range(total):
                dns_server, future = result_q.get()
                try:
                    result = future.result()
                except Exception as exc:
                    result = {
                        "dns_server": dns_server,
                        "alive": False,
                        "dns_response_time": None,
                        "error": str(exc)[:120],
                    }

                all_results.append(result)
                completed += 1

                if result["alive"]:
                    total_alive += 1
                    if result.get("hijack"):
                        total_hijack += 1

                    if result.get("delegation_ok"):
                        total_deleg_ok += 1
                    elif self.check_delegation and "delegation_ok" in result:
                        total_deleg_fail += 1

                    if result.get("censorship_clean"):
                        total_censor_clean += 1
                    elif self.check_censorship and "censorship_clean" in result:
                        total_censor_dirty += 1

                    response_time = (
                        f"{result['dns_response_time']:.3f}s"
                        if result["dns_response_time"]
                        else "N/A"
                    )

                    details: List[str] = []
                    if self.check_nxdomain:
                        if result.get("hijack"):
                            details.append(colors.red("HIJACK"))
                        elif result.get("nxdomain_ok"):
                            details.append(colors.green("NX:ok"))
                        else:
                            details.append(colors.yellow("NX:?"))

                    if self.check_edns:
                        edns_max = result.get("edns_max")
                        details.append(
                            colors.green(f"EDNS:{edns_max}")
                            if edns_max
                            else colors.yellow("EDNS:none")
                        )

                    if self.check_delegation:
                        details.append(
                            colors.green("NS:ok")
                            if result.get("delegation_ok")
                            else colors.red("NS:fail")
                        )

                    if self.check_censorship:
                        if result.get("censorship_clean"):
                            details.append(colors.green("CLEAN"))
                        else:
                            ips = result.get("resolved_ips", [])
                            details.append(colors.red(f"CENS:{ips[0] if ips else '?'}"))

                    detail_str = f"  [{' '.join(details)}]" if details else ""
                    print_above(
                        f"  {colors.green('OK')}   {result['dns_server']:>18}  DNS reply in {response_time}{detail_str}"
                    )
                else:
                    total_dead += 1
                    if self.show_failed:
                        err_msg = (result.get("error") or "")[:80]
                        if len(result.get("error") or "") > 80:
                            err_msg = err_msg[:77] + "..."
                        print_above(
                            f"  {colors.red('FAIL')} {result['dns_server']:>18}"
                            + (f"  {colors.dim(err_msg)}" if err_msg else "")
                        )
                    else:
                        update_progress()

            producer_thread.join()

        if is_tty:
            sys.stdout.write(f"\r{' ' * term_width}\r")
            sys.stdout.flush()

        elapsed = time.time() - start_time
        print(f"\nCompleted in {colors.bold(_format_duration(elapsed))}")
        print("=" * 70)
        print(
            f"TOTAL: {colors.green(f'{total_alive} alive')}, "
            f"{colors.red(f'{total_dead} dead')} out of {total}"
        )

        if self.check_nxdomain:
            clean = sum(1 for row in all_results if row.get("nxdomain_ok"))
            print(
                f"  NXDOMAIN: {colors.green(f'{clean} clean')}, "
                f"{colors.yellow(f'{total_hijack} hijacking')}"
            )

        if self.check_edns:
            with_edns = sum(1 for row in all_results if row.get("edns_max"))
            print(f"  EDNS:     {colors.green(f'{with_edns} support EDNS')}")

        if self.check_delegation:
            print(
                f"  NS deleg: {colors.green(f'{total_deleg_ok} ok')}, "
                f"{colors.red(f'{total_deleg_fail} fail')}"
            )

        if self.check_censorship:
            print(
                f"  Censor:   {colors.green(f'{total_censor_clean} clean')}, "
                f"{colors.red(f'{total_censor_dirty} censored')}"
            )

        print("=" * 70)
        return all_results

    def save_alive(self, results: List[Dict], path: str) -> None:
        """Save alive DNS servers to text output with optional filters."""
        alive_servers: List[str] = []

        for row in results:
            if not row.get("alive"):
                continue
            if self.filter_delegation and not row.get("delegation_ok"):
                continue
            if self.filter_censorship and not row.get("censorship_clean"):
                continue
            alive_servers.append(row["dns_server"])

        with open(path, "w") as f:
            for ip in alive_servers:
                f.write(ip + "\n")

        print(f"Alive servers saved to {path} ({len(alive_servers)} servers)")

    @staticmethod
    def _derive_output_path(base_path: str, suffix: str) -> str:
        stem, ext = os.path.splitext(base_path)
        if ext:
            return f"{stem}_{suffix}{ext}"
        return f"{base_path}_{suffix}.txt"

    @staticmethod
    def _write_ip_list(path: str, ips: List[str], label: str) -> None:
        with open(path, "w") as f:
            for ip in ips:
                f.write(ip + "\n")
        print(f"{label} saved to {path} ({len(ips)} servers)")

    def save_category_outputs(self, results: List[Dict], output_path: str) -> None:
        """Save separate category outputs derived from the main output path."""
        alive_only = [row["dns_server"] for row in results if row.get("alive")]
        clean = [
            row["dns_server"]
            for row in results
            if row.get("alive") and row.get("censorship_clean")
        ]
        nx_ok = [
            row["dns_server"]
            for row in results
            if row.get("alive") and row.get("nxdomain_ok")
        ]
        ns_ok = [
            row["dns_server"]
            for row in results
            if row.get("alive") and row.get("delegation_ok")
        ]

        self._write_ip_list(
            self._derive_output_path(output_path, "alive_only"),
            alive_only,
            "Alive-only servers",
        )
        self._write_ip_list(
            self._derive_output_path(output_path, "clean"),
            clean,
            "Clean servers",
        )
        self._write_ip_list(
            self._derive_output_path(output_path, "nx_ok"),
            nx_ok,
            "NXDOMAIN-ok servers",
        )
        self._write_ip_list(
            self._derive_output_path(output_path, "ns_ok"),
            ns_ok,
            "NS-ok servers",
        )

    @staticmethod
    def save_json(results: List[Dict], path: str) -> None:
        with open(path, "w") as f:
            json.dump(results, f, indent=2)
        print(f"Full results saved to {path}")


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------


def _build_cli() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Stage 1: DNS liveness checker - test which DNS servers respond to queries",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""\
Extended checks (off by default):
  --check-nxdomain     Detect resolvers that hijack NXDOMAIN (ad injection)
  --check-edns         Test EDNS payload size support (512/900/1232 bytes)
  --check-delegation   Test NS delegation for tunnel domain (requires --domain)
  --filter-delegation  Only include servers that pass NS delegation in output

Auto-generated category files (derived from --output):
  *_alive_only.txt, *_clean.txt, *_nx_ok.txt, *_ns_ok.txt

Examples:
  %(prog)s --dns-list all_dns.txt --output alive.txt
  %(prog)s --dns-list all_dns.txt --output alive.txt --output-json results.json \\
           --check-nxdomain --check-edns
  %(prog)s --dns-list all_dns.txt --output alive.txt --output-json results.json \\
           --check-delegation --domain t.example.com --filter-delegation
""",
    )

    parser.add_argument(
        "--dns-list",
        default="dns-servers.txt",
        help="Text file with DNS server IPs, one per line (default: dns-servers.txt)",
    )
    parser.add_argument("--dns-port", type=int, default=53, help="DNS port (default: 53)")
    parser.add_argument(
        "--concurrent",
        type=int,
        default=50,
        help="Max concurrent checks (default: 50)",
    )
    parser.add_argument(
        "--timeout",
        type=float,
        default=5.0,
        help="Timeout per DNS query (default: 5.0s)",
    )
    parser.add_argument(
        "--attempts",
        type=int,
        default=2,
        help="Number of query attempts per server (default: 2)",
    )
    parser.add_argument(
        "--output",
        default="alive_dns_servers.txt",
        help="Output file for alive server IPs (default: alive_dns_servers.txt)",
    )
    parser.add_argument(
        "--output-json",
        default=None,
        help="Save full results as JSON (auto-enabled when extended checks are used)",
    )

    ext = parser.add_argument_group("extended checks")
    ext.add_argument(
        "--check-nxdomain",
        action="store_true",
        default=False,
        help="Check for NXDOMAIN hijacking (off by default)",
    )
    ext.add_argument(
        "--check-edns",
        action="store_true",
        default=False,
        help="Test EDNS payload size support: 512, 900, 1232 bytes (off by default)",
    )
    ext.add_argument(
        "--check-delegation",
        action="store_true",
        default=False,
        help="Test NS delegation for the tunnel domain (off by default, requires --domain)",
    )
    ext.add_argument(
        "--domain",
        default=None,
        help="Tunnel domain for NS delegation check (e.g. t.example.com)",
    )
    ext.add_argument(
        "--filter-delegation",
        action="store_true",
        default=False,
        help="Only include servers that pass NS delegation in the output txt file",
    )
    ext.add_argument(
        "--check-censorship",
        action="store_true",
        default=False,
        help="Detect resolvers returning censored IPs for a filtered domain (off by default)",
    )
    ext.add_argument(
        "--censorship-domain",
        default="facebook.com",
        help="Domain to test for censorship (default: facebook.com)",
    )
    ext.add_argument(
        "--censorship-prefix",
        default="10.10.",
        help="Blocked IP prefix indicating censorship (default: 10.10.)",
    )
    ext.add_argument(
        "--filter-censorship",
        action="store_true",
        default=False,
        help="Only include servers that return non-censored IPs in the output txt file",
    )

    parser.add_argument(
        "--show-failed",
        action="store_true",
        default=False,
        help="Show failed DNS servers in output (hidden by default)",
    )
    parser.add_argument(
        "--no-color",
        action="store_true",
        default=False,
        help="Disable colored output",
    )

    return parser


def _raise_fd_limit() -> None:
    """Increase open-file limit on POSIX for high-concurrency runs."""
    if _IS_WIN:
        return

    try:
        import resource as _resource

        soft, hard = _resource.getrlimit(_resource.RLIMIT_NOFILE)
        desired = min(hard, max(65536, soft))
        _resource.setrlimit(_resource.RLIMIT_NOFILE, (desired, hard))
        print(f"File descriptor limit: {desired} (was {soft})")
    except Exception as exc:
        print(f"Warning: could not raise file descriptor limit: {exc}")


def main() -> None:
    _raise_fd_limit()

    parser = _build_cli()
    args = parser.parse_args()

    if args.check_delegation and not args.domain:
        parser.error("--check-delegation requires --domain")
    if args.filter_delegation and not args.check_delegation:
        parser.error("--filter-delegation requires --check-delegation")
    if args.filter_censorship and not args.check_censorship:
        parser.error("--filter-censorship requires --check-censorship")

    has_extended = (
        args.check_nxdomain
        or args.check_edns
        or args.check_delegation
        or args.check_censorship
    )
    if has_extended and not args.output_json:
        base = args.output.rsplit(".", 1)[0] if "." in args.output else args.output
        args.output_json = f"{base}.json"
        print(f"Extended checks enabled - JSON output auto-set to: {args.output_json}")

    tester = DnsLivenessTester(
        dns_list_path=args.dns_list,
        dns_port=args.dns_port,
        concurrent=args.concurrent,
        timeout=args.timeout,
        attempts=args.attempts,
        show_failed=args.show_failed,
        use_color=not args.no_color,
        check_nxdomain=args.check_nxdomain,
        check_edns=args.check_edns,
        check_delegation=args.check_delegation,
        tunnel_domain=args.domain or "",
        filter_delegation=args.filter_delegation,
        check_censorship=args.check_censorship,
        censorship_domain=args.censorship_domain,
        censorship_prefix=args.censorship_prefix,
        filter_censorship=args.filter_censorship,
    )

    try:
        results = tester.run()
    except KeyboardInterrupt:
        if sys.stdout.isatty():
            width = shutil.get_terminal_size((80, 24)).columns
            sys.stdout.write(f"\r{' ' * width}\r")
            sys.stdout.flush()

        results = tester.partial_results
        alive_count = sum(1 for row in results if row.get("alive"))
        print(
            f"\nInterrupted! Saving {alive_count} alive servers found so far..."
        )

    tester.save_alive(results, args.output)
    tester.save_category_outputs(results, args.output)
    if args.output_json:
        tester.save_json(results, args.output_json)


if __name__ == "__main__":
    main()
