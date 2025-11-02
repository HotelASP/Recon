#!/usr/bin/env python3
"""Lightweight TCP scanner compatible with Recon's discovery workflow.

This module emulates the behaviour of the ``smrib.py`` helper bundled with the
original Recon tooling.  It performs targeted TCP connection attempts against
one or more hosts and records ports that accept connections.  Results are
persisted as JSON so that :mod:`tools.aggregate` can merge them with the
findings from the remaining reconnaissance stages.

Only a very small feature set is required by ``run_recon.py``:

* ``--targets`` supplies a comma-separated list of hostnames or IP addresses.
* ``--ports`` specifies an explicit list or range of TCP ports to probe.
* ``--top-ports`` requests the *N* most common TCP ports.
* ``--json`` selects the output file (``stdout`` is used when omitted).

Any additional arguments passed via ``--smrib-extra`` are safely ignored by the
parser, allowing callers to extend the command line without modifying this
script.  The implementation intentionally favours clarity and resilience over
raw performance; the goal is to provide a dependable default scanner that does
not require external dependencies.
"""

from __future__ import annotations

import argparse
import ipaddress
import json
import os
import socket
import sys
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass
from pathlib import Path
from typing import Dict, Iterable, Iterator, List, Optional, Sequence, Set, Tuple

# Nmap's "top ports" list cannot be redistributed directly without the original
# project.  Instead we provide a curated selection of commonly exposed TCP
# services.  The ordering reflects their relative popularity so that requests
# such as ``--top-ports 10`` focus on the most ubiquitous services first.
COMMON_TCP_PORTS: Tuple[int, ...] = (
    80,
    443,
    22,
    21,
    25,
    23,
    110,
    143,
    53,
    135,
    139,
    445,
    993,
    995,
    1723,
    3306,
    3389,
    5900,
    5901,
    5902,
    5903,
    5904,
    5905,
    8080,
    8443,
    8000,
    8081,
    8444,
    8888,
    8880,
    8008,
    4443,
    1433,
    1521,
    5432,
    5500,
    5985,
    5986,
    6379,
    7001,
    7002,
    7003,
    7004,
    8009,
    8010,
    8082,
    8083,
    8086,
    8087,
    8088,
    8090,
    8091,
    8181,
    8222,
    8300,
    8447,
    8500,
    8600,
    8649,
    8883,
    9000,
    9001,
    9002,
    9042,
    9090,
    9091,
    9200,
    9300,
    9418,
    9443,
    9485,
    9500,
    9600,
    9700,
    9785,
    9898,
    9997,
    9999,
    10000,
    10001,
    10002,
    10050,
    10051,
    10161,
    10243,
    11211,
    27017,
    27018,
    27019,
    28017,
    37777,
    44818,
    49152,
    49153,
    49154,
    49155,
    49156,
    49157,
    49158,
    49159,
    49160,
    50000,
    50070,
    50075,
    61616,
    19,
    37,
    69,
    88,
    102,
    111,
    161,
    162,
    389,
    427,
    520,
    546,
    547,
    873,
    989,
    990,
    992,
    2000,
    2049,
    2121,
    2222,
    2601,
    2602,
    2604,
    2605,
    3000,
    3268,
    3269,
    3388,
    3986,
    4444,
    4567,
    4899,
    4911,
    5009,
    5222,
    5269,
    5280,
    5357,
    5439,
    5560,
    5631,
    5666,
    5800,
    5801,
    5906,
    5907,
    6000,
    6001,
)


@dataclass(frozen=True)
class Target:
    """Represent a single host to be scanned."""

    label: str
    addresses: Tuple[str, ...]


@dataclass
class ScanJob:
    """Describe a single (address, port) probe."""

    address: str
    port: int
    label: str


@dataclass
class ScanResult:
    """Aggregate the ports that were reachable for a target address."""

    label: str
    address: str
    open_ports: Set[int]


def parse_port_spec(spec: str) -> List[int]:
    """Expand a textual port specification into a sorted list of integers."""

    ports: Set[int] = set()
    for part in spec.split(","):
        candidate = part.strip()
        if not candidate:
            continue
        if "-" in candidate:
            start_text, end_text = candidate.split("-", 1)
            if not start_text.isdigit() or not end_text.isdigit():
                raise ValueError(f"Invalid port range: '{candidate}'")
            start = int(start_text)
            end = int(end_text)
            if start > end:
                start, end = end, start
            for value in range(start, end + 1):
                _validate_port(value)
                ports.add(value)
        else:
            if not candidate.isdigit():
                raise ValueError(f"Invalid port: '{candidate}'")
            value = int(candidate)
            _validate_port(value)
            ports.add(value)
    if not ports:
        raise ValueError("Port specification did not yield any usable ports")
    return sorted(ports)


def _validate_port(value: int) -> None:
    if not 1 <= value <= 65535:
        raise ValueError(f"Port values must be between 1 and 65535 (got {value})")


def build_port_list(args: argparse.Namespace) -> List[int]:
    """Return the list of ports requested via --ports or --top-ports."""

    if args.ports and args.top_ports:
        raise SystemExit("Specify either --ports or --top-ports, not both")

    if args.ports:
        try:
            return parse_port_spec(args.ports)
        except ValueError as exc:  # pragma: no cover - validated in CLI usage
            raise SystemExit(str(exc)) from exc

    if args.top_ports is None:
        # Default to the 100 most common ports when neither option is supplied.
        count = 100
    else:
        if args.top_ports <= 0:
            raise SystemExit("--top-ports must be a positive integer")
        count = args.top_ports

    if count > len(COMMON_TCP_PORTS):
        ports = sorted(set(COMMON_TCP_PORTS))
        ports.extend(range(1, 65536))
        deduped: List[int] = []
        for port in ports:
            if port not in deduped:
                deduped.append(port)
            if len(deduped) >= count:
                return deduped
        return deduped

    return list(COMMON_TCP_PORTS[:count])


def resolve_targets(labels: Sequence[str]) -> List[Target]:
    """Resolve targets into concrete IP addresses (IPv4/IPv6)."""

    resolved: List[Target] = []
    for label in labels:
        label = label.strip()
        if not label:
            continue
        addresses: Set[str] = set()
        try:
            ipaddress.ip_address(label)
            addresses.add(label)
        except ValueError:
            try:
                infos = socket.getaddrinfo(label, None)
            except socket.gaierror:
                continue
            for _, _, _, _, sockaddr in infos:
                addresses.add(sockaddr[0])
        if addresses:
            resolved.append(Target(label=label, addresses=tuple(sorted(addresses))))
    return resolved


def iter_scan_jobs(targets: Sequence[Target], ports: Sequence[int]) -> Iterator[ScanJob]:
    for target in targets:
        for address in target.addresses:
            for port in ports:
                yield ScanJob(address=address, port=port, label=target.label)


def probe(job: ScanJob, timeout: float) -> Tuple[str, int, bool]:
    """Attempt to connect to a host:port tuple."""

    try:
        with socket.create_connection((job.address, job.port), timeout=timeout):
            return job.address, job.port, True
    except (OSError, socket.timeout):
        return job.address, job.port, False


def execute_scan(targets: Sequence[Target], ports: Sequence[int], timeout: float, workers: int) -> Dict[str, ScanResult]:
    """Perform the TCP connection attempts and collate the outcome."""

    results: Dict[str, ScanResult] = {}
    jobs = list(iter_scan_jobs(targets, ports))
    if not jobs:
        return results

    max_workers = max(1, min(workers, len(jobs)))
    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        future_to_job = {executor.submit(probe, job, timeout): job for job in jobs}
        for future in as_completed(future_to_job):
            job = future_to_job[future]
            try:
                address, port, is_open = future.result()
            except Exception:  # pragma: no cover - defensive safety net
                continue
            if not is_open:
                continue
            entry = results.setdefault(
                address,
                ScanResult(label=job.label, address=address, open_ports=set()),
            )
            entry.open_ports.add(port)
    return results


def serialise_results(results: Dict[str, ScanResult]) -> List[Dict[str, object]]:
    """Transform internal results into the JSON structure expected by Recon."""

    serialised: List[Dict[str, object]] = []
    for address in sorted(results):
        result = results[address]
        ports = sorted(result.open_ports)
        serialised.append(
            {
                "ip": address,
                "host": result.label,
                "ports": [{"port": port} for port in ports],
            }
        )
    return serialised


def ensure_parent(path: Path) -> None:
    """Create the parent directory for *path* when it does not yet exist."""

    parent = path.parent
    if parent and not parent.exists():
        parent.mkdir(parents=True, exist_ok=True)


def parse_arguments(argv: Optional[Sequence[str]] = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Perform a lightweight TCP port scan")
    parser.add_argument(
        "--targets",
        required=True,
        help="Comma separated list of hosts or IP addresses to scan.",
    )
    parser.add_argument(
        "--ports",
        help=(
            "Explicit TCP ports to scan. Comma separated values and ranges (e.g. "
            "'80,443,1000-1010') are supported."
        ),
    )
    parser.add_argument(
        "--top-ports",
        type=int,
        help="Scan the N most common TCP ports (defaults to 100 when omitted).",
    )
    parser.add_argument(
        "--timeout",
        type=float,
        default=1.0,
        help="Socket timeout (seconds) for individual connection attempts.",
    )
    parser.add_argument(
        "--workers",
        type=int,
        default=os.cpu_count() or 4,
        help="Maximum number of concurrent connection attempts.",
    )
    parser.add_argument(
        "--json",
        type=Path,
        help="Write scan results to the specified JSON file instead of stdout.",
    )
    parser.add_argument(
        "extra",
        nargs=argparse.REMAINDER,
        help="Ignored placeholder for compatibility with upstream scripts.",
    )
    return parser.parse_args(argv)


def main(argv: Optional[Sequence[str]] = None) -> int:
    args = parse_arguments(argv)

    targets = [target.strip() for target in args.targets.split(",") if target.strip()]
    if not targets:
        print("No targets supplied", file=sys.stderr)
        return 1

    port_list = build_port_list(args)
    resolved = resolve_targets(targets)
    if not resolved:
        print("Unable to resolve any supplied targets", file=sys.stderr)
        return 2

    results = execute_scan(resolved, port_list, args.timeout, args.workers)
    serialised = serialise_results(results)

    output = json.dumps(serialised, indent=2)

    if args.json:
        ensure_parent(args.json)
        args.json.write_text(output + "\n", encoding="utf-8")
    else:
        print(output)

    return 0


if __name__ == "__main__":  # pragma: no cover - CLI entry point
    sys.exit(main())
