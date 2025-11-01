#!/usr/bin/env python3
# Orchestrate a three-stage reconnaissance workflow that chains together
# discovery, service fingerprinting, and OSINT enrichment. The execution flow
# is intentionally verbose to make the automation steps clear:
#
# 1. Discovery scan – execute Masscan (default), ``smrib.py``, or Nmap against
#    the supplied targets to find live hosts and open TCP ports.
# 2. Detailed fingerprinting – run a comprehensive Nmap scan for the discovered
#    host/port combinations, capturing service, version, and OS information.
# 3. OSINT collection – when supported, query theHarvester to enumerate
#    hostnames and subdomains related to the identified domains.
#
# The aggregated results are written to ``inventory.json`` and
# ``inventory.csv`` and summarised in ``report.md`` together with any
# EyeWitness screenshots.

from __future__ import annotations

import argparse
import atexit
import ipaddress
import json
import os
import re
import shutil
import socket
import subprocess
import sys
import tempfile
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, Iterable, List, Mapping, Optional, Sequence, Set, TextIO, Union

from tools import aggregate


ROOT = Path(__file__).resolve().parent
OUT_DIR = ROOT / "out"
DISCOVERY_DIR = OUT_DIR / "discovery"
NMAP_DIR = OUT_DIR / "nmap"
HARVESTER_DIR = OUT_DIR / "harvester"
EYEWITNESS_DIR = OUT_DIR / "eyewitness"
INVENTORY_JSON = OUT_DIR / "inventory.json"
INVENTORY_CSV = OUT_DIR / "inventory.csv"
REPORT_PATH = OUT_DIR / "report.md"
MASSCAN_JSON = OUT_DIR / "masscan.json"
SMRIB_JSON = OUT_DIR / "smrib.json"
TARGETS_FILE = ROOT / "targets.txt"
LOG_PATH = OUT_DIR / "recon.log"


TOOL_SUMMARIES = {
    "Masscan": (
        "Masscan performs a high-speed TCP SYN sweep to quickly spot responsive "
        "hosts and their open ports. It favours breadth and speed, trading some "
        "accuracy for rapid coverage of large target lists."
    ),
    "Nmap": (
        "Nmap is used twice: optionally for discovery and always for in-depth "
        "fingerprinting. During fingerprinting it runs default scripts, probes "
        "service banners, and attempts OS detection to build a rich host profile."
    ),
    "theHarvester": (
        "theHarvester enriches the scan by querying OSINT sources for "
        "subdomains, hostnames, and related infrastructure connected to "
        "discovered domains."
    ),
    "EyeWitness": (
        "EyeWitness drives a headless browser against detected HTTP(S) services "
        "to capture screenshots, providing a quick visual triage of exposed "
        "web interfaces."
    ),
}


_PRIVILEGE_WARNINGS: Set[str] = set()
_SILENT_MODE = False
_LOG_FILE: Optional[TextIO] = None


def _ensure_log_file() -> TextIO:
    """Return an open handle to the workflow log file, creating it on demand."""

    global _LOG_FILE
    if _LOG_FILE is None:
        OUT_DIR.mkdir(parents=True, exist_ok=True)
        timestamp = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S %Z")
        _LOG_FILE = LOG_PATH.open("w", encoding="utf-8")
        _LOG_FILE.write("=" * 72 + "\n")
        _LOG_FILE.write(f"Reconnaissance run started {timestamp}\n")
        _LOG_FILE.write("=" * 72 + "\n")
        _LOG_FILE.flush()
    return _LOG_FILE


def _close_log_file() -> None:
    """Close the log file when the interpreter exits."""

    global _LOG_FILE
    if _LOG_FILE is not None:
        _LOG_FILE.close()
        _LOG_FILE = None


atexit.register(_close_log_file)


def _log_message(message: str) -> None:
    """Append a formatted message to the log file."""

    handle = _ensure_log_file()
    if message.endswith("\n"):
        handle.write(message)
    else:
        handle.write(f"{message}\n")
    handle.flush()


def _log_stream_output(text: str) -> None:
    """Record raw subprocess output in the log file."""

    handle = _ensure_log_file()
    handle.write(text)
    if not text.endswith("\n"):
        handle.write("\n")
    handle.flush()


def echo(message: str, *, essential: bool = False) -> None:
    """Print a message unless running in silent mode, always logging it."""

    _log_message(message)
    if not _SILENT_MODE or essential or message.startswith("[!]"):
        print(message)


def warn_privileges(tool: str, use_sudo: bool) -> None:
    """Warn once when a scanner is likely to require elevated privileges."""

    if use_sudo:
        return

    # ``os.geteuid`` is not available on Windows, so guard the lookup.
    geteuid = getattr(os, "geteuid", None)
    if geteuid is None:
        return

    if geteuid() == 0:
        return

    if tool in _PRIVILEGE_WARNINGS:
        return

    _PRIVILEGE_WARNINGS.add(tool)
    echo(
        f"[!] {tool} typically requires elevated privileges for raw socket scans. "
        "Re-run with --sudo or as root if the command fails with permission errors.",
        essential=True,
    )


def ensure_writable_directory(path: Path) -> None:
    """Ensure that the provided directory exists and is writable."""

    try:
        path.mkdir(parents=True, exist_ok=True)
    except PermissionError as exc:
        raise SystemExit(
            f"Unable to create directory '{path}': {exc}. Adjust its permissions or "
            "run the script with elevated privileges."
        ) from exc

    if not os.access(path, os.W_OK | os.X_OK):
        raise SystemExit(
            f"Directory '{path}' is not writable. Update its ownership/permissions "
            "or rerun the script with --sudo."
        )

    try:
        with tempfile.TemporaryFile(dir=path):
            pass
    except PermissionError as exc:
        raise SystemExit(
            f"Unable to write to directory '{path}': {exc}. Fix permissions or use "
            "--sudo to continue."
        ) from exc


@dataclass
class PortSelection:
    # Represent the discovery port scanning strategy so the same configuration
    # can be reused by Masscan, smrib.py, and Nmap.

    description: str
    masscan_args: List[str]
    nmap_args: List[str]
    smrib_args: List[str]
    forced_ports: Optional[List[int]] = None


def parse_args(argv: Optional[Sequence[str]] = None) -> argparse.Namespace:
    # Configure the command-line interface and explain every supported stage so
    # the automation can be controlled without editing the script.
    parser = argparse.ArgumentParser(
        description=(
            "Run the reconnaissance workflow: discovery (masscan/smrib/nmap) → "
            "detailed Nmap fingerprinting → theHarvester → aggregation."
        )
    )
    parser.add_argument(
        "--scanner",
        choices=("masscan", "smrib", "nmap"),
        default="masscan",
        help="Scanner to use for the discovery stage (default: masscan).",
    )
    parser.add_argument(
        "--top-ports",
        type=int,
        help="Scan only the top N ports instead of the full range (default: 100).",
    )
    parser.add_argument(
        "--port-range",
        help="Explicit port range or comma separated list (default: 1-65535).",
    )
    parser.add_argument(
        "--ports",
        help="Comma separated list of TCP ports to scan and fingerprint.",
    )
    parser.add_argument(
        "--masscan-rate",
        type=int,
        default=1000,
        help="Packet rate to use with masscan (default: 1000).",
    )
    parser.add_argument(
        "--masscan-status-interval",
        type=float,
        help=(
            "Seconds between masscan status updates. Use 0 to suppress the "
            "progress lines."
        ),
    )
    parser.add_argument(
        "--smrib-path",
        default=os.environ.get("SMRIB_PATH", str(Path.home() / "Desktop/RT/smrib.py")),
        help="Location of smrib.py when using the smrib discovery option.",
    )
    parser.add_argument(
        "--smrib-extra",
        nargs=argparse.REMAINDER,
        help="Additional arguments to forward to smrib.py after the defaults.",
    )
    parser.add_argument(
        "--harvester-sources",
        default="all",
        help="Comma separated sources for theHarvester (default: all).",
    )
    parser.add_argument(
        "--harvester-source",
        dest="harvester_source",
        action="append",
        help=(
            "Repeatable option to choose individual theHarvester sources. "
            "When supplied, overrides --harvester-sources."
        ),
    )
    parser.add_argument(
        "--harvester-limit",
        type=int,
        default=500,
        help="Result limit for theHarvester queries (default: 500).",
    )
    parser.add_argument(
        "--skip-eyewitness",
        action="store_true",
        help="Skip the EyeWitness screenshot stage.",
    )
    parser.add_argument(
        "--eyewitness-timeout",
        type=int,
        default=10,
        help="Timeout (seconds) for EyeWitness requests (default: 10).",
    )
    parser.add_argument(
        "--eyewitness-threads",
        type=int,
        default=4,
        help="Number of EyeWitness browser threads (default: 4).",
    )
    parser.add_argument(
        "--sudo",
        action="store_true",
        help="Prefix network scanners with sudo when available.",
    )
    parser.add_argument(
        "--silent",
        action="store_true",
        help="Only display essential status messages.",
    )

    args = parser.parse_args(argv)

    if args.harvester_source:
        sources: List[str] = []
        for entry in args.harvester_source:
            for part in entry.split(","):
                cleaned = part.strip()
                if cleaned:
                    sources.append(cleaned)

        if not sources:
            raise SystemExit("--harvester-source requires at least one source name")

        args.harvester_sources = ",".join(sources)

    return args


def build_port_selection(args: argparse.Namespace) -> PortSelection:
    # Decide which port coverage strategy to use. Users can explicitly request a
    # port range or the top-N ports. When no preference is provided the script
    # defaults to the top 100 ports to keep the initial scan focused.
    explicit_top_ports = args.top_ports is not None
    top_ports = args.top_ports

    if args.ports and args.port_range:
        raise SystemExit("Specify either --ports or --port-range, not both.")
    if args.ports and explicit_top_ports:
        raise SystemExit("Specify either --ports or --top-ports, not both.")

    if args.ports:
        ports: List[int] = []
        for entry in args.ports.split(","):
            part = entry.strip()
            if not part:
                continue
            if not part.isdigit():
                raise SystemExit("--ports must contain only integers separated by commas")
            value = int(part)
            if not 1 <= value <= 65535:
                raise SystemExit("--ports values must be between 1 and 65535")
            ports.append(value)

        if not ports:
            raise SystemExit("--ports requires at least one port number")

        unique_ports = sorted(dict.fromkeys(ports))
        port_list = ",".join(str(port) for port in unique_ports)

        return PortSelection(
            description=f"ports {port_list}",
            masscan_args=["-p", port_list],
            nmap_args=["-p", port_list],
            smrib_args=["--ports", port_list],
            forced_ports=unique_ports,
        )

    if not args.port_range and not explicit_top_ports:
        top_ports = 100

    if top_ports is not None and top_ports <= 0:
        raise SystemExit("--top-ports must be a positive integer")

    if args.port_range and explicit_top_ports:
        raise SystemExit("Specify either --top-ports or --port-range, not both.")

    if args.port_range:
        if not re.fullmatch(r"[0-9,-]+", args.port_range):
            raise SystemExit("--port-range must contain only digits, commas, and hyphens")
        description = f"ports {args.port_range}"
        masscan_args = ["-p", args.port_range]
        nmap_args = ["-p", args.port_range]
        smrib_args = ["--ports", args.port_range]
    elif top_ports is not None:
        description = f"top {top_ports} ports"
        value = str(top_ports)
        masscan_args = ["--top-ports", value]
        nmap_args = ["--top-ports", value]
        smrib_args = ["--top-ports", value]
    else:
        description = "ports 1-65535"
        masscan_args = ["-p", "1-65535"]
        nmap_args = ["-p", "1-65535"]
        smrib_args = ["--ports", "1-65535"]
    return PortSelection(description, masscan_args, nmap_args, smrib_args)


def load_targets(path: Path) -> List[str]:
    # Load the reconnaissance targets from disk. If the operator has not
    # prepared a list yet, create a starter file that points at
    # ``hackthissite.org`` so the workflow can run immediately.
    if not path.exists():
        path.write_text("hackthissite.org\n", encoding="utf-8")
        echo(f"[+] Created default targets file at {path} with hackthissite.org", essential=True)

    targets: List[str] = []
    for line in path.read_text(encoding="utf-8").splitlines():
        stripped = line.strip()
        if not stripped:
            continue

        # Allow operators to annotate entries with comments by stripping the
        # fragment that follows ``#``.  Lines that only contain a comment are
        # ignored entirely.
        if "#" in stripped:
            stripped, _, _ = stripped.partition("#")
            stripped = stripped.strip()
            if not stripped:
                continue

        if stripped.startswith("#"):
            continue
        targets.append(stripped)

    if not targets:
        raise SystemExit("No targets defined in targets.txt")

    return targets


def prefix_command(cmd: List[str], use_sudo: bool) -> List[str]:
    # Optionally prefix commands with sudo when elevated permissions are
    # required and sudo is available on the host system.
    if not use_sudo:
        return cmd
    sudo_path = shutil.which("sudo")
    if sudo_path:
        return [sudo_path] + cmd
    return cmd


def _format_banner(title: str) -> List[str]:
    """Create a high-contrast banner that highlights the running tool."""

    clean = " ".join(title.strip().split()) or "Running"
    label = f" RUNNING: {clean} "
    width = max(len(label), 32)
    top_bottom = "═" * width
    padded = label.center(width)
    return [
        f"╔{top_bottom}╗",
        f"║{padded}║",
        f"╚{top_bottom}╝",
    ]


def run_command(cmd: List[str], *, description: str, check: bool = False) -> bool:
    # Execute a subprocess while printing clear status messages. Returning a
    # boolean allows callers to gracefully skip follow-up steps when a stage
    # fails instead of raising an exception mid-pipeline.
    banner_lines = _format_banner(description)
    if not _SILENT_MODE:
        echo("")
    for line in banner_lines:
        echo(line, essential=True)
    if not _SILENT_MODE:
        echo("  Details:")
        echo(f"    {description}")
        echo("  Command:")
        echo(f"    {' '.join(cmd)}")
    try:
        proc = subprocess.Popen(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
        )
    except FileNotFoundError:
        echo(f"[!] Command not found: {cmd[0]}", essential=True)
        return False
    except OSError as exc:
        echo(f"[!] Unable to execute {cmd[0]}: {exc}", essential=True)
        return False

    output_chunks: List[str] = []
    assert proc.stdout is not None
    for line in proc.stdout:
        output_chunks.append(line)
        _log_stream_output(line)
        if not _SILENT_MODE:
            sys.stdout.write(line)
            sys.stdout.flush()
    proc.stdout.close()
    return_code = proc.wait()

    if return_code != 0:
        message = f"[!] Command failed with exit code {return_code}"
        echo(message, essential=True)
        if check:
            raise subprocess.CalledProcessError(return_code, cmd, output="".join(output_chunks))
        return False

    return True


def run_masscan(
    targets: Sequence[str],
    port_selection: PortSelection,
    rate: int,
    status_interval: Optional[float],
    use_sudo: bool,
) -> Mapping[str, Set[int]]:
    # Perform the high-speed discovery scan with Masscan, resolving hostnames
    # to IPv4 addresses when necessary.
    if not shutil.which("masscan"):
        echo("[!] masscan is not installed or not in PATH – skipping discovery stage.", essential=True)
        return {}

    resolved_targets: List[str] = []
    for target in targets:
        try:
            # Preserve IP addresses and networks as-is so Masscan can handle
            # them directly.
            ipaddress.ip_network(target, strict=False)
            resolved_targets.append(target)
            continue
        except ValueError:
            pass

        try:
            ipaddress.ip_address(target)
            resolved_targets.append(target)
            continue
        except ValueError:
            pass

        try:
            infos = socket.getaddrinfo(target, None)
        except socket.gaierror:
            echo(f"[!] Unable to resolve target '{target}' for Masscan – skipping.", essential=True)
            continue

        ipv4_addresses = {
            info[4][0]
            for info in infos
            if info and info[4] and isinstance(info[4][0], str) and ":" not in info[4][0]
        }

        if not ipv4_addresses:
            echo(f"[!] No IPv4 addresses resolved for '{target}' – skipping Masscan entry.", essential=True)
            continue

        resolved_targets.extend(sorted(ipv4_addresses))

    if not resolved_targets:
        echo("[!] No valid targets available for Masscan – skipping discovery stage.", essential=True)
        return {}

    warn_privileges("masscan", use_sudo)

    cmd = [
        "masscan",
        "--rate",
        str(rate),
        "--open",
        "--output-format",
        "json",
        "-oJ",
        str(MASSCAN_JSON),
    ]
    if status_interval is not None:
        interval_value: Union[float, int]
        if isinstance(status_interval, float) and status_interval.is_integer():
            interval_value = int(status_interval)
        else:
            interval_value = status_interval
        cmd.extend(["--status", str(interval_value)])
    cmd.extend(port_selection.masscan_args)
    cmd.extend(list(dict.fromkeys(resolved_targets)))
    target_count = len(resolved_targets)
    description = (
        "Masscan discovery – high-speed TCP SYN sweep "
        f"across {target_count} target(s) covering {port_selection.description} "
        f"at {rate} packets/sec"
    )
    success = run_command(prefix_command(cmd, use_sudo), description=description)
    if not success:
        return {}

    results = aggregate.parse_masscan_json(str(MASSCAN_JSON))
    return {ip: set(data.get("masscan_ports", [])) for ip, data in results.items()}


def run_smrib(
    targets: Sequence[str],
    port_selection: PortSelection,
    smrib_path: str,
    extra_args: Optional[Sequence[str]],
    use_sudo: bool,
) -> Mapping[str, Set[int]]:
    # Provide an alternative discovery method that shells out to smrib.py with
    # similar arguments to the Masscan workflow.
    script_path = Path(smrib_path).expanduser()
    if not script_path.exists():
        echo(f"[!] smrib.py not found at {script_path} – skipping discovery stage.", essential=True)
        return {}

    cmd: List[str] = [sys.executable or "python3", str(script_path)]
    cmd.extend(port_selection.smrib_args)
    cmd.extend(["--json", str(SMRIB_JSON)])
    cmd.extend(["--targets", ",".join(targets)])
    if extra_args:
        cmd.extend(extra_args)

    description = (
        "smrib discovery – Python-based scanner performing targeted TCP probes "
        f"across {port_selection.description}"
    )
    success = run_command(prefix_command(cmd, use_sudo), description=description)
    if not success:
        return {}

    results = aggregate.parse_smrib_json(str(SMRIB_JSON))
    return {ip: set(data.get("smrib_ports", [])) for ip, data in results.items()}


def run_nmap_discovery(
    targets: Sequence[str],
    port_selection: PortSelection,
    use_sudo: bool,
) -> Mapping[str, Set[int]]:
    # Use Nmap for the discovery phase when Masscan or smrib.py are not
    # requested, saving greppable output per target for later parsing.
    if not shutil.which("nmap"):
        echo("[!] nmap not installed – unable to perform discovery stage.", essential=True)
        return {}

    warn_privileges("nmap", use_sudo)

    DISCOVERY_DIR.mkdir(parents=True, exist_ok=True)
    discovered: Dict[str, Set[int]] = {}
    for target in targets:
        sanitized = re.sub(r"[^0-9A-Za-z_.-]", "_", target)
        outbase = DISCOVERY_DIR / sanitized
        cmd = [
            "nmap",
            "-Pn",
            "-sS",
            "-T4",
            "-oA",
            str(outbase),
        ]
        cmd.extend(port_selection.nmap_args)
        cmd.append(target)
        port_summary = port_selection.description
        description = (
            f"Nmap discovery for {target} – TCP connect/SYN sweep focusing on {port_summary}"
        )
        run_command(prefix_command(cmd, use_sudo), description=description)

    results = aggregate.parse_nmap_dir(str(DISCOVERY_DIR))
    for ip, data in results.items():
        ports = {
            entry.get("port")
            for entry in data.get("nmap_ports", [])
            if entry.get("state") == "open"
        }
        discovered[ip] = {port for port in ports if port is not None}
    return discovered


def merge_discovered_hosts(
    targets: Sequence[str],
    masscan_results: Mapping[str, Set[int]],
    smrib_results: Mapping[str, Set[int]],
    nmap_results: Mapping[str, Set[int]],
    forced_ports: Optional[Sequence[int]],
) -> Dict[str, Set[int]]:
    # Consolidate discovery findings. Only ports confirmed during discovery will
    # be fingerprinted in the next stage.
    merged: Dict[str, Set[int]] = {}

    for result in (masscan_results, smrib_results, nmap_results):
        for ip, ports in result.items():
            merged.setdefault(ip, set()).update(ports)

    if forced_ports:
        forced_sorted = sorted(dict.fromkeys(forced_ports))
        forced_set = set(forced_sorted)
        overridden: Dict[str, Set[int]] = {}
        for host in merged:
            overridden[host] = set(forced_set)

        for target in targets:
            overridden.setdefault(target, set(forced_set))

        return overridden

    if not merged:
        for target in targets:
            merged[target] = set()

    for ip, ports in list(merged.items()):
        merged[ip] = set(sorted(ports))

    return merged


def display_discovered_hosts(
    discovered_hosts: Mapping[str, Set[int]],
) -> None:
    """Print a concise summary of discovered hosts and their ports."""

    if not discovered_hosts:
        echo("[!] No hosts discovered during the discovery phase.", essential=True)
        return

    echo("[+] Hosts and ports identified:", essential=True)
    for host in sorted(discovered_hosts):
        ports = discovered_hosts[host]
        if ports:
            port_list = ", ".join(str(port) for port in sorted(ports))
        else:
            port_list = "no open ports discovered"
        echo(f"    - {host}: {port_list}", essential=True)


def run_nmap_fingerprinting(
    hosts: Mapping[str, Set[int]],
    use_sudo: bool,
) -> None:
    # Perform comprehensive service detection with Nmap using only the
    # host/port combinations identified during discovery.
    if not shutil.which("nmap"):
        echo("[!] nmap is required for the fingerprinting stage; skipping.", essential=True)
        return

    warn_privileges("nmap", use_sudo)

    NMAP_DIR.mkdir(parents=True, exist_ok=True)
    actionable_hosts = {target: ports for target, ports in hosts.items() if ports}

    if not actionable_hosts:
        echo("[!] No open ports discovered during phase 1 – skipping fingerprinting stage.", essential=True)
        return

    for target, ports in actionable_hosts.items():
        sanitized = re.sub(r"[^0-9A-Za-z_.-]", "_", target)
        outbase = NMAP_DIR / sanitized
        cmd = [
            "nmap",
            "-sC",
            "-sV",
            "-O",
            "-T4",
            "-oA",
            str(outbase),
        ]
        port_list = ",".join(str(port) for port in sorted(ports))
        cmd.extend(["-p", port_list])
        port_scope = f"{len(ports)} discovered port(s)"
        cmd.append(target)
        description = (
            f"Nmap fingerprinting for {target} – default scripts, version, and OS detection "
            f"against {port_scope}"
        )
        run_command(prefix_command(cmd, use_sudo), description=description)


def extract_domains_from_nmap() -> Set[str]:
    # Parse the Nmap XML output to collect second-level domains that can be fed
    # into theHarvester for OSINT enrichment.
    results = aggregate.parse_nmap_dir(str(NMAP_DIR))
    domains: Set[str] = set()
    for data in results.values():
        for hostname in data.get("hostnames", []):
            try:
                ipaddress.ip_address(hostname)
                continue
            except ValueError:
                pass
            parts = hostname.lower().strip().split(".")
            parts = [part for part in parts if part]
            if len(parts) < 2:
                continue
            domain = ".".join(parts[-2:])
            domains.add(domain)
    return domains


_HARVESTER_HELP_CACHE: Optional[str] = None


def _harvester_supports_option(executable: str, option: str) -> bool:
    # Cache theHarvester help output to detect whether optional flags are
    # supported by the installed version.
    global _HARVESTER_HELP_CACHE
    if _HARVESTER_HELP_CACHE is None:
        try:
            proc = subprocess.run(
                [executable, "-h"],
                check=False,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                text=True,
            )
            _HARVESTER_HELP_CACHE = proc.stdout or ""
        except Exception:
            _HARVESTER_HELP_CACHE = ""

    pattern = re.compile(rf"(?m)^\s*{re.escape(option)}\b")
    return bool(_HARVESTER_HELP_CACHE and pattern.search(_HARVESTER_HELP_CACHE))


def run_harvester(domains: Iterable[str], args: argparse.Namespace) -> None:
    # Collect OSINT for each discovered domain, falling back to built-in DNS
    # commands when theHarvester is not present.
    HARVESTER_DIR.mkdir(parents=True, exist_ok=True)
    harvester_path = shutil.which("theHarvester")

    for domain in sorted(set(domains)):
        if not domain:
            continue

        if harvester_path:
            prefix = HARVESTER_DIR / domain
            cmd = [
                harvester_path,
                "-d",
                domain,
                "-b",
                args.harvester_sources,
                "-l",
                str(args.harvester_limit),
                "-f",
                str(prefix),
            ]
            json_flag: Optional[List[str]] = None
            if _harvester_supports_option(harvester_path, "-o"):
                json_flag = ["-o", f"{prefix}.json"]
            elif _harvester_supports_option(harvester_path, "-j"):
                json_flag = ["-j", f"{prefix}.json"]
            elif _harvester_supports_option(harvester_path, "--json"):
                json_flag = ["--json", f"{prefix}.json"]

            if json_flag:
                cmd.extend(json_flag)
            description = (
                f"theHarvester OSINT for {domain} – enumerating hosts via sources: {args.harvester_sources}"
            )
            run_command(cmd, description=description)
        else:
            echo(
                f"[!] theHarvester not available – collecting basic DNS data for {domain}",
                essential=True,
            )
            host_out = HARVESTER_DIR / f"{domain}.host.txt"
            dig_out = HARVESTER_DIR / f"{domain}.dig.txt"
            with host_out.open("w", encoding="utf-8") as hfile:
                subprocess.run(["host", domain], stdout=hfile, stderr=subprocess.STDOUT)
            with dig_out.open("w", encoding="utf-8") as dfile:
                subprocess.run(["dig", "+short", "any", domain], stdout=dfile, stderr=subprocess.STDOUT)


def aggregate_results() -> None:
    # Invoke the aggregation helper to merge outputs from every stage into the
    # consolidated inventory artefacts.
    cmd = [
        sys.executable or "python3",
        str(ROOT / "tools" / "aggregate.py"),
        "--nmap-dir",
        str(NMAP_DIR),
        "--masscan-json",
        str(MASSCAN_JSON),
        "--smrib-json",
        str(SMRIB_JSON),
        "--harv-dir",
        str(HARVESTER_DIR),
        "--out-json",
        str(INVENTORY_JSON),
        "--out-csv",
        str(INVENTORY_CSV),
    ]
    description = (
        "Aggregating scan outputs – merging Masscan, Nmap, smrib, and theHarvester artefacts"
    )
    run_command(cmd, description=description, check=False)


def collect_http_urls(inventory: List[Mapping[str, object]]) -> List[str]:
    # Walk the aggregated inventory and build a deduplicated list of HTTP(S)
    # endpoints that EyeWitness should visit.
    urls: List[str] = []
    for entry in inventory:
        ip = entry.get("ip")
        if not isinstance(ip, str):
            continue
        for service in entry.get("services", []) or []:
            port = service.get("port") if isinstance(service, dict) else None
            name = (service.get("service") or "").lower() if isinstance(service, dict) else ""
            if not isinstance(port, int):
                continue

            scheme = "http"
            if "https" in name or port in {443, 8443, 9443}:
                scheme = "https"
            elif "http" not in name and port not in {80, 8080, 8000, 8888}:
                continue

            if port in {80, 443}:
                url = f"{scheme}://{ip}"
            else:
                url = f"{scheme}://{ip}:{port}"
            urls.append(url)
    return sorted(set(urls))


def run_eyewitness(urls: Sequence[str], args: argparse.Namespace) -> List[Path]:
    # Capture screenshots of HTTP services using EyeWitness when the binary is
    # installed and the operator has not opted out of this stage.
    if args.skip_eyewitness or not urls:
        return []

    eyewitness_path = shutil.which("eyewitness")
    if not eyewitness_path:
        echo("[!] EyeWitness not installed – skipping screenshot capture.", essential=True)
        return []

    screenshots: List[Path] = []
    for url in urls:
        safe_dir = re.sub(r"[^0-9A-Za-z_.-]", "_", url)
        output_dir = EYEWITNESS_DIR / safe_dir
        output_dir.mkdir(parents=True, exist_ok=True)
        cmd = [
            eyewitness_path,
            "--web",
            "--timeout",
            str(args.eyewitness_timeout),
            "--threads",
            str(args.eyewitness_threads),
            "--single",
            url,
            "--no-prompt",
            "-d",
            str(output_dir),
        ]
        description = (
            f"EyeWitness capture for {url} – headless browser screenshot of the HTTP(S) service"
        )
        run_command(cmd, description=description)
        screenshots.extend(output_dir.rglob("*.png"))

    return screenshots


def load_inventory() -> List[Mapping[str, object]]:
    # Return the aggregated reconnaissance inventory if it already exists. The
    # data is reused when generating a new report.
    if not INVENTORY_JSON.exists():
        return []
    try:
        with INVENTORY_JSON.open("r", encoding="utf-8") as file:
            data = json.load(file)
        if isinstance(data, list):
            return data
    except json.JSONDecodeError:
        pass
    return []


def write_report(
    args: argparse.Namespace,
    targets: Sequence[str],
    discovery_description: str,
    discovered_hosts: Mapping[str, Optional[Set[int]]],
    screenshots: Sequence[Path],
) -> None:
    # Produce a Markdown summary of the recon run that references the generated
    # inventory and any captured screenshots.
    inventory = load_inventory()
    OUT_DIR.mkdir(parents=True, exist_ok=True)

    timestamp = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    total_hosts = len(inventory)
    total_services = sum(len(entry.get("services", [])) for entry in inventory)

    lines: List[str] = ["# Reconnaissance Report", ""]
    lines.append(f"*Generated*: {timestamp}")
    lines.append(f"*Discovery scanner*: {discovery_description}")
    lines.append(f"*Targets*: {', '.join(targets)}")
    lines.append(f"*Hosts in inventory*: {total_hosts}")
    lines.append(f"*Total services recorded*: {total_services}")
    lines.append("")

    lines.append("## Target Scope")
    if targets:
        for index, target in enumerate(targets, start=1):
            lines.append(f"{index}. {target}")
    else:
        lines.append("No targets were defined when the report was generated.")

    lines.append("")
    lines.append("## Tool Activities")
    for tool, summary in TOOL_SUMMARIES.items():
        lines.append(f"- **{tool}**: {summary}")

    lines.append("")
    lines.append("## Host Overview")
    if inventory:
        for entry in inventory:
            ip = entry.get("ip", "unknown")
            hostnames = ", ".join(entry.get("hostnames", [])) or "-"
            ports = ", ".join(str(port) for port in entry.get("open_ports", [])) or "-"
            os_name = entry.get("os") or "-"
            lines.append(f"- **{ip}** – Hostnames: {hostnames}; Ports: {ports}; OS: {os_name}")
    else:
        lines.append("No aggregated inventory was generated.")

    lines.append("")
    lines.append("## Discovery Summary")
    for host, ports in discovered_hosts.items():
        if ports:
            port_list = ", ".join(str(port) for port in sorted(ports))
        else:
            port_list = "no open ports discovered"
        lines.append(f"- {host}: {port_list}")

    lines.append("")
    lines.append("## Screenshots")
    if screenshots:
        for shot in screenshots:
            rel = shot.relative_to(ROOT)
            lines.append(f"![Screenshot for {shot.stem}]({rel.as_posix()})")
    else:
        if args.skip_eyewitness:
            lines.append("EyeWitness stage skipped by request.")
        else:
            lines.append("No screenshots captured (EyeWitness unavailable or no HTTP services detected).")

    REPORT_PATH.write_text("\n".join(lines), encoding="utf-8")
    echo(f"[+] Wrote report to {REPORT_PATH}", essential=True)


def main(argv: Optional[Sequence[str]] = None) -> None:
    # Tie together all pipeline stages in the intended execution order.
    args = parse_args(argv)
    global _SILENT_MODE
    _SILENT_MODE = args.silent

    echo("[+] Starting reconnaissance workflow", essential=True)
    port_selection = build_port_selection(args)
    targets = load_targets(TARGETS_FILE)
    echo(f"[+] Loaded {len(targets)} target(s) from {TARGETS_FILE}", essential=True)
    if targets:
        echo("    Target list (in scanning order):", essential=True)
        for index, target in enumerate(targets, start=1):
            echo(f"      {index}. {target}", essential=True)
        echo(
            "    Each entry originates from targets.txt; edit that file to adjust the scope.",
            essential=True,
        )

    ensure_writable_directory(OUT_DIR)
    for path in (DISCOVERY_DIR, NMAP_DIR, HARVESTER_DIR, EYEWITNESS_DIR):
        ensure_writable_directory(path)
    echo("[+] Output directories verified", essential=True)

    discovery_description = f"{args.scanner} ({port_selection.description})"
    masscan_results: Mapping[str, Set[int]] = {}
    smrib_results: Mapping[str, Set[int]] = {}
    nmap_results: Mapping[str, Set[int]] = {}

    if args.scanner == "masscan":
        masscan_results = run_masscan(
            targets,
            port_selection,
            args.masscan_rate,
            args.masscan_status_interval,
            args.sudo,
        )
    elif args.scanner == "smrib":
        smrib_results = run_smrib(targets, port_selection, args.smrib_path, args.smrib_extra, args.sudo)
    else:
        nmap_results = run_nmap_discovery(targets, port_selection, args.sudo)

    discovered_hosts = merge_discovered_hosts(
        targets,
        masscan_results,
        smrib_results,
        nmap_results,
        port_selection.forced_ports,
    )

    display_discovered_hosts(discovered_hosts)

    run_nmap_fingerprinting(discovered_hosts, args.sudo)

    domains = extract_domains_from_nmap()
    if domains:
        run_harvester(domains, args)
    else:
        echo("[!] No domains discovered in Nmap XML – skipping theHarvester stage.", essential=True)

    aggregate_results()

    inventory = load_inventory()
    echo(f"[+] Aggregated inventory entries: {len(inventory)}", essential=True)
    urls = collect_http_urls(inventory)
    screenshots = run_eyewitness(urls, args)

    write_report(args, targets, discovery_description, discovered_hosts, screenshots)

    echo(
        f"[+] Recon workflow completed. Inventory: {INVENTORY_JSON}, CSV: {INVENTORY_CSV}",
        essential=True,
    )
    echo(f"[+] Full console output recorded in {LOG_PATH}", essential=True)


if __name__ == "__main__":
    main()
