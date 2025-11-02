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
#
# sudo python3 run_recon.py --scanner nmap --targets-file targets.txt  --top-ports 200 --targets-new-export --search-related-data 
# sudo python3 run_recon.py --scanner smrib --targets hotelasp.com --top-ports 200 --targets-new-export --harvester-sources 'crtsh, bing' --search-related-data
# sudo python3 run_recon.py --scanner smrib --targets-file targets_new.txt --top-ports 200 --targets-new-export --harvester-sources 'crtsh, bing' --search-related-data
# sudo python3 run_recon.py --scanner smrib --targets-file targets.txt --port-range 1-65535 --targets-new-export --search-related-data
# sudo python3 run_recon.py --scanner nmap --targets-file targets.txt --port-range 1-65535 --targets-new-export --search-related-data
#

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
from typing import Dict, Iterable, List, Mapping, Optional, Sequence, Set, TextIO, Tuple, Union

from tools import aggregate


ROOT = Path(__file__).resolve().parent
OUT_DIR = ROOT / "out"
DISCOVERY_DIR = OUT_DIR / "discovery"
NMAP_DIR = OUT_DIR / "nmap"
HARVESTER_DIR = OUT_DIR / "harvester"
EYEWITNESS_DIR = OUT_DIR / "eyewitness"
MASSCAN_DIR = OUT_DIR / "masscan"
SMRIB_DIR = OUT_DIR / "smrib"
REPORT_DIR = OUT_DIR / "report"
LOG_DIR = OUT_DIR / "log"
MASSCAN_JSON = MASSCAN_DIR / "masscan.json"
SMRIB_JSON = SMRIB_DIR / "smrib.json"
INVENTORY_JSON = REPORT_DIR / "inventory.json"
INVENTORY_CSV = REPORT_DIR / "inventory.csv"
REPORT_PATH = REPORT_DIR / "report.md"
TARGETS_FILE = ROOT / "targets.txt"
LOG_PATH = LOG_DIR / "recon.log"
TARGETS_NEW_FILE = ROOT / "targets_new.txt"
# File used to record any domains or hosts that are deliberately ignored during
# the OSINT enrichment stage so the operator can review them manually later.
TARGETS_NOT_PROCESSED_FILE = ROOT / "targets_related_not_processed.txt"


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


SCANNER_LABELS = {
    "masscan": "Masscan",
    "smrib": "smrib.py",
    "nmap": "Nmap",
}


_PRIVILEGE_WARNINGS: Set[str] = set()
_SILENT_MODE = False
_LOG_FILE: Optional[TextIO] = None


def _remove_path(path: Path) -> None:
    """Delete a file or directory, ignoring missing-path errors."""

    try:
        if not path.exists():
            return
        if path.is_file() or path.is_symlink():
            path.unlink()
        else:
            shutil.rmtree(path)
    except FileNotFoundError:
        return


def reset_output_tree() -> None:
    """Clear artefacts from previous runs to avoid cross-run contamination."""

    for artefact in (
        MASSCAN_JSON,
        SMRIB_JSON,
        INVENTORY_JSON,
        INVENTORY_CSV,
        REPORT_PATH,
        LOG_PATH,
        TARGETS_NOT_PROCESSED_FILE,
    ):
        _remove_path(artefact)

    for directory in (
        DISCOVERY_DIR,
        NMAP_DIR,
        HARVESTER_DIR,
        EYEWITNESS_DIR,
        MASSCAN_DIR,
        SMRIB_DIR,
        REPORT_DIR,
        LOG_DIR,
    ):
        _remove_path(directory)


def _ensure_log_file() -> TextIO:
    """Return an open handle to the workflow log file, creating it on demand."""

    global _LOG_FILE
    if _LOG_FILE is None:
        LOG_DIR.mkdir(parents=True, exist_ok=True)
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


def echo_stage(stage_number: int, title: str, *, summary: Optional[str] = None) -> None:
    """Emit a prominent stage heading so operators can follow progress."""

    header = f"[+] Stage {stage_number}: {title}"
    border = "=" * len(header)
    echo("", essential=True)
    echo(border, essential=True)
    echo(header, essential=True)
    if summary:
        echo(f"    {summary}", essential=True)
    echo(border, essential=True)


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
        "Re-run the script with sudo or as root if the command fails with permission errors.",
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
            "or rerun the script with elevated privileges."
        )

    try:
        with tempfile.TemporaryFile(dir=path):
            pass
    except PermissionError as exc:
        raise SystemExit(
            f"Unable to write to directory '{path}': {exc}. Fix permissions or run the "
            "script with elevated privileges to continue."
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


@dataclass
class TargetDefinition:
    # Describe an individual target together with optional per-target ports.

    value: str
    ports: Optional[List[int]] = None

    def formatted(self) -> str:
        if not self.ports:
            return self.value
        port_list = ",".join(str(port) for port in self.ports)
        return f"{self.value} (ports: {port_list})"


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
        default=os.environ.get("SMRIB_PATH", str(Path.home() / "/home/kali/Desktop/RT/smrib.py")),
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
        "--search-related-data",
        action="store_true",
        help=(
            "Iteratively fingerprint hosts discovered via theHarvester for up to three "
            "rounds before aggregating results."
        ),
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
        "--preserve-output",
        action="store_true",
        help=(
            "Keep existing files under out/ instead of wiping them at the start "
            "of a run. When enabled, results from previous executions may bleed "
            "into the current inventory."
        ),
    )
    parser.add_argument(
        "--targets",
        action="append",
        nargs="+",
        metavar="TARGET",
        help=(
            "One or more targets (hostnames, IP addresses, or CIDR ranges) to scan. "
            "Entries may be comma-separated and the option can be repeated."
        ),
    )
    parser.add_argument(
        "--targets-file",
        type=Path,
        metavar="FILE",
        help="Read additional targets from FILE (one per line).",
    )
    parser.add_argument(
        "--targets-new-export",
        action="store_true",
        help=(
            "Export all discovered hosts and domains together with their ports to "
            "targets_new.txt for use in a subsequent run."
        ),
    )
    parser.add_argument(
        "--silent",
        action="store_true",
        help="Only display essential status messages.",
    )

    args = parser.parse_args(argv)

    raw_targets: List[str] = []
    if args.targets:
        for group in args.targets:
            for entry in group:
                for part in entry.split(","):
                    cleaned = part.strip()
                    if cleaned:
                        raw_targets.append(cleaned)
    args.targets = raw_targets

    if args.targets_file is not None:
        args.targets_file = args.targets_file.expanduser()

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


def _parse_port_list(port_text: str) -> List[int]:
    if not port_text:
        return []
    ports: List[int] = []
    for entry in port_text.split(","):
        cleaned = entry.strip()
        if not cleaned:
            continue
        if not cleaned.isdigit():
            raise SystemExit(
                "Target files must specify ports as integers separated by commas"
            )
        value = int(cleaned)
        if not 1 <= value <= 65535:
            raise SystemExit("Target ports must be between 1 and 65535")
        ports.append(value)
    return sorted(dict.fromkeys(ports))


def _split_target_and_ports(raw: str) -> TargetDefinition:
    target = raw.strip()
    port_text = ""

    if not target:
        raise SystemExit("Encountered an empty target entry after processing")

    if " " in target:
        first, rest = target.split(None, 1)
        target = first
        port_text = rest.strip()
    else:
        # Support the common ``target:80,443`` form while avoiding IPv6 mix-ups.
        if target.count(":") == 1:
            host, port_part = target.split(":", 1)
            if port_part and port_part.replace(",", "").isdigit():
                target = host
                port_text = port_part
        elif target.startswith("[") and "]" in target:
            host_part, remainder = target[1:].split("]", 1)
            if remainder.startswith(":") and remainder[1:].replace(",", "").isdigit():
                target = host_part
                port_text = remainder[1:]
            else:
                target = host_part or raw.strip()

    ports = _parse_port_list(port_text) if port_text else None
    return TargetDefinition(target, ports)


def load_targets(path: Path, *, create_default: bool) -> List[TargetDefinition]:
    # Load the reconnaissance targets from disk. When ``create_default`` is
    # enabled and the file is missing, populate it with ``hackthissite.org`` so
    # the workflow has an immediate starting point.
    if not path.exists():
        if not create_default:
            raise SystemExit(f"Targets file not found: {path}")
        path.write_text("hackthissite.org\n", encoding="utf-8")
        echo(f"[+] Created default targets file at {path} with hackthissite.org", essential=True)

    targets: List[TargetDefinition] = []
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

        targets.append(_split_target_and_ports(stripped))

    if not targets:
        raise SystemExit(f"No targets defined in {path}")

    return targets


def _merge_target_definitions(definitions: Sequence[TargetDefinition]) -> List[TargetDefinition]:
    combined: Dict[str, TargetDefinition] = {}
    for definition in definitions:
        key = _normalise_target(definition.value)
        ports = sorted(dict.fromkeys(definition.ports)) if definition.ports else None
        existing = combined.get(key)
        if existing is None:
            combined[key] = TargetDefinition(definition.value, ports)
            continue

        if ports:
            if existing.ports:
                merged = sorted(dict.fromkeys(existing.ports + ports))
            else:
                merged = ports
            existing.ports = merged

    return list(combined.values())


def _group_targets_by_ports(
    definitions: Sequence[TargetDefinition],
) -> Dict[Optional[Tuple[int, ...]], List[str]]:
    groups: Dict[Optional[Tuple[int, ...]], List[str]] = {}
    for definition in definitions:
        key: Optional[Tuple[int, ...]]
        if definition.ports:
            key = tuple(definition.ports)
        else:
            key = None
        groups.setdefault(key, []).append(definition.value)
    return groups


def _port_selection_from_ports(ports: Sequence[int]) -> PortSelection:
    unique = sorted(dict.fromkeys(int(port) for port in ports))
    port_list = ",".join(str(port) for port in unique)
    return PortSelection(
        description=f"ports {port_list}",
        masscan_args=["-p", port_list],
        nmap_args=["-p", port_list],
        smrib_args=["--ports", port_list],
        forced_ports=unique,
    )


def _merge_result_maps(
    destination: Dict[str, Set[int]],
    source: Mapping[str, Set[int]],
) -> None:
    for host, ports in source.items():
        destination.setdefault(host, set()).update(ports)


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

    MASSCAN_DIR.mkdir(parents=True, exist_ok=True)
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
    SMRIB_DIR.mkdir(parents=True, exist_ok=True)
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
    per_target_ports: Mapping[str, Sequence[int]],
) -> Dict[str, Set[int]]:
    # Consolidate discovery findings. Only ports confirmed during discovery will
    # be fingerprinted in the next stage.
    merged: Dict[str, Set[int]] = {}

    for result in (masscan_results, smrib_results, nmap_results):
        for ip, ports in result.items():
            merged.setdefault(ip, set()).update(ports)

    overrides: Dict[str, Set[int]] = {}
    for target, ports in per_target_ports.items():
        port_set = set(int(port) for port in ports)
        overrides[target] = set(sorted(port_set))

    if forced_ports:
        forced_sorted = sorted(dict.fromkeys(int(port) for port in forced_ports))
        forced_set = set(forced_sorted)
        for host in merged:
            if host not in overrides:
                overrides.setdefault(host, set()).update(forced_set)
        for target in targets:
            if target not in overrides:
                overrides.setdefault(target, set()).update(forced_set)

    if not merged:
        for target in targets:
            merged[target] = set()

    for target, ports in overrides.items():
        merged[target] = set(sorted(ports))

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
            "--script=default,banner",
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


def export_target_file(
    path: Path,
    targets: Sequence[TargetDefinition],
    discovered_hosts: Mapping[str, Set[int]],
    inventory: Sequence[Mapping[str, object]],
    domains: Iterable[str],
) -> None:
    """Persist consolidated targets with per-host ports for future runs."""

    entries: Dict[str, Set[int]] = {}

    for definition in targets:
        entry_ports = entries.setdefault(definition.value, set())
        if definition.ports:
            entry_ports.update(int(port) for port in definition.ports)

    for host, ports in discovered_hosts.items():
        entry_ports = entries.setdefault(host, set())
        entry_ports.update(int(port) for port in ports)

    for record in inventory:
        open_ports = record.get("open_ports", [])
        try:
            port_values = {int(port) for port in open_ports}
        except (TypeError, ValueError):
            port_values = set()

        ip_value = record.get("ip")
        if isinstance(ip_value, str) and ip_value:
            entries.setdefault(ip_value, set()).update(port_values)

        hostnames = record.get("hostnames", [])
        if isinstance(hostnames, list):
            for hostname in hostnames:
                if isinstance(hostname, str) and hostname:
                    entries.setdefault(hostname, set()).update(port_values)

    for domain in domains:
        if isinstance(domain, str) and domain:
            entries.setdefault(domain, set())

    sorted_targets = sorted(entries.items(), key=lambda item: item[0].lower())

    lines: List[str] = []
    for target, ports in sorted_targets:
        if ports:
            port_list = ",".join(str(port) for port in sorted(ports))
            lines.append(f"{target} {port_list}")
        else:
            lines.append(target)

    path.parent.mkdir(parents=True, exist_ok=True)
    content = "\n".join(lines)
    if content:
        content += "\n"
    path.write_text(content, encoding="utf-8")
    echo(f"[+] Exported {len(sorted_targets)} target(s) to {path}", essential=True)


def export_not_processed_targets(entries: Iterable[str]) -> None:
    values = sorted({entry.strip() for entry in entries if entry and entry.strip()})
    if values:
        with TARGETS_NOT_PROCESSED_FILE.open("w", encoding="utf-8") as file:
            file.write("\n".join(values) + "\n")
        echo(
            f"[+] Logged {len(values)} target(s) ignored from OSINT in {TARGETS_NOT_PROCESSED_FILE}",
            essential=True,
        )
    elif TARGETS_NOT_PROCESSED_FILE.exists():
        TARGETS_NOT_PROCESSED_FILE.unlink()


def _normalise_target(value: str) -> str:
    """Return a consistent identifier for tracking processed targets."""

    return value.strip().lower()


def _normalise_ip(value: Optional[str]) -> Optional[str]:
    """Return a canonical representation of *value* when it is an IP address."""

    if not value:
        return None

    candidate = value.strip()
    if not candidate:
        return None

    try:
        return str(ipaddress.ip_address(candidate))
    except ValueError:
        return None


def _validate_osint_host_ip_uniqueness(
    results: Mapping[str, aggregate.HarvesterDomainResult]
) -> None:
    """Ensure theHarvester host/IP tuples are unique before further enrichment."""

    seen_pairs: Set[Tuple[str, str]] = set()
    ip_to_host: Dict[str, str] = {}
    duplicate_pairs: List[str] = []
    conflicting_ips: List[str] = []

    for domain_result in results.values():
        for finding in domain_result.findings:
            host_key = _normalise_target(finding.hostname)
            ip_normalised = _normalise_ip(finding.ip)
            if not host_key or not ip_normalised:
                continue

            pair = (host_key, ip_normalised)
            if pair in seen_pairs:
                duplicate_pairs.append(f"{finding.hostname} → {ip_normalised}")
                continue

            seen_pairs.add(pair)
            existing_host = ip_to_host.setdefault(ip_normalised, host_key)
            if existing_host != host_key:
                conflicting_ips.append(
                    f"{ip_normalised} assigned to {existing_host} and {host_key}"
                )

    if not duplicate_pairs and not conflicting_ips:
        return

    problems: List[str] = []
    if duplicate_pairs:
        problems.append(
            "duplicate host/IP tuples detected: " + ", ".join(sorted(duplicate_pairs))
        )
    if conflicting_ips:
        problems.append(
            "conflicting IP assignments detected: " + ", ".join(sorted(conflicting_ips))
        )

    details = " | ".join(problems)
    raise SystemExit(f"[!] OSINT validation failed – {details}")


def _registered_domain(candidate: str) -> Optional[str]:
    """Return the registrable domain component of *candidate* if possible."""

    if not candidate:
        return None

    candidate = candidate.strip().lower()
    if not candidate:
        return None

    try:
        ipaddress.ip_address(candidate)
        return None
    except ValueError:
        pass

    parts = [part for part in candidate.split(".") if part]
    if len(parts) < 2:
        return None
    return ".".join(parts[-2:])


def _domain_is_permitted(candidate: str, permitted: Set[str]) -> bool:
    """Return ``True`` when *candidate* belongs to one of the permitted domains."""

    if not permitted:
        return False

    registrable = _registered_domain(candidate)
    if not registrable:
        return False

    return registrable.lower() in permitted


def extract_domains_from_nmap() -> Set[str]:
    # Parse the Nmap XML output to collect second-level domains that can be fed
    # into theHarvester for OSINT enrichment.
    results = aggregate.parse_nmap_dir(str(NMAP_DIR))
    domains: Set[str] = set()
    for data in results.values():
        for hostname in data.get("hostnames", []):
            domain = _registered_domain(hostname)
            if domain:
                domains.add(domain)
    return domains


def _extract_registered_domains_from_hosts(hosts: Iterable[str]) -> Set[str]:
    """Derive registrable domains from an iterable of hostnames."""

    domains: Set[str] = set()
    for host in hosts:
        domain = _registered_domain(host)
        if domain:
            domains.add(domain)
    return domains


def extract_domains_from_targets(targets: Iterable[str]) -> Set[str]:
    """Derive registrable domains directly from the requested *targets*."""

    domains: Set[str] = set()
    for target in targets:
        domain = _registered_domain(target)
        if domain:
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


def _resolve_related_targets(candidates: Iterable[str]) -> List[str]:
    """Filter and de-duplicate hostnames/IPs extracted from OSINT tools."""

    resolved: List[str] = []
    seen: Set[str] = set()
    for candidate in candidates:
        cleaned = candidate.strip()
        if not cleaned:
            continue
        normalised = _normalise_target(cleaned)
        if normalised in seen:
            continue
        seen.add(normalised)
        resolved.append(cleaned)
    return resolved


def aggregate_results() -> None:
    # Invoke the aggregation helper to merge outputs from every stage into the
    # consolidated inventory artefacts.
    REPORT_DIR.mkdir(parents=True, exist_ok=True)
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


def display_inventory_contents() -> None:
    """Print the contents of the aggregated inventory for quick inspection."""

    if not INVENTORY_JSON.exists():
        echo("[!] inventory.json not found – nothing to display.", essential=True)
        return

    try:
        raw = INVENTORY_JSON.read_text(encoding="utf-8")
        parsed = json.loads(raw)
    except OSError as exc:
        echo(f"[!] Failed to read {INVENTORY_JSON}: {exc}", essential=True)
        return
    except json.JSONDecodeError as exc:
        echo(
            f"[!] {INVENTORY_JSON} is not valid JSON (line {exc.lineno}, column {exc.colno}).",
            essential=True,
        )
        return

    echo(f"[+] Final inventory from {INVENTORY_JSON}:", essential=True)

    hosts: List[Mapping[str, object]]
    harvester_domains: Sequence[Mapping[str, object]] = []

    if isinstance(parsed, dict):
        raw_hosts = parsed.get("hosts")
        if isinstance(raw_hosts, list):
            hosts = raw_hosts
        else:
            echo("    Inventory format unexpected – missing 'hosts' list.", essential=True)
            return
        domains_section = parsed.get("harvester_domains")
        if isinstance(domains_section, list):
            harvester_domains = domains_section
    elif isinstance(parsed, list):
        hosts = parsed
    else:
        echo("    Inventory format unexpected – unrecognised structure.", essential=True)
        pretty = json.dumps(parsed, indent=2, sort_keys=True)
        for line in pretty.splitlines():
            echo(f"    {line}", essential=True)
        return

    if not hosts:
        echo("    (Inventory empty)", essential=True)
        return

    for host in hosts:
        if not isinstance(host, dict):
            continue
        ip = host.get("ip", "unknown")
        echo(f"    Host: {ip}", essential=True)
        hostnames = host.get("hostnames") or []
        if hostnames:
            echo(f"      Hostnames: {', '.join(hostnames)}", essential=True)
        os_guess = host.get("os") or "Unknown"
        accuracy = host.get("os_accuracy")
        if accuracy:
            echo(f"      Probable OS: {os_guess} (confidence {accuracy}%)", essential=True)
        else:
            echo(f"      Probable OS: {os_guess}", essential=True)
        open_ports = host.get("open_ports") or []
        if open_ports:
            ports = ", ".join(str(port) for port in open_ports)
            echo(f"      Open ports: {ports}", essential=True)
        services = host.get("services") or []
        if services:
            echo("      Services:", essential=True)
            for service in services:
                if not isinstance(service, dict):
                    continue
                port = service.get("port")
                name = service.get("service") or "unknown"
                version = service.get("version")
                tunnel = service.get("tunnel")
                banner = service.get("banner")
                cpes = service.get("cpe") or []
                scripts = service.get("scripts") or []
                line = f"        - Port {port}/{service.get('proto') or 'tcp'}: {name}"
                if tunnel:
                    line += f" ({tunnel})"
                if version:
                    line += f" – {version}"
                echo(line, essential=True)
                if banner:
                    echo(f"          Banner: {banner}", essential=True)
                if cpes:
                    echo(f"          CPE: {', '.join(cpes)}", essential=True)
                if scripts:
                    for script in scripts:
                        script_id = script.get("id", "script")
                        output = script.get("output")
                        if output:
                            echo(f"          {script_id}: {output}", essential=True)
        related = host.get("related_domains") or []
        if related:
            echo(f"      Related domains: {', '.join(related)}", essential=True)
        harvester_data = host.get("harvester")
        if isinstance(harvester_data, dict) and harvester_data:
            echo("      theHarvester:", essential=True)
            domains = harvester_data.get("domains") or []
            if domains:
                echo(f"        Domains: {', '.join(domains)}", essential=True)
            for key, values in sorted(harvester_data.items()):
                if key == "domains":
                    continue
                if not isinstance(values, list) or not values:
                    continue
                label = key.replace("_", " ").capitalize()
                echo(f"        {label}: {', '.join(values)}", essential=True)
        echo("", essential=True)

    if harvester_domains:
        echo("    theHarvester domain summaries:", essential=True)
        for summary in harvester_domains:
            if not isinstance(summary, Mapping):
                continue
            domain_label = summary.get("domain") or "unknown"
            echo(f"    Domain: {domain_label}", essential=True)
            hosts_list = summary.get("hosts") or []
            if hosts_list:
                echo(f"      Hosts: {', '.join(hosts_list)}", essential=True)
            ips_list = summary.get("ips") or []
            if ips_list:
                echo(f"      IPs: {', '.join(ips_list)}", essential=True)
            sections = summary.get("sections") or {}
            if isinstance(sections, Mapping):
                for key, values in sorted(sections.items()):
                    if not values:
                        continue
                    if isinstance(values, list):
                        label = key.replace("_", " ").capitalize()
                        echo(f"      {label}: {', '.join(values)}", essential=True)
            echo("", essential=True)


def collect_http_urls(inventory: List[Mapping[str, object]]) -> List[str]:
    # Walk the aggregated inventory and build a deduplicated list of HTTP(S)
    # endpoints that EyeWitness should visit.
    urls: Set[str] = set()
    hosts: Dict[str, List[Mapping[str, object]]] = {}

    for entry in inventory:
        ip = entry.get("ip")
        if not isinstance(ip, str):
            continue
        services = entry.get("services", []) or []
        hosts.setdefault(ip, []).extend(
            [service for service in services if isinstance(service, Mapping)]
        )

    for ip, services in hosts.items():
        ports = {service.get("port") for service in services if isinstance(service.get("port"), int)}
        for service in services:
            port = service.get("port") if isinstance(service.get("port"), int) else None
            name = (service.get("service") or "").lower()
            if port is None:
                continue

            if "http" not in name and port not in {80, 443, 8080, 8000, 8888, 8443, 9443}:
                continue

            scheme = "http"
            if port == 443 and 80 in ports:
                # Prefer HTTP on port 80 when both 80 and 443 are available.
                continue
            if "https" in name or port in {443, 8443, 9443}:
                scheme = "https"

            if port in {80, 443}:
                url = f"{scheme}://{ip}"
            else:
                url = f"{scheme}://{ip}:{port}"
            urls.add(url)

        # When 443 is the only standard web port exposed, ensure we still visit it.
        if ports == {443} and not any(url.startswith("https://") and url.endswith(ip) for url in urls):
            urls.add(f"https://{ip}")

    return sorted(urls)


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
        output_path = str(output_dir.resolve())
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
            output_path,
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
        if isinstance(data, dict):
            hosts = data.get("hosts")
            if isinstance(hosts, list):
                return hosts
    except json.JSONDecodeError:
        pass
    return []


def load_domain_summaries() -> List[Mapping[str, object]]:
    # Read the optional domain-level intelligence that the aggregator stores so
    # the Markdown report can present theHarvester findings in a structured
    # section. The helper returns an empty list when the JSON payload is missing
    # or cannot be parsed safely.
    if not INVENTORY_JSON.exists():
        return []

    try:
        payload = json.loads(INVENTORY_JSON.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return []

    if isinstance(payload, dict):
        raw_domains = payload.get("harvester_domains")
        if isinstance(raw_domains, list):
            return [entry for entry in raw_domains if isinstance(entry, dict)]

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
    lines.append("## Host and Domain Inventory")

    # Convert the discovery findings into a normalised lookup so that aliases
    # (IP address vs. hostname) map back to the same bucket of open ports.
    discovery_lookup: Dict[str, Set[int]] = {}
    for label, ports in discovered_hosts.items():
        if not label:
            continue
        normalised = _normalise_target(label)
        if not normalised:
            continue
        port_set: Set[int] = set()
        if ports:
            for port in ports:
                if port is None:
                    continue
                try:
                    port_set.add(int(port))
                except (TypeError, ValueError):
                    continue
        discovery_lookup[normalised] = port_set

    documented_aliases: Set[str] = set()

    if inventory:
        for entry in inventory:
            if not isinstance(entry, Mapping):
                continue

            ip = str(entry.get("ip") or "unknown")
            lines.append(f"### {ip}")

            aliases: Set[str] = {alias for alias in {ip} if alias}
            hostnames = [hostname for hostname in entry.get("hostnames", []) if hostname]
            aliases.update(hostnames)

            for alias in aliases:
                documented_aliases.add(_normalise_target(alias))

            hostname_text = ", ".join(hostnames) if hostnames else "-"
            lines.append(f"- **Hostnames**: {hostname_text}")

            open_ports = [
                int(port)
                for port in entry.get("open_ports", [])
                if isinstance(port, int) or (isinstance(port, str) and port.isdigit())
            ]
            open_text = ", ".join(str(port) for port in sorted(set(open_ports))) or "-"
            lines.append(f"- **Inventory open ports**: {open_text}")

            # Merge discovery results from all known aliases for the current host.
            discovery_ports: Set[int] = set()
            for alias in aliases:
                normalised = _normalise_target(alias)
                discovery_ports.update(discovery_lookup.get(normalised, set()))
            if discovery_ports:
                discovery_text = ", ".join(str(port) for port in sorted(discovery_ports))
            else:
                discovery_text = "not observed during discovery"
            lines.append(f"- **Discovery ports**: {discovery_text}")

            os_name = entry.get("os") or "Unknown"
            accuracy = entry.get("os_accuracy")
            if accuracy:
                lines.append(f"- **Operating system**: {os_name} (confidence {accuracy}%)")
            else:
                lines.append(f"- **Operating system**: {os_name}")

            related_domains = entry.get("related_domains", []) or []
            related_text = ", ".join(related_domains) if related_domains else "-"
            lines.append(f"- **Related domains**: {related_text}")

            services = entry.get("services") or []
            if services:
                lines.append("- **Services**:")
                for service in services:
                    if not isinstance(service, Mapping):
                        continue
                    port = service.get("port")
                    proto = service.get("proto") or "tcp"
                    name = service.get("service") or "unknown"
                    state = service.get("state") or "unknown"
                    product = service.get("product") or ""
                    version = service.get("version") or ""
                    summary_parts = []
                    if port is not None:
                        summary_parts.append(f"{port}/{proto}")
                    summary_parts.append(f"state={state}")
                    summary_parts.append(name)
                    if product:
                        summary_parts.append(product)
                    if version:
                        summary_parts.append(version)
                    if service.get("tunnel"):
                        summary_parts.append(f"tunnel={service['tunnel']}")
                    service_line = " – ".join(part for part in summary_parts if part)
                    lines.append(f"    - {service_line}")

                    extras: List[str] = []
                    banner = service.get("banner")
                    if banner:
                        extras.append(f"banner: {banner}")
                    cpes = service.get("cpe") or []
                    if cpes:
                        extras.append(f"cpes: {' | '.join(str(cpe) for cpe in cpes if cpe)}")
                    scripts = service.get("scripts") or []
                    for script in scripts:
                        if not isinstance(script, Mapping):
                            continue
                        script_id = script.get("id") or "script"
                        output = (script.get("output") or "").strip()
                        if output:
                            extras.append(f"script {script_id}: {output}")
                    for detail in extras:
                        lines.append(f"      - {detail}")

            harvester_data = entry.get("harvester")
            if isinstance(harvester_data, Mapping) and harvester_data:
                lines.append("- **OSINT excerpts**:")
                domains = harvester_data.get("domains") or []
                if domains:
                    lines.append(f"    - Domains: {', '.join(domains)}")
                for key, values in sorted(harvester_data.items()):
                    if key == "domains":
                        continue
                    if not isinstance(values, list) or not values:
                        continue
                    label = key.replace("_", " ").capitalize()
                    lines.append(f"    - {label}: {', '.join(values)}")

            lines.append("")
    else:
        lines.append("No aggregated inventory was generated.")

    # Highlight any discovery findings that did not make it into the inventory,
    # such as hosts that timed out during fingerprinting.
    discovery_only: List[Tuple[str, Set[int]]] = []
    for label, ports in discovered_hosts.items():
        normalised = _normalise_target(label)
        if normalised and normalised not in documented_aliases:
            port_candidates = ports or []
            port_set = {
                int(port)
                for port in port_candidates
                if isinstance(port, int)
                or (isinstance(port, str) and port.isdigit())
            }
            discovery_only.append((label, port_set))

    if discovery_only:
        lines.append("## Discovery-Only Hosts")
        for label, ports in sorted(discovery_only, key=lambda item: item[0].lower()):
            if ports:
                port_text = ", ".join(str(port) for port in sorted(ports))
            else:
                port_text = "no open ports confirmed"
            lines.append(f"- {label}: {port_text}")
        lines.append("")

    domain_summaries = load_domain_summaries()
    if domain_summaries:
        lines.append("## Domain Intelligence")
        for summary in domain_summaries:
            domain = summary.get("domain") or "unknown"
            lines.append(f"### {domain}")
            hosts = summary.get("hosts") or []
            if hosts:
                lines.append(f"- **Hosts**: {', '.join(hosts)}")
            ips = summary.get("ips") or []
            if ips:
                lines.append(f"- **IP addresses**: {', '.join(ips)}")
            sections = summary.get("sections")
            if isinstance(sections, Mapping):
                for key, values in sorted(sections.items()):
                    if not isinstance(values, list) or not values:
                        continue
                    label = key.replace("_", " ").capitalize()
                    lines.append(f"- **{label}**: {', '.join(values)}")
            lines.append("")

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

    REPORT_DIR.mkdir(parents=True, exist_ok=True)
    REPORT_PATH.write_text("\n".join(lines), encoding="utf-8")
    echo(f"[+] Wrote report to {REPORT_PATH}", essential=True)


def main(argv: Optional[Sequence[str]] = None) -> None:
    # Tie together all pipeline stages in the intended execution order.
    args = parse_args(argv)
    global _SILENT_MODE
    _SILENT_MODE = args.silent

    if not args.preserve_output:
        reset_output_tree()
    else:
        echo(
            "[!] Preserving existing output files – prior results may appear in the current run.",
            essential=True,
        )

    echo("[+] Starting reconnaissance workflow", essential=True)
    port_selection = build_port_selection(args)
    cli_targets = [_split_target_and_ports(entry) for entry in args.targets]
    file_targets: List[TargetDefinition] = []
    file_origin: Optional[Path] = None
    if args.targets_file:
        candidate = args.targets_file
        if not candidate.is_absolute():
            candidate = Path.cwd() / candidate
        file_origin = candidate.resolve(strict=False)
        file_targets = load_targets(file_origin, create_default=False)
    elif not cli_targets:
        file_origin = TARGETS_FILE
        file_targets = load_targets(file_origin, create_default=True)

    target_definitions = _merge_target_definitions(cli_targets + file_targets)

    if not target_definitions:
        raise SystemExit("No reconnaissance targets provided. Use --targets or --targets-file.")

    targets = [definition.value for definition in target_definitions]
    formatted_targets = [definition.formatted() for definition in target_definitions]
    per_target_ports: Dict[str, Sequence[int]] = {
        definition.value: definition.ports or []
        for definition in target_definitions
        if definition.ports
    }

    ip_host_assignments: Dict[str, str] = {}

    def _note_known_ip(label: str) -> None:
        normalised_ip = _normalise_ip(label)
        if normalised_ip and normalised_ip not in ip_host_assignments:
            ip_host_assignments[normalised_ip] = _normalise_target(label)

    for definition in target_definitions:
        _note_known_ip(definition.value)

    echo(f"[+] Loaded {len(targets)} target(s)", essential=True)
    echo("    Target list (in scanning order):", essential=True)
    for index, target in enumerate(formatted_targets, start=1):
        echo(f"      {index}. {target}", essential=True)

    if cli_targets and file_origin:
        echo(
            f"    Targets supplied via --targets and from {file_origin}.",
            essential=True,
        )
    elif cli_targets:
        echo("    Targets supplied directly via --targets.", essential=True)
    elif file_origin:
        echo(
            f"    Each entry originates from {file_origin}; edit that file to adjust the scope.",
            essential=True,
        )

    ensure_writable_directory(OUT_DIR)
    for path in (
        DISCOVERY_DIR,
        NMAP_DIR,
        HARVESTER_DIR,
        EYEWITNESS_DIR,
        MASSCAN_DIR,
        SMRIB_DIR,
        REPORT_DIR,
        LOG_DIR,
    ):
        ensure_writable_directory(path)
    echo("[+] Output directories verified", essential=True)

    scanner_label = SCANNER_LABELS.get(args.scanner, args.scanner)
    stage_one_summary = (
        f"Discovery scanning with {scanner_label} to identify responsive hosts and open ports."
    )
    echo_stage(1, "Discovery", summary=stage_one_summary)

    groups = _group_targets_by_ports(target_definitions)

    discovery_descriptions: List[str] = []
    masscan_results: Dict[str, Set[int]] = {}
    smrib_results: Dict[str, Set[int]] = {}
    nmap_results: Dict[str, Set[int]] = {}
    use_sudo = False

    for key, subset in groups.items():
        if not subset:
            continue
        if key is None:
            selection = port_selection
        else:
            selection = _port_selection_from_ports(list(key))
        if selection.description not in discovery_descriptions:
            discovery_descriptions.append(selection.description)

        if args.scanner == "masscan":
            results = run_masscan(
                subset,
                selection,
                args.masscan_rate,
                args.masscan_status_interval,
                use_sudo,
            )
            _merge_result_maps(masscan_results, results)
        elif args.scanner == "smrib":
            results = run_smrib(subset, selection, args.smrib_path, args.smrib_extra, use_sudo)
            _merge_result_maps(smrib_results, results)
        else:
            results = run_nmap_discovery(subset, selection, use_sudo)
            _merge_result_maps(nmap_results, results)

    if not discovery_descriptions:
        discovery_description = f"{args.scanner} (no targets)"
    elif len(discovery_descriptions) == 1:
        discovery_description = f"{args.scanner} ({discovery_descriptions[0]})"
    else:
        joined = "; ".join(discovery_descriptions)
        discovery_description = f"{args.scanner} ({joined})"

    discovered_hosts = merge_discovered_hosts(
        targets,
        masscan_results,
        smrib_results,
        nmap_results,
        port_selection.forced_ports,
        per_target_ports,
    )

    for label in discovered_hosts:
        _note_known_ip(label)

    display_discovered_hosts(discovered_hosts)

    actionable_hosts = sum(1 for ports in discovered_hosts.values() if ports)
    stage_two_summary = (
        "Nmap service and OS detection against "
        f"{actionable_hosts} host(s) with confirmed open ports."
    )
    echo_stage(2, "Fingerprinting", summary=stage_two_summary)

    run_nmap_fingerprinting(discovered_hosts, use_sudo)

    target_domains = extract_domains_from_targets(targets)
    permitted_domains = {domain.lower() for domain in target_domains}
    nmap_domains = extract_domains_from_nmap()

    # Only consider Nmap-discovered domains when they share a registrable
    # domain with the explicit targets. This prevents follow-up OSINT queries
    # against unrelated hosting providers that appear via reverse DNS.
    if permitted_domains:
        nmap_domains = {
            domain
            for domain in nmap_domains
            if _domain_is_permitted(domain, permitted_domains)
        }
        domains = set(target_domains)
        domains.update(nmap_domains)
    else:
        domains = set()
    all_domains: Set[str] = set(domains)

    stage_three_summary = (
        "Gathering OSINT with theHarvester for "
        f"{len(domains)} domain(s) linked to discovered assets."
    )
    echo_stage(3, "OSINT enrichment", summary=stage_three_summary)

    processed_domains: Set[str] = set()
    pending_domains: Set[str] = set()
    scanned_targets: Set[str] = {_normalise_target(target) for target in targets}
    for ip in discovered_hosts:
        scanned_targets.add(_normalise_target(ip))
    not_processed_related: Set[str] = set()

    if not domains:
        echo("[!] No domains discovered in Nmap XML – skipping theHarvester stage.", essential=True)
    else:
        pending_domains = set(domains)
        iteration = 0
        max_iterations = 3 if args.search_related_data else 1

        while pending_domains and iteration < max_iterations:
            iteration += 1
            iteration_label = (
                f"[+] theHarvester iteration {iteration}/{max_iterations} for domains: {', '.join(sorted(pending_domains))}"
            )
            echo(iteration_label, essential=True)
            run_harvester(sorted(pending_domains), args)
            processed_domains.update(domain.lower() for domain in pending_domains)

            if not args.search_related_data:
                break

            harvester_map = aggregate.parse_harvester_dir(str(HARVESTER_DIR))
            all_domains.update(
                domain
                for domain in harvester_map.keys()
                if _domain_is_permitted(domain, permitted_domains)
            )
            current_batch = {domain.lower() for domain in pending_domains}
            new_targets: Set[str] = set()
            related_domains: Set[str] = set()
            discovered_host_ip_tuple = False

            def _record_unprocessed(value: Optional[str]) -> None:
                if not value:
                    return
                cleaned = str(value).strip()
                if cleaned:
                    not_processed_related.add(cleaned)

            for domain_name, result in harvester_map.items():
                domain_lower = domain_name.lower()
                if domain_lower not in current_batch:
                    continue

                if not _domain_is_permitted(domain_lower, permitted_domains):
                    _record_unprocessed(domain_name)
                    for finding in result.findings:
                        _record_unprocessed(finding.hostname)
                        _record_unprocessed(finding.ip)
                    for section_values in result.sections.values():
                        for item in section_values:
                            _record_unprocessed(item)
                    continue

                normalised_domain = _normalise_target(domain_name)
                if normalised_domain not in scanned_targets:
                    new_targets.add(domain_name)

                for finding in result.findings:
                    candidate = finding.hostname
                    if not candidate:
                        continue

                    if finding.ip:
                        discovered_host_ip_tuple = True

                    if not _domain_is_permitted(candidate, permitted_domains):
                        _record_unprocessed(candidate)
                        if finding.ip:
                            _record_unprocessed(finding.ip)
                        continue

                    all_domains.add(candidate)

                    normalised_candidate = _normalise_target(candidate)
                    ip_conflict = False
                    ip_normalised = _normalise_ip(finding.ip)
                    if ip_normalised:
                        existing_host = ip_host_assignments.get(ip_normalised)
                        if existing_host and existing_host != normalised_candidate:
                            _record_unprocessed(candidate)
                            _record_unprocessed(finding.ip)
                            ip_conflict = True
                        else:
                            ip_host_assignments[ip_normalised] = normalised_candidate
                            scanned_targets.add(ip_normalised)

                    if ip_conflict:
                        continue

                    if normalised_candidate not in scanned_targets:
                        new_targets.add(candidate)

                    candidate_domain = _registered_domain(candidate)
                    if candidate_domain:
                        related_domains.add(candidate_domain.lower())

                for host_value in result.sections.get("hosts", []):
                    if _domain_is_permitted(host_value, permitted_domains):
                        all_domains.add(host_value)
                        normalised_host = _normalise_target(host_value)
                        if normalised_host not in scanned_targets:
                            new_targets.add(host_value)
                    else:
                        _record_unprocessed(host_value)

                for ip_value in result.sections.get("ips", []):
                    ip_normalised = _normalise_ip(ip_value)
                    if not ip_normalised:
                        continue
                    existing_host = ip_host_assignments.get(ip_normalised)
                    if existing_host and existing_host != normalised_domain:
                        _record_unprocessed(ip_value)
                        continue
                    ip_host_assignments[ip_normalised] = normalised_domain
                    scanned_targets.add(ip_normalised)

            if new_targets:
                resolved_targets = _resolve_related_targets(sorted(new_targets))
                echo(
                    f"[+] Fingerprinting {len(resolved_targets)} host(s) discovered via OSINT",
                    essential=True,
                )
                discovery_subset = run_nmap_discovery(resolved_targets, port_selection, use_sudo)
                for host, ports in discovery_subset.items():
                    discovered_hosts.setdefault(host, set()).update(ports)
                    _note_known_ip(host)
                display_discovered_hosts(discovery_subset)
                run_nmap_fingerprinting(discovery_subset, use_sudo)
                for candidate in resolved_targets:
                    scanned_targets.add(_normalise_target(candidate))
                for host in discovery_subset:
                    scanned_targets.add(_normalise_target(host))
            else:
                echo("[!] No new hosts from theHarvester results required fingerprinting.", essential=True)

            new_domain_candidates = {
                domain
                for domain in related_domains
                if domain not in processed_domains
                and _domain_is_permitted(domain, permitted_domains)
            }

            prospective_pending = {
                domain for domain in new_domain_candidates if domain not in processed_domains
            }

            if (
                args.search_related_data
                and iteration == 1
                and prospective_pending
                and new_targets
                and discovered_host_ip_tuple
            ):
                _validate_osint_host_ip_uniqueness(harvester_map)

            pending_domains = prospective_pending
            all_domains.update(new_domain_candidates)

            if not pending_domains:
                echo("[+] No additional domains discovered via OSINT – ending iterative search.", essential=True)

    export_not_processed_targets(not_processed_related)

    aggregate_results()

    inventory = load_inventory()
    echo(f"[+] Aggregated inventory entries: {len(inventory)}", essential=True)
    display_inventory_contents()
    urls = collect_http_urls(inventory)
    screenshots = run_eyewitness(urls, args)

    if args.targets_new_export:
        all_domains.update(processed_domains)
        all_domains.update(pending_domains)
        export_target_file(
            TARGETS_NEW_FILE,
            target_definitions,
            discovered_hosts,
            inventory,
            all_domains,
        )

    write_report(args, formatted_targets, discovery_description, discovered_hosts, screenshots)

    echo(
        f"[+] Recon workflow completed. Inventory: {INVENTORY_JSON}, CSV: {INVENTORY_CSV}",
        essential=True,
    )
    echo(f"[+] Full console output recorded in {LOG_PATH}", essential=True)


if __name__ == "__main__":
    main()
