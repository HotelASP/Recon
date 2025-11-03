#!/usr/bin/env python3
# Orchestrate a three-stage reconnaissance workflow that chains together
# discovery, service fingerprinting, and OSINT enrichment. The execution flow
# is intentionally verbose to make the automation steps clear:
#
# 1. Discovery scan – execute ``smrib.py`` (default), Masscan, or Nmap against
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
# python3 run_recon.py --help
# python3 run_recon.py --targets-file targets.txt  --top-ports 200 --targets-new-export --search-related-data 
# python3 run_recon.py --scanner nmap --targets hotelasp.com --top-ports 200 --targets-new-export --harvester-sources 'crtsh, bing' --search-related-data
# python3 run_recon.py --scanner masscan --targets-file targets.txt --top-ports 200 --targets-new-export --harvester-sources 'crtsh, bing' --search-related-data
# sudo python3 run_recon.py --scanner smrib --targets-file targets.txt --port-range 1-65535 --targets-new-export --search-related-data --smrib-parameters --fast --shuffle
# sudo python3 run_recon.py --targets-file targets.txt --port-range 1-65535 --targets-new-export --search-related-data 
# python3 run_recon.py --scanner nmap --targets-file targets.txt --port-range 1-1024 --targets-new-export --search-related-data
#

from __future__ import annotations

import argparse
import atexit
import http.client
import io
import ipaddress
import json
import os
import re
import shlex
import shutil
import socket
import ssl
import subprocess
import sys
import tempfile
import zipfile
from pprint import pformat
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, Iterable, List, Mapping, Optional, Sequence, Set, TextIO, Tuple, Union
from urllib.error import HTTPError, URLError
from urllib.parse import quote as urlquote
from urllib.request import Request, urlopen

from tools import aggregate
from tools.ownership import ensure_path_owner, ensure_tree_owner


ROOT = Path(__file__).resolve().parent
SCANNER_DIR = ROOT / "scanner"
OUT_DIR = ROOT / "out"
DISCOVERY_DIR = OUT_DIR / "discovery"
NMAP_DIR = OUT_DIR / "nmap"
NIKTO_DIR = OUT_DIR / "nikto"
HARVESTER_DIR = OUT_DIR / "harvester"
EYEWITNESS_DIR = OUT_DIR / "eyewitness"
MASSCAN_DIR = OUT_DIR / "masscan"
SMRIB_DIR = OUT_DIR / "smrib"
REPORT_DIR = OUT_DIR / "report"
DNS_ENUM_DIR = OUT_DIR / "dns"
BANNER_DIR = OUT_DIR / "banners"
WHOIS_DIR = OUT_DIR / "whois"
CT_DIR = OUT_DIR / "certificate_transparency"
SHODAN_DIR = OUT_DIR / "shodan"
MAC_DIR = OUT_DIR / "mac"
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

DEFAULT_HARVESTER_SOURCES: Tuple[str, ...] = ("all",)

SCANNER_REPO_URLS = (
    "https://github.com/HotelASP/Scanner/archive/refs/heads/main.zip",
    "https://github.com/HotelASP/Scanner/archive/refs/heads/master.zip",
)
DEFAULT_SMRIB_PATH = str(SCANNER_DIR / "smrib.py")


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
    "Nikto": (
        "Nikto complements service discovery by probing HTTP services for "
        "common misconfigurations, dangerous files, and known vulnerabilities, "
        "adding contextual risk data to web-facing hosts."
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


def _run_git_command(*args: str) -> Optional[str]:
    # Execute a git command relative to the repository root, returning the
    # stripped stdout when successful. The helper hides errors so the caller can
    # fall back gracefully when git is unavailable or the repo lacks the
    # requested refs.

    try:
        result = subprocess.run(
            ["git", "-C", str(ROOT), *args],
            check=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )
    except (FileNotFoundError, subprocess.CalledProcessError):
        return None

    output = result.stdout.strip()
    return output or None


def _format_git_version_message() -> Optional[str]:
    # Build a concise summary of the local and upstream git revisions so the
    # operator can easily identify which code versions are in play.

    local_commit = _run_git_command("rev-parse", "--short", "HEAD")
    if not local_commit:
        return None

    branch_name = _run_git_command("rev-parse", "--abbrev-ref", "HEAD")
    branch_label = branch_name if branch_name and branch_name != "HEAD" else None

    upstream_ref = _run_git_command("rev-parse", "--abbrev-ref", "--symbolic-full-name", "@{u}")
    upstream_commit = None
    if upstream_ref:
        upstream_commit = _run_git_command("rev-parse", "--short", "@{u}")

    if upstream_ref and upstream_commit:
        remote_text = f"remote {upstream_ref} @ {upstream_commit}"
    else:
        remote_text = "remote version unavailable"

    if branch_label:
        local_text = f"{branch_label} @ {local_commit}"
    else:
        local_text = local_commit

    return f"[+] Git version – local {local_text}; {remote_text}"


def _parse_boolean_option(value: Union[str, bool]) -> bool:
    # Interpret common truthy/falsey strings for command-line flags that
    # explicitly accept yes/no style values.
    if isinstance(value, bool):
        return value

    cleaned = str(value).strip().lower()
    if cleaned in {"1", "true", "yes", "on"}:
        return True
    if cleaned in {"0", "false", "no", "off"}:
        return False
    raise argparse.ArgumentTypeError(f"Expected a true/false value, got: {value}")


def _remove_path(path: Path) -> None:
    # Delete a file or directory while ignoring missing-path errors so previous
    # runs do not block a new execution.

    try:
        if not path.exists():
            return
        if path.is_file() or path.is_symlink():
            path.unlink()
        else:
            shutil.rmtree(path)
    except FileNotFoundError:
        return


def _ensure_directory(path: Path) -> None:
    # Create the provided directory (and parents) and normalise ownership so
    # follow-up stages can safely write artefacts.

    path.mkdir(parents=True, exist_ok=True)
    ensure_path_owner(path, parents=True)


def reset_output_tree() -> None:
    # Clear artefacts from previous runs to avoid cross-run contamination when
    # the operator has not requested ``--preserve-output``. Removing the entire
    # ``out`` directory guarantees no stale files linger from earlier
    # executions, even if a new tool creates previously unknown subdirectories
    # or artefacts.

    _remove_path(OUT_DIR)

    for artefact in (
        TARGETS_NOT_PROCESSED_FILE,
        MASSCAN_JSON,
        SMRIB_JSON,
        INVENTORY_JSON,
        INVENTORY_CSV,
        REPORT_PATH,
        LOG_PATH,
    ):
        _remove_path(artefact)


def _ensure_log_file() -> TextIO:
    # Return an open handle to the workflow log file, creating it on demand and
    # stamping it with a clear start marker.

    global _LOG_FILE
    if _LOG_FILE is None:
        _ensure_directory(LOG_DIR)
        timestamp = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S %Z")
        _LOG_FILE = LOG_PATH.open("w", encoding="utf-8")
        _LOG_FILE.write("=" * 72 + "\n")
        _LOG_FILE.write(f"Reconnaissance run started {timestamp}\n")
        _LOG_FILE.write("=" * 72 + "\n")
        _LOG_FILE.flush()
        ensure_path_owner(LOG_PATH)
    return _LOG_FILE


def _close_log_file() -> None:
    # Close the log file when the interpreter exits to avoid leaving handles
    # dangling on disk.

    global _LOG_FILE
    if _LOG_FILE is not None:
        _LOG_FILE.close()
        _LOG_FILE = None


atexit.register(_close_log_file)


def _log_message(message: str) -> None:
    # Append a formatted message to the log file, ensuring newline handling is
    # consistent across callers.

    handle = _ensure_log_file()
    if message.endswith("\n"):
        handle.write(message)
    else:
        handle.write(f"{message}\n")
    handle.flush()


def _log_stream_output(text: str) -> None:
    # Record raw subprocess output in the log file without altering whitespace
    # so troubleshooting remains accurate.

    handle = _ensure_log_file()
    handle.write(text)
    if not text.endswith("\n"):
        handle.write("\n")
    handle.flush()


def echo(message: str, *, essential: bool = False) -> None:
    # Print a message unless running in silent mode while always logging it to
    # the recon log for later review.

    _log_message(message)
    if not _SILENT_MODE or essential or message.startswith("[!]"):
        print(message)


def _summarize_port_sequence(ports: Sequence[int]) -> Optional[str]:
    # Generate a compact range-based representation of port lists so stages
    # with many contiguous ports don't flood the console with dozens of lines.

    if not ports:
        return None

    if not all(isinstance(port, int) for port in ports):
        return None

    sorted_ports = sorted(ports)
    ranges = []
    start = previous = sorted_ports[0]

    for port in sorted_ports[1:]:
        if port == previous + 1:
            previous = port
            continue

        ranges.append((start, previous))
        start = previous = port

    ranges.append((start, previous))

    range_strings = []
    for start, end in ranges:
        if start == end:
            range_strings.append(str(start))
        else:
            range_strings.append(f"{start}-{end}")

    joined = ", ".join(range_strings)
    total = len(sorted_ports)
    return f"ports {joined} ({total} total)"


def _format_stage_input(entry: Tuple[object, ...]) -> str:
    # Provide readable, single-line descriptions for stage input tuples while
    # falling back to ``pformat`` for structures we don't recognize.

    if len(entry) == 2:
        target, ports = entry
        if isinstance(ports, Sequence) and not isinstance(ports, (str, bytes)):
            summary = _summarize_port_sequence(ports)
            if summary is not None:
                return f"({target!r}, {summary})"

    return pformat(entry, width=120, compact=True)


def pretty_print_stage_inputs(
    stage_label: str, entries: Iterable[Tuple[object, ...]]
) -> None:
    # Pretty print the tuples that will be fed into a pipeline stage so the
    # operator knows which targets and port strategies are grouped together.

    items = list(entries)
    echo(f"[+] {stage_label} input tuples:", essential=True)
    if not items:
        echo("    (no inputs)", essential=True)
        return

    for entry in items:
        formatted = _format_stage_input(entry)
        for line in formatted.splitlines():
            echo(f"    {line}", essential=True)


def echo_stage(stage_number: int, title: str, *, summary: Optional[str] = None) -> None:
    # Emit a prominent stage heading so operators can follow progress through
    # the workflow and understand the current objective.

    header = f"[+] STAGE {stage_number}: {title}"
    border = "=" * max(len(header), 32)
    echo("", essential=True)
    echo(border, essential=True)
    echo(header, essential=True)
    if summary:
        echo(f"    {summary}", essential=True)
    echo(border, essential=True)


def warn_privileges(tool: str, use_sudo: bool) -> None:
    # Warn once when a scanner is likely to require elevated privileges,
    # reminding the operator they may need to rerun with ``--sudo``.

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
    # Ensure that the provided directory exists and is writable, giving clear
    # errors when a permissions issue would otherwise surface later.

    try:
        _ensure_directory(path)
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


def _download_scanner_archive(url: str) -> bytes:
    # Retrieve the zipped Scanner repository from GitHub and return the raw
    # bytes so they can be extracted into ``scanner/``.

    request = Request(url, headers={"User-Agent": "ReconScannerFetcher/1.0"})
    with urlopen(request) as response:
        return response.read()


def _extract_scanner_archive(archive_bytes: bytes, destination: Path) -> None:
    # Extract the downloaded Scanner repository into ``destination`` while
    # discarding the top-level folder created by GitHub archives.

    with zipfile.ZipFile(io.BytesIO(archive_bytes)) as archive:
        root_prefix: Optional[str] = None
        for member in archive.infolist():
            name = Path(member.filename)
            if not name.parts:
                continue

            if root_prefix is None:
                root_prefix = name.parts[0]

            if name.parts[0] != root_prefix:
                continue

            relative_parts = name.parts[1:]
            if not relative_parts:
                if member.is_dir():
                    destination.mkdir(parents=True, exist_ok=True)
                continue

            target_path = destination.joinpath(*relative_parts)
            if member.is_dir():
                target_path.mkdir(parents=True, exist_ok=True)
                continue

            target_path.parent.mkdir(parents=True, exist_ok=True)
            with archive.open(member) as source, target_path.open("wb") as handle:
                shutil.copyfileobj(source, handle)


def ensure_scanner_repository() -> bool:
    # Ensure the ``scanner`` directory contains the upstream Scanner project so
    # the bundled smrib.py is available. Returning ``False`` allows callers to
    # gracefully fall back to Nmap when GitHub cannot be reached.

    scanner_dir = SCANNER_DIR
    scanner_dir.mkdir(parents=True, exist_ok=True)

    smrib_path = scanner_dir / "smrib.py"
    data_dir = scanner_dir / "data"
    if smrib_path.is_file() and data_dir.is_dir():
        return True

    echo(
        "[!] Local scanner assets missing – downloading HotelASP/Scanner from GitHub.",
        essential=True,
    )

    _remove_path(scanner_dir)
    scanner_dir.mkdir(parents=True, exist_ok=True)

    last_error: Optional[Exception] = None
    for url in SCANNER_REPO_URLS:
        try:
            echo(f"[+] Fetching scanner repository archive from {url}", essential=True)
            archive_bytes = _download_scanner_archive(url)
            _extract_scanner_archive(archive_bytes, scanner_dir)
            break
        except (HTTPError, URLError, zipfile.BadZipFile, OSError) as exc:
            last_error = exc
            echo(
                f"[!] Failed to download Scanner repository from {url}: {exc}",
                essential=True,
            )
    else:
        echo(
            "[!] Unable to download the Scanner repository from GitHub after trying all fallbacks.",
            essential=True,
        )
        if last_error is not None:
            echo(f"    Last error: {last_error}", essential=True)
        return False

    if not smrib_path.is_file() or not data_dir.is_dir():
        echo(
            "[!] Downloaded Scanner repository is incomplete – smrib.py or the data directory is missing.",
            essential=True,
        )
        return False

    try:
        current_mode = smrib_path.stat().st_mode
        smrib_path.chmod(current_mode | 0o111)
    except OSError:
        pass

    ensure_tree_owner(scanner_dir)
    echo("[+] Scanner repository ready", essential=True)
    return True


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
        add_help=False,
        description=(
            "Run the reconnaissance workflow: discovery (masscan/smrib/nmap) → "
            "detailed Nmap fingerprinting → theHarvester → aggregation."
        ),
    )
    parser.add_argument(
        "-h",
        "--help",
        "--?",
        action="help",
        help="Show this help message and exit.",
    )
    parser.add_argument(
        "--scanner",
        choices=("masscan", "smrib", "nmap"),
        default="smrib",
        help="Scanner to use for the discovery stage (default: smrib).",
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
        "--nmap-max-retries",
        type=int,
        help=(
            "Set Nmap's --max-retries value for both discovery and fingerprinting "
            "stages."
        ),
    )
    parser.add_argument(
        "--nmap-host-timeout",
        help=(
            "Apply an overall --host-timeout value to Nmap discovery and "
            "fingerprinting scans."
        ),
    )
    parser.add_argument(
        "--nmap-min-rate",
        type=int,
        help="Set Nmap's --min-rate to control the minimum packet rate.",
    )
    parser.add_argument(
        "--nmap-max-rate",
        type=int,
        help="Set Nmap's --max-rate to cap the packet rate during scans.",
    )
    parser.add_argument(
        "--nmap-scan-delay",
        help=(
            "Provide a value for Nmap's --scan-delay option to space probe "
            "packets."
        ),
    )
    parser.add_argument(
        "--smrib-path",
        default=os.environ.get("SMRIB_PATH", DEFAULT_SMRIB_PATH),
        help="Location of smrib.py when using the smrib discovery option.",
    )
    parser.add_argument(
        "--smrib-parameters",
        action="append",
        metavar="ARG",
        help=(
            "Additional arguments to forward to smrib.py after the defaults. "
            "Values that begin with a dash do not need special quoting."
        ),
    )
    parser.add_argument(
        "--harvester-sources",
        default=",".join(DEFAULT_HARVESTER_SOURCES),
        help=(
            "Comma separated sources for theHarvester. Defaults to `all` to "
            "query every available backend while relying on -quiet to suppress "
            "API warning noise."
        ),
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
        default=200,
        help="Result limit for theHarvester queries (default: 200).",
    )
    parser.add_argument(
        "--stage2-use-nmap",
        "-stage2-use-nmap",
        dest="stage2_use_nmap",
        type=_parse_boolean_option,
        metavar="BOOL",
        help="Enable or disable Nmap during stage 2 fingerprinting (default: true).",
    )
    parser.add_argument(
        "--stage2-use-nikto",
        "-stage2-use-nikto",
        dest="stage2_use_nikto",
        type=_parse_boolean_option,
        metavar="BOOL",
        help="Enable or disable Nikto during stage 2 fingerprinting (default: true).",
    )
    parser.add_argument(
        "--stage3-dns",
        "-stage3-dns",
        dest="stage3_dns",
        type=_parse_boolean_option,
        metavar="BOOL",
        help="Enable or disable DNS enumeration during stage 3 (default: true).",
    )
    parser.add_argument(
        "--stage3-banners",
        "-stage3-banners",
        dest="stage3_banners",
        type=_parse_boolean_option,
        metavar="BOOL",
        help="Enable or disable banner grabbing during stage 3 (default: true).",
    )
    parser.add_argument(
        "--stage3-whois",
        "-stage3-whois",
        dest="stage3_whois",
        type=_parse_boolean_option,
        metavar="BOOL",
        help="Enable or disable WHOIS lookups during stage 3 (default: true).",
    )
    parser.add_argument(
        "--stage3-ct",
        "-stage3-ct",
        dest="stage3_ct",
        type=_parse_boolean_option,
        metavar="BOOL",
        help="Enable or disable certificate transparency lookups during stage 3 (default: true).",
    )
    parser.add_argument(
        "--stage3-shodan",
        "-stage3-shodan",
        dest="stage3_shodan",
        type=_parse_boolean_option,
        metavar="BOOL",
        help="Enable or disable Shodan lookups during stage 3 (default: true).",
    )
    parser.add_argument(
        "--stage3-mac",
        "-stage3-mac",
        "--stage3-search-mac",
        "--search-mac",
        dest="stage3_mac",
        nargs="?",
        const="true",
        type=_parse_boolean_option,
        metavar="BOOL",
        help="Enable or disable MAC address enrichment during stage 3 (default: true).",
    )
    parser.add_argument(
        "--stage3-harvester",
        "-stage3-harvester",
        dest="stage3_harvester",
        type=_parse_boolean_option,
        metavar="BOOL",
        help="Enable or disable theHarvester during stage 3 (default: true).",
    )
    parser.add_argument(
        "--shodan-api-key",
        default=os.environ.get("SHODAN_API_KEY"),
        help="API key used for Shodan lookups during stage 3 (defaults to SHODAN_API_KEY env var).",
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
        "--show-inventory",
        action="store_true",
        help="Display the aggregated inventory.json contents when the run completes.",
    )
    parser.add_argument(
        "--show-eyewitness",
        action="store_true",
        help="Open EyeWitness HTML reports in Firefox after capture.",
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
        "--sudo",
        action="store_true",
        help="Prefix scanner commands with sudo when the binary is available.",
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

    if argv is None:
        argv_list = sys.argv[1:]
    else:
        argv_list = list(argv)

    option_strings = set(parser._option_string_actions)
    normalised: List[str] = []
    index = 0

    while index < len(argv_list):
        token = argv_list[index]

        if token == "--smrib-parameters":
            index += 1
            collected: List[str] = []

            while index < len(argv_list):
                candidate = argv_list[index]

                if candidate == "--":
                    index += 1
                    collected.extend(argv_list[index:])
                    index = len(argv_list)
                    break

                if candidate.startswith("-"):
                    option_key = candidate.split("=", 1)[0]
                    if option_key in option_strings:
                        break

                collected.append(candidate)
                index += 1

            if not collected:
                raise SystemExit("--smrib-parameters requires at least one argument")

            normalised.extend(f"{token}={value}" for value in collected)
            continue

        normalised.append(token)
        index += 1

    args = parser.parse_args(normalised)

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
        seen_sources: Set[str] = set()
        for entry in args.harvester_source:
            for part in entry.split(","):
                cleaned = part.strip()
                if cleaned:
                    lowered = cleaned.lower()
                    if lowered in seen_sources:
                        continue
                    seen_sources.add(lowered)
                    sources.append(cleaned)

        if not sources:
            raise SystemExit("--harvester-source requires at least one source name")

        args.harvester_sources = ",".join(sources)

    if args.nmap_max_retries is not None and args.nmap_max_retries < 0:
        raise SystemExit("--nmap-max-retries must be zero or a positive integer")

    if args.nmap_min_rate is not None and args.nmap_min_rate <= 0:
        raise SystemExit("--nmap-min-rate must be a positive integer")

    if args.nmap_max_rate is not None and args.nmap_max_rate <= 0:
        raise SystemExit("--nmap-max-rate must be a positive integer")

    if (
        args.nmap_min_rate is not None
        and args.nmap_max_rate is not None
        and args.nmap_min_rate > args.nmap_max_rate
    ):
        raise SystemExit("--nmap-min-rate cannot exceed --nmap-max-rate")

    if args.smrib_parameters:
        extras: List[str] = []
        for entry in args.smrib_parameters:
            if isinstance(entry, str):
                extras.extend(shlex.split(entry))
            else:
                extras.extend(entry)
        args.smrib_parameters = extras or None

    if args.stage2_use_nmap is None and args.stage2_use_nikto is None:
        args.stage2_use_nmap = True
        args.stage2_use_nikto = True
    else:
        if args.stage2_use_nmap is None:
            args.stage2_use_nmap = True
        if args.stage2_use_nikto is None:
            args.stage2_use_nikto = True

    if args.stage3_dns is None:
        args.stage3_dns = True
    if args.stage3_banners is None:
        args.stage3_banners = True
    if args.stage3_whois is None:
        args.stage3_whois = True
    if args.stage3_ct is None:
        args.stage3_ct = True
    if args.stage3_shodan is None:
        args.stage3_shodan = True
    if args.stage3_mac is None:
        args.stage3_mac = True
    if args.stage3_harvester is None:
        args.stage3_harvester = True

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
        tokens: List[str] = []
        for entry in args.ports.split(","):
            part = entry.strip()
            if not part:
                continue

            range_match = re.fullmatch(r"(\d+)\s*-\s*(\d+)", part)
            if range_match:
                start = int(range_match.group(1))
                end = int(range_match.group(2))
                if not 1 <= start <= 65535 or not 1 <= end <= 65535:
                    raise SystemExit("--ports values must be between 1 and 65535")
                if end < start:
                    raise SystemExit("--ports ranges must have an end greater than or equal to the start")
                tokens.append(f"{start}-{end}" if start != end else str(start))
                continue

            if not part.isdigit():
                raise SystemExit(
                    "--ports must contain only integers, ranges, and commas"
                )

            value = int(part)
            if not 1 <= value <= 65535:
                raise SystemExit("--ports values must be between 1 and 65535")
            tokens.append(str(value))

        if not tokens:
            raise SystemExit("--ports requires at least one port number")

        normalised_tokens: List[str] = []
        seen_tokens: Set[str] = set()
        for token in tokens:
            if token not in seen_tokens:
                normalised_tokens.append(token)
                seen_tokens.add(token)

        port_spec = ",".join(normalised_tokens)
        return PortSelection(
            description=f"ports {port_spec}",
            masscan_args=["-p", port_spec],
            nmap_args=["-p", port_spec],
            smrib_args=["--ports", port_spec],
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


def build_nmap_tuning_args(args: argparse.Namespace) -> List[str]:
    """Translate CLI tuning options into Nmap command arguments."""

    tuning: List[str] = []

    if args.nmap_max_retries is not None:
        tuning.extend(["--max-retries", str(args.nmap_max_retries)])

    if args.nmap_host_timeout:
        tuning.extend(["--host-timeout", args.nmap_host_timeout])

    if args.nmap_min_rate is not None:
        tuning.extend(["--min-rate", str(args.nmap_min_rate)])

    if args.nmap_max_rate is not None:
        tuning.extend(["--max-rate", str(args.nmap_max_rate)])

    if args.nmap_scan_delay:
        tuning.extend(["--scan-delay", args.nmap_scan_delay])

    return tuning


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
        ensure_path_owner(path, parents=True)
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
    # Create a high-contrast banner that highlights the running tool and makes
    # stage transitions obvious in the terminal output.

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


def resolve_masscan_targets(targets: Sequence[str]) -> List[str]:
    """Resolve Masscan targets to IPv4 addresses while preserving raw inputs."""

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
            echo(
                f"[!] No IPv4 addresses resolved for '{target}' – skipping Masscan entry.",
                essential=True,
            )
            continue

        resolved_targets.extend(sorted(ipv4_addresses))

    return resolved_targets


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

    resolved_targets = resolve_masscan_targets(targets)

    if not resolved_targets:
        echo("[!] No valid targets available for Masscan – skipping discovery stage.", essential=True)
        return {}

    warn_privileges("masscan", use_sudo)

    _ensure_directory(MASSCAN_DIR)
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
    ensure_tree_owner(MASSCAN_DIR)
    if not success:
        return {}

    results = aggregate.parse_masscan_json(str(MASSCAN_JSON))
    return {ip: set(data.get("masscan_ports", [])) for ip, data in results.items()}


def run_smrib(
    targets: Sequence[str],
    port_selection: PortSelection,
    smrib_path: str,
    parameters: Optional[Sequence[str]],
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
    _ensure_directory(SMRIB_DIR)
    cmd.extend(["--json", str(SMRIB_JSON)])
    cmd.extend(["--targets", ",".join(targets)])
    cmd.append("--show-only-open")
    if parameters:
        cmd.extend(parameters)

    description = (
        "smrib discovery – Python-based scanner performing targeted TCP probes "
        f"across {port_selection.description}"
    )
    success = run_command(prefix_command(cmd, use_sudo), description=description)
    ensure_tree_owner(SMRIB_DIR)
    if not success:
        return {}

    results = aggregate.parse_smrib_json(str(SMRIB_JSON))
    return {ip: set(data.get("smrib_ports", [])) for ip, data in results.items()}


def run_nmap_discovery(
    targets: Sequence[str],
    port_selection: PortSelection,
    use_sudo: bool,
    tuning_args: Sequence[str] = (),
) -> Mapping[str, Set[int]]:
    # Use Nmap for the discovery phase when Masscan or smrib.py are not
    # requested, saving greppable output per target for later parsing.
    if not shutil.which("nmap"):
        echo("[!] nmap not installed – unable to perform discovery stage.", essential=True)
        return {}

    warn_privileges("nmap", use_sudo)

    _ensure_directory(DISCOVERY_DIR)
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
        if tuning_args:
            cmd.extend(tuning_args)
        cmd.append(target)
        port_summary = port_selection.description
        description = (
            f"Nmap discovery for {target} – TCP connect/SYN sweep focusing on {port_summary}"
        )
        run_command(prefix_command(cmd, use_sudo), description=description)
        ensure_tree_owner(DISCOVERY_DIR)

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
    # Print a concise summary of discovered hosts and their ports so operators
    # can quickly validate discovery progress.

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
    tuning_args: Sequence[str] = (),
) -> None:
    # Perform comprehensive service detection with Nmap using only the
    # host/port combinations identified during discovery.
    if not shutil.which("nmap"):
        echo("[!] nmap is required for the fingerprinting stage; skipping.", essential=True)
        return

    warn_privileges("nmap", use_sudo)

    _ensure_directory(NMAP_DIR)
    actionable_hosts = {target: ports for target, ports in hosts.items() if ports}

    if not actionable_hosts:
        echo("[!] No open ports discovered during phase 1 – skipping fingerprinting stage.", essential=True)
        return

    for target, ports in actionable_hosts.items():
        sanitized = re.sub(r"[^0-9A-Za-z_.-]", "_", target)
        outbase = NMAP_DIR / sanitized
        cmd = [
            "nmap",
            "-sS",
            "-T4",
            "-sV",
            "-O",
            "--script=default,banner,vuln",
            "-oA",
            str(outbase),
        ]
        selected_ports = sorted(port for port in ports if port > 0)
        if selected_ports:
            port_arg = ",".join(str(port) for port in selected_ports)
            cmd.extend(["-p", port_arg])
            port_scope = (
                f"{len(selected_ports)} discovered port(s): "
                f"{', '.join(str(port) for port in selected_ports)}"
            )
        else:
            port_scope = "no discovered ports"
        if tuning_args:
            cmd.extend(tuning_args)
        cmd.append(target)
        description = (
            f"Nmap fingerprinting for {target} – SYN scan with default, banner, and vuln scripts "
            f"plus version and OS detection (based on {port_scope})"
        )
        run_command(prefix_command(cmd, use_sudo), description=description)
        ensure_tree_owner(NMAP_DIR)


def run_nikto_scans(
    hosts: Mapping[str, Set[int]],
    use_sudo: bool,
) -> None:
    # Execute Nikto against each discovered host/port pair to surface HTTP
    # vulnerabilities and misconfigurations.
    nikto_path = shutil.which("nikto")
    if not nikto_path:
        echo("[!] nikto not installed – skipping Nikto fingerprinting stage.", essential=True)
        return

    _ensure_directory(NIKTO_DIR)
    actionable_hosts = {target: ports for target, ports in hosts.items() if ports}

    if not actionable_hosts:
        echo(
            "[!] No open ports discovered during phase 1 – skipping Nikto fingerprinting stage.",
            essential=True,
        )
        return

    https_ports = {443, 8443, 9443}

    for target, ports in actionable_hosts.items():
        sanitized = re.sub(r"[^0-9A-Za-z_.-]", "_", target)
        for port in sorted(ports):
            if port <= 0:
                continue
            prefix = NIKTO_DIR / f"{sanitized}_{port}"
            output_path = f"{prefix}.json"
            cmd = [
                nikto_path,
                "-host",
                target,
                "-port",
                str(port),
                "-Format",
                "json",
                "-output",
                output_path,
            ]
            if port in https_ports:
                cmd.append("-ssl")
            description = (
                f"Nikto vulnerability scan for {target}:{port} – enumerating web service misconfigurations"
            )
            run_command(prefix_command(cmd, use_sudo), description=description)

    ensure_tree_owner(NIKTO_DIR)


def export_target_file(
    path: Path,
    targets: Sequence[TargetDefinition],
    discovered_hosts: Mapping[str, Set[int]],
    inventory: Sequence[Mapping[str, object]],
    domains: Iterable[str],
) -> None:
    # Persist consolidated targets with per-host ports for future runs,
    # mirroring the ``targets.txt`` syntax for continuity.

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

    _ensure_directory(path.parent)
    content = "\n".join(lines)
    if content:
        content += "\n"
    path.write_text(content, encoding="utf-8")
    ensure_path_owner(path)
    echo(f"[+] Exported {len(sorted_targets)} target(s) to {path}", essential=True)


def export_not_processed_targets(entries: Iterable[str]) -> None:
    values = sorted({entry.strip() for entry in entries if entry and entry.strip()})
    if values:
        with TARGETS_NOT_PROCESSED_FILE.open("w", encoding="utf-8") as file:
            file.write("\n".join(values) + "\n")
        ensure_path_owner(TARGETS_NOT_PROCESSED_FILE)
        echo(
            f"[+] Logged {len(values)} target(s) ignored from OSINT in {TARGETS_NOT_PROCESSED_FILE}",
            essential=True,
        )
    elif TARGETS_NOT_PROCESSED_FILE.exists():
        TARGETS_NOT_PROCESSED_FILE.unlink()


def _normalise_target(value: str) -> str:
    # Return a consistent identifier for tracking processed targets so merges
    # and comparisons stay reliable.

    return value.strip().lower()


def _normalise_ip(value: Optional[str]) -> Optional[str]:
    # Return a canonical representation of ``value`` when it is an IP address,
    # allowing IPv4/IPv6 lookups to align across stages.

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
    # Ensure theHarvester host/IP tuples are unique before further enrichment so
    # follow-up scans are not duplicated unnecessarily.

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
    # Return the registrable domain component of ``candidate`` if possible,
    # simplifying domain comparisons for OSINT processing.

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
    # Return ``True`` when ``candidate`` belongs to one of the permitted domains
    # so unrelated OSINT results can be filtered out.

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
    # Derive registrable domains from an iterable of hostnames, keeping the set
    # unique to minimise redundant OSINT lookups.

    domains: Set[str] = set()
    for host in hosts:
        domain = _registered_domain(host)
        if domain:
            domains.add(domain)
    return domains


def extract_domains_from_targets(targets: Iterable[str]) -> Set[str]:
    # Derive registrable domains directly from the requested targets so OSINT
    # scoping can include original entries even when discovery found nothing.

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
    _ensure_directory(HARVESTER_DIR)
    harvester_path = shutil.which("theHarvester")

    for domain in sorted(set(domains)):
        if not domain:
            continue

        if harvester_path:
            prefix = HARVESTER_DIR / domain
            sources = args.harvester_sources or "all"
            cmd = [
                harvester_path,
                "-d",
                domain,
                "-b",
                sources,
                "-l",
                str(args.harvester_limit),
                "-f",
                str(prefix),
            ]

            if _harvester_supports_option(harvester_path, "-quiet"):
                cmd.append("-quiet")
            elif _harvester_supports_option(harvester_path, "-q"):
                cmd.append("-q")
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
                f"theHarvester OSINT for {domain} – enumerating hosts via sources: {sources}"
            )
            run_command(cmd, description=description)
            ensure_tree_owner(HARVESTER_DIR)
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
            ensure_path_owner(host_out)
            ensure_path_owner(dig_out)
            ensure_tree_owner(HARVESTER_DIR)


def _resolve_related_targets(candidates: Iterable[str]) -> List[str]:
    # Filter and de-duplicate hostnames/IPs extracted from OSINT tools so only
    # unique entries are scheduled for follow-up scans.

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


def _safe_enrichment_name(label: str) -> str:
    cleaned = re.sub(r"[^0-9A-Za-z_.-]", "_", str(label).strip())
    return cleaned or "entry"


def _write_enrichment_file(directory: Path, label: str, payload: Mapping[str, object]) -> None:
    _ensure_directory(directory)
    safe_name = _safe_enrichment_name(label)
    path = directory / f"{safe_name}.json"
    try:
        path.write_text(json.dumps(payload, indent=2), encoding="utf-8")
    except OSError as exc:
        echo(f"[!] Failed to write enrichment file {path}: {exc}", essential=True)
        return
    ensure_path_owner(path)


_MAC_CANDIDATE_PATTERNS = (
    re.compile(r"\b(?:[0-9A-Fa-f]{2}[:-]){5}[0-9A-Fa-f]{2}\b"),
    re.compile(r"\b[0-9A-Fa-f]{4}\.[0-9A-Fa-f]{4}\.[0-9A-Fa-f]{4}\b"),
    re.compile(r"\b[0-9A-Fa-f]{12}\b"),
)
_MAC_VENDOR_PATHS: Tuple[Path, ...] = (
    Path("/usr/share/nmap/nmap-mac-prefixes"),
    Path("/usr/share/ieee-data/oui.txt"),
    Path("/usr/share/misc/oui.txt"),
    Path("/var/lib/ieee-data/oui.txt"),
)
_MAC_VENDOR_CACHE: Optional[Dict[str, str]] = None


def _normalise_mac_address(value: str) -> Optional[str]:
    cleaned = re.sub(r"[^0-9A-Fa-f]", "", value)
    if len(cleaned) != 12:
        return None
    grouped = [cleaned[i : i + 2] for i in range(0, 12, 2)]
    return ":".join(group.upper() for group in grouped)


def _parse_mac_vendor_file(path: Path) -> Dict[str, str]:
    mapping: Dict[str, str] = {}
    try:
        with path.open("r", encoding="utf-8", errors="ignore") as handle:
            for raw_line in handle:
                line = raw_line.strip()
                if not line or line.startswith(("#", ";", "//")):
                    continue
                match = None
                for pattern in _MAC_CANDIDATE_PATTERNS:
                    match = pattern.search(line)
                    if match:
                        break
                if not match:
                    continue
                prefix = _normalise_mac_address(match.group(0))
                if not prefix:
                    continue
                prefix_key = prefix.replace(":", "")
                remainder = line[match.end() :].strip()
                remainder = re.sub(r"^(?:\(hex\)|\(base 16\))", "", remainder, flags=re.IGNORECASE).strip(
                    " \t-"
                )
                if not remainder:
                    continue
                mapping.setdefault(prefix_key.upper(), remainder)
    except OSError:
        return {}
    return mapping


def _load_mac_vendor_mapping() -> Dict[str, str]:
    global _MAC_VENDOR_CACHE
    if _MAC_VENDOR_CACHE is not None:
        return _MAC_VENDOR_CACHE

    mapping: Dict[str, str] = {}
    custom_path = os.environ.get("OUI_DATABASE")
    if custom_path:
        candidate = Path(custom_path).expanduser()
        mapping.update(_parse_mac_vendor_file(candidate))

    for candidate in _MAC_VENDOR_PATHS:
        if candidate.is_file():
            for key, value in _parse_mac_vendor_file(candidate).items():
                mapping.setdefault(key, value)

    _MAC_VENDOR_CACHE = mapping
    return mapping


def _lookup_mac_vendor(mac_address: str, vendor_map: Mapping[str, str]) -> Optional[str]:
    prefix = mac_address.replace(":", "").upper()[:6]
    return vendor_map.get(prefix)


def _extract_mac_candidates_from_json(
    node: object, path: str = ""
) -> List[Tuple[str, Dict[str, object]]]:
    results: List[Tuple[str, Dict[str, object]]] = []
    if isinstance(node, Mapping):
        for key, value in node.items():
            child_path = f"{path}.{key}" if path else str(key)
            results.extend(_extract_mac_candidates_from_json(value, child_path))
    elif isinstance(node, (list, tuple, set)):
        for index, value in enumerate(node):
            child_path = f"{path}[{index}]" if path else f"[{index}]"
            results.extend(_extract_mac_candidates_from_json(value, child_path))
    elif isinstance(node, str):
        seen: Set[str] = set()
        for pattern in _MAC_CANDIDATE_PATTERNS:
            for match in pattern.finditer(node):
                candidate = match.group(0)
                if candidate in seen:
                    continue
                seen.add(candidate)
                results.append(
                    (
                        candidate,
                        {
                            "match": candidate,
                            "value": node,
                            "path": path or "value",
                        },
                    )
                )
    return results


def _extract_mac_candidates_from_text(text: str) -> List[Tuple[str, Dict[str, object]]]:
    results: List[Tuple[str, Dict[str, object]]] = []
    for lineno, raw_line in enumerate(text.splitlines(), start=1):
        seen: Set[str] = set()
        for pattern in _MAC_CANDIDATE_PATTERNS:
            for match in pattern.finditer(raw_line):
                candidate = match.group(0)
                if candidate in seen:
                    continue
                seen.add(candidate)
                results.append(
                    (
                        candidate,
                        {
                            "match": candidate,
                            "value": raw_line.strip(),
                            "line": raw_line.strip(),
                            "lineno": lineno,
                        },
                    )
                )
    return results


def _resolve_domain_from_harvester_content(data: object, fallback: str) -> str:
    if isinstance(data, Mapping):
        for key in getattr(aggregate, "HARVESTER_DOMAIN_KEYS", ("domain", "target", "dns_domain", "query", "search")):
            value = data.get(key)
            if isinstance(value, str) and value.strip():
                return value.strip()
            if isinstance(value, Mapping):
                derived = _resolve_domain_from_harvester_content(value, fallback)
                if derived:
                    return derived
        cmd_value = data.get("cmd")
        if isinstance(cmd_value, str):
            match = re.search(r"-d\s+([A-Za-z0-9_.-]+)", cmd_value)
            if match:
                return match.group(1)
        nested = data.get("data")
        if isinstance(nested, (Mapping, list)):
            derived = _resolve_domain_from_harvester_content(nested, fallback)
            if derived:
                return derived
    elif isinstance(data, list):
        for item in data:
            derived = _resolve_domain_from_harvester_content(item, fallback)
            if derived:
                return derived
    return fallback


def _summarise_harvester_domain(
    result: aggregate.HarvesterDomainResult,
) -> Mapping[str, object]:
    summary: Dict[str, object] = {}
    hosts = sorted({finding.hostname for finding in result.findings if finding.hostname})
    ips = sorted({finding.ip for finding in result.findings if finding.ip})
    if hosts:
        summary["hosts"] = hosts
    if ips:
        summary["ips"] = ips
    sections: Dict[str, List[str]] = {}
    for key, values in result.sections.items():
        cleaned = sorted({value for value in values if value})
        if cleaned:
            sections[key] = cleaned
    if sections:
        summary["sections"] = sections
    return summary


def run_mac_address_search() -> None:
    if not HARVESTER_DIR.is_dir():
        echo(
            "[!] Stage 3 – MAC address enrichment skipped because no theHarvester artefacts were generated.",
            essential=True,
        )
        return

    echo("[+] Stage 3 – scanning OSINT artefacts for MAC addresses", essential=True)

    vendor_map = _load_mac_vendor_mapping()
    harvester_results = aggregate.parse_harvester_dir(str(HARVESTER_DIR))
    harvester_context: Dict[str, Mapping[str, object]] = {
        domain.lower(): _summarise_harvester_domain(result)
        for domain, result in harvester_results.items()
        if isinstance(domain, str)
    }

    domains_with_hits = 0
    unique_addresses = 0
    total_occurrences = 0

    for candidate in sorted(HARVESTER_DIR.iterdir()):
        if candidate.is_dir():
            continue
        try:
            raw_text = candidate.read_text(encoding="utf-8", errors="ignore")
        except OSError as exc:
            echo(f"[!] Unable to read {candidate}: {exc}", essential=True)
            continue

        try:
            payload = json.loads(raw_text)
        except json.JSONDecodeError:
            payload = None

        domain_hint = candidate.stem
        if isinstance(payload, (Mapping, list)):
            domain_value = _resolve_domain_from_harvester_content(payload, domain_hint)
        else:
            domain_value = domain_hint

        domain_clean = (domain_value or domain_hint or "").strip()
        if not domain_clean:
            domain_clean = domain_hint or "entry"
        domain_lower = domain_clean.lower()

        contexts = []
        if isinstance(payload, (Mapping, list)):
            contexts.extend(_extract_mac_candidates_from_json(payload))
        contexts.extend(_extract_mac_candidates_from_text(raw_text))

        aggregated: Dict[str, Dict[str, object]] = {}
        seen_occurrences: Set[Tuple[object, ...]] = set()

        for raw_value, context in contexts:
            normalised = _normalise_mac_address(raw_value)
            if not normalised:
                continue

            mac_entry = aggregated.setdefault(
                normalised,
                {
                    "address": normalised,
                    "vendor": _lookup_mac_vendor(normalised, vendor_map),
                    "occurrences": [],
                },
            )

            try:
                relative_path = candidate.relative_to(ROOT)
            except ValueError:
                relative_path = candidate

            occurrence: Dict[str, object] = {
                "source": "harvester",
                "file": str(relative_path),
                "match": context.get("match") or raw_value,
            }

            if "path" in context:
                occurrence["path"] = context["path"]
            if "value" in context:
                occurrence["value"] = context["value"]
            if "line" in context:
                occurrence["line"] = context["line"]
            if "lineno" in context:
                occurrence["lineno"] = context["lineno"]

            occurrence_key = (
                occurrence.get("file"),
                occurrence.get("path"),
                occurrence.get("lineno"),
                occurrence.get("line"),
                occurrence.get("match"),
            )
            if occurrence_key in seen_occurrences:
                continue
            seen_occurrences.add(occurrence_key)
            mac_entry.setdefault("occurrences", []).append(occurrence)

        if not aggregated:
            continue

        mac_entries = sorted(aggregated.values(), key=lambda item: item.get("address", ""))
        payload_out: Dict[str, object] = {
            "domain": domain_clean,
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "mac_addresses": mac_entries,
        }

        context_snapshot = harvester_context.get(domain_lower)
        if context_snapshot:
            payload_out["context"] = context_snapshot

        _write_enrichment_file(MAC_DIR, domain_clean, payload_out)

        domains_with_hits += 1
        unique_addresses += len(mac_entries)
        total_occurrences += sum(len(entry.get("occurrences", [])) for entry in mac_entries)

    if domains_with_hits:
        ensure_tree_owner(MAC_DIR)
        message = (
            f"[+] Stage 3 – recorded {unique_addresses} unique MAC address(es) across "
            f"{domains_with_hits} domain artefact(s) ({total_occurrences} evidence entries)"
        )
        echo(message, essential=True)
    else:
        echo("[!] Stage 3 – no MAC addresses found in theHarvester artefacts.", essential=True)


def _run_dns_command(cmd: Sequence[str]) -> Tuple[Optional[str], Optional[str]]:
    try:
        result = subprocess.run(
            cmd,
            check=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            timeout=20,
        )
        return result.stdout, None
    except FileNotFoundError:
        return None, "command not found"
    except subprocess.TimeoutExpired:
        return None, "timeout"
    except subprocess.CalledProcessError as exc:
        output = exc.stdout if exc.stdout else None
        return output, f"exit code {exc.returncode}"


def _parse_dig_output(output: str, record_type: str) -> List[str]:
    results: List[str] = []
    for raw_line in output.splitlines():
        line = raw_line.strip()
        if not line or line.startswith(";"):
            continue
        parts = line.split()
        if len(parts) < 5:
            continue
        rtype = parts[3].upper()
        if rtype != record_type.upper():
            continue
        data = " ".join(parts[4:])
        if record_type.upper() in {"A", "AAAA"}:
            data = parts[-1]
        data = data.strip().strip('"')
        if not data:
            continue
        if data not in results:
            results.append(data)
    return results


def _socket_dns_lookup(domain: str, record_type: str) -> Tuple[List[str], Optional[str]]:
    values: Set[str] = set()
    try:
        infos = socket.getaddrinfo(domain, None)
    except socket.gaierror as exc:
        return [], str(exc)
    for info in infos:
        sockaddr = info[4]
        if not sockaddr:
            continue
        address = sockaddr[0]
        try:
            parsed = ipaddress.ip_address(address)
        except ValueError:
            continue
        if record_type.upper() == "A" and isinstance(parsed, ipaddress.IPv4Address):
            values.add(str(parsed))
        elif record_type.upper() == "AAAA" and isinstance(parsed, ipaddress.IPv6Address):
            values.add(str(parsed))
    return sorted(values), None


def _lookup_dns_record(domain: str, record_type: str) -> Tuple[List[str], Optional[str], Optional[str]]:
    errors: List[str] = []
    dig_path = shutil.which("dig")
    if dig_path:
        output, error = _run_dns_command([dig_path, "+nocmd", domain, record_type, "+noall", "+answer"])
        if output:
            values = _parse_dig_output(output, record_type)
            if values:
                return values, "dig", None
        if error:
            errors.append(f"dig {record_type}: {error}")
    else:
        errors.append("dig not available")

    if record_type.upper() in {"A", "AAAA"}:
        values, socket_error = _socket_dns_lookup(domain, record_type)
        if values:
            return values, "socket", None
        if socket_error:
            errors.append(f"socket lookup failed: {socket_error}")

    return [], None, ", ".join(errors) if errors else None


def run_dns_enumeration(domains: Sequence[str]) -> Dict[str, Dict[str, object]]:
    results: Dict[str, Dict[str, object]] = {}

    if not domains:
        return results

    echo(f"[+] Stage 3 – enumerating DNS records for {len(domains)} domain(s)", essential=True)
    echo(
        "    ↳ Collecting A, AAAA, MX, NS, and TXT records (dig/socket) and saving JSON summaries to"
        f" {DNS_ENUM_DIR}",
        essential=True,
    )

    for domain in domains:
        domain = domain.strip()
        if not domain:
            continue
        records: Dict[str, List[str]] = {}
        resolvers: Set[str] = set()
        errors: List[str] = []
        for record_type in ("A", "AAAA", "MX", "NS", "TXT"):
            values, resolver, error = _lookup_dns_record(domain, record_type)
            if values:
                records[record_type.lower()] = values
            if resolver:
                resolvers.add(resolver)
            if error:
                errors.append(f"{record_type}: {error}")

        payload: Dict[str, object] = {
            "domain": domain,
            "records": records,
            "timestamp": datetime.now(timezone.utc).isoformat(),
        }
        if resolvers:
            payload["resolvers"] = sorted(resolvers)
        if errors:
            payload["errors"] = errors

        _write_enrichment_file(DNS_ENUM_DIR, domain, payload)

        results[domain.lower()] = payload

    return results


def _grab_http_banner(domain: str, port: int, use_ssl: bool) -> Mapping[str, object]:
    protocol = "https" if use_ssl else "http"
    headers: Dict[str, str] = {}
    try:
        if use_ssl:
            context = ssl.create_default_context()
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE
            connection = http.client.HTTPSConnection(
                domain,
                port,
                timeout=8,
                context=context,
            )
        else:
            connection = http.client.HTTPConnection(domain, port, timeout=8)
        connection.request("HEAD", "/", headers={"User-Agent": "ReconWorkflow/1.0"})
        response = connection.getresponse()
        headers = {key: value for key, value in response.getheaders()}
        banner = headers.get("Server") or headers.get("server")
        return {
            "port": port,
            "protocol": protocol,
            "status": response.status,
            "reason": response.reason,
            "server": banner,
            "headers": headers,
        }
    except Exception as exc:  # pragma: no cover - best-effort network interaction
        return {"port": port, "protocol": protocol, "error": str(exc)}
    finally:
        try:
            connection.close()
        except Exception:  # pragma: no cover - close best effort
            pass


def _grab_raw_banner(domain: str, port: int) -> Mapping[str, object]:
    try:
        with socket.create_connection((domain, port), timeout=8) as conn:
            conn.settimeout(4)
            if port in {80, 443}:
                conn.sendall(b"HEAD / HTTP/1.0\r\nHost: %b\r\n\r\n" % domain.encode("utf-8", errors="ignore"))
            data = conn.recv(200)
    except Exception as exc:  # pragma: no cover - network operations
        return {"port": port, "protocol": "tcp", "error": str(exc)}

    banner = data.decode("utf-8", errors="replace").strip()
    return {"port": port, "protocol": "tcp", "banner": banner}


def run_banner_grabbing(domains: Sequence[str]) -> None:
    if not domains:
        return

    echo(f"[+] Stage 3 – grabbing service banners for {len(domains)} domain(s)", essential=True)
    echo(
        "    ↳ Probing HTTP(S) (ports 80/443) and raw TCP services (ports 22/25) and storing banner captures in"
        f" {BANNER_DIR}",
        essential=True,
    )

    for domain in domains:
        domain = domain.strip()
        if not domain:
            continue
        banners: List[Mapping[str, object]] = []
        for port, use_ssl in ((80, False), (443, True)):
            banners.append(_grab_http_banner(domain, port, use_ssl))
        for raw_port in (22, 25):
            banners.append(_grab_raw_banner(domain, raw_port))

        payload = {
            "domain": domain,
            "banners": banners,
            "timestamp": datetime.now(timezone.utc).isoformat(),
        }
        _write_enrichment_file(BANNER_DIR, domain, payload)


def _whois_query(server: str, query: str) -> Tuple[Optional[str], Optional[str]]:
    try:
        with socket.create_connection((server, 43), timeout=15) as conn:
            conn.sendall(f"{query}\r\n".encode("utf-8"))
            chunks: List[bytes] = []
            while True:
                data = conn.recv(4096)
                if not data:
                    break
                chunks.append(data)
    except OSError as exc:
        return None, str(exc)

    return b"".join(chunks).decode("utf-8", errors="replace"), None


_WHOIS_FALLBACKS: Mapping[str, str] = {
    "com": "whois.verisign-grs.com",
    "net": "whois.verisign-grs.com",
    "org": "whois.pir.org",
    "io": "whois.nic.io",
    "biz": "whois.biz",
    "info": "whois.afilias.net",
    "me": "whois.nic.me",
}


def _extract_whois_refer(text: str) -> Optional[str]:
    for line in text.splitlines():
        if line.lower().startswith("refer:"):
            _, _, remainder = line.partition(":")
            candidate = remainder.strip()
            if candidate:
                return candidate
    return None


_WHOIS_MULTI_KEYS = {"status", "name server", "nameserver", "nserver"}


def _parse_whois_response(text: str) -> Mapping[str, object]:
    parsed: Dict[str, object] = {}
    for raw_line in text.splitlines():
        line = raw_line.strip()
        if not line or line.startswith("%") or line.startswith("#"):
            continue
        if ":" not in line:
            continue
        key, _, value = line.partition(":")
        key = key.strip()
        value = value.strip()
        if not key or not value:
            continue
        canonical = key.lower().replace(" ", "_")
        if canonical in _WHOIS_MULTI_KEYS or key.lower() in _WHOIS_MULTI_KEYS:
            bucket = parsed.setdefault(canonical, [])
            if isinstance(bucket, list) and value not in bucket:
                bucket.append(value)
        else:
            parsed[canonical] = value
    return parsed


def run_whois_lookups(domains: Sequence[str]) -> None:
    if not domains:
        return

    echo(f"[+] Stage 3 – performing WHOIS lookups for {len(domains)} domain(s)", essential=True)
    echo(
        "    ↳ Querying IANA and registry WHOIS servers; parsed responses are written to"
        f" {WHOIS_DIR}",
        essential=True,
    )

    for domain in domains:
        domain = domain.strip()
        if not domain:
            continue
        payload: Dict[str, object] = {
            "domain": domain,
            "timestamp": datetime.now(timezone.utc).isoformat(),
        }

        primary_text, primary_error = _whois_query("whois.iana.org", domain)
        errors: List[str] = []
        if primary_text:
            payload["iana_response"] = primary_text
            refer_server = _extract_whois_refer(primary_text)
        else:
            refer_server = None
            if primary_error:
                errors.append(f"iana: {primary_error}")

        if not refer_server:
            suffix = domain.rsplit(".", 1)[-1].lower() if "." in domain else domain.lower()
            refer_server = _WHOIS_FALLBACKS.get(suffix)

        if refer_server:
            payload["whois_server"] = refer_server
            response_text, lookup_error = _whois_query(refer_server, domain)
            if response_text:
                payload["raw_response"] = response_text
                parsed = _parse_whois_response(response_text)
                if parsed:
                    payload["parsed"] = parsed
            elif lookup_error:
                errors.append(f"{refer_server}: {lookup_error}")
        elif primary_text:
            payload["raw_response"] = primary_text
            parsed = _parse_whois_response(primary_text)
            if parsed:
                payload["parsed"] = parsed

        if errors:
            payload["errors"] = errors

        _write_enrichment_file(WHOIS_DIR, domain, payload)


def run_certificate_transparency(domains: Sequence[str]) -> None:
    if not domains:
        return

    echo(
        f"[+] Stage 3 – querying certificate transparency logs for {len(domains)} domain(s)",
        essential=True,
    )
    echo(
        "    ↳ Fetching recent crt.sh entries (up to 50 per domain) and recording them under"
        f" {CT_DIR}",
        essential=True,
    )

    for domain in domains:
        domain = domain.strip()
        if not domain:
            continue
        payload: Dict[str, object] = {
            "domain": domain,
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "source": "crt.sh",
        }
        url = f"https://crt.sh/?q={urlquote(domain)}&output=json"
        try:
            request = Request(url, headers={"User-Agent": "ReconWorkflow/1.0"})
            with urlopen(request, timeout=30) as response:
                raw = response.read()
        except (HTTPError, URLError, OSError) as exc:
            payload["error"] = str(exc)
            _write_enrichment_file(CT_DIR, domain, payload)
            continue

        try:
            decoded = json.loads(raw.decode("utf-8"))
        except json.JSONDecodeError as exc:
            payload["error"] = f"decode error: {exc}"
            _write_enrichment_file(CT_DIR, domain, payload)
            continue

        entries: List[Mapping[str, object]] = []
        seen: Set[Tuple[object, object]] = set()
        if isinstance(decoded, list):
            for entry in decoded:
                if not isinstance(entry, Mapping):
                    continue
                name_value = entry.get("name_value") or entry.get("common_name")
                if not isinstance(name_value, str):
                    continue
                cleaned_name = name_value.strip()
                if not cleaned_name:
                    continue
                key = (cleaned_name.lower(), entry.get("min_cert_id"))
                if key in seen:
                    continue
                seen.add(key)
                entries.append(
                    {
                        "name": cleaned_name,
                        "issuer": entry.get("issuer_name"),
                        "not_before": entry.get("not_before"),
                        "not_after": entry.get("not_after"),
                        "entry_timestamp": entry.get("entry_timestamp"),
                        "min_cert_id": entry.get("min_cert_id"),
                    }
                )
                if len(entries) >= 50:
                    break
        payload["entries"] = entries
        _write_enrichment_file(CT_DIR, domain, payload)


def _collect_shodan_summary(data: Mapping[str, object]) -> Mapping[str, object]:
    ports = []
    raw_ports = data.get("ports")
    if isinstance(raw_ports, list):
        ports = sorted(
            {
                int(port)
                for port in raw_ports
                if isinstance(port, int) or (isinstance(port, str) and port.isdigit())
            }
        )

    hostnames: List[str] = []
    raw_hostnames = data.get("hostnames")
    if isinstance(raw_hostnames, list):
        hostnames = sorted(
            {
                str(host).strip()
                for host in raw_hostnames
                if isinstance(host, str) and host.strip()
            }
        )

    vulns: List[str] = []
    raw_vulns = data.get("vulns")
    if isinstance(raw_vulns, Mapping):
        vulns = sorted({str(key) for key in raw_vulns.keys() if key})

    entries: List[Mapping[str, object]] = []
    raw_data = data.get("data")
    if isinstance(raw_data, list):
        for item in raw_data[:10]:
            if not isinstance(item, Mapping):
                continue
            entry: Dict[str, object] = {}
            for key in ("port", "transport", "product", "version", "timestamp"):
                value = item.get(key)
                if value is not None:
                    entry[key] = value
            cpe = item.get("cpe")
            if isinstance(cpe, list):
                entry["cpe"] = [str(value) for value in cpe if value]
            snippet = item.get("data")
            if isinstance(snippet, str):
                entry["data"] = snippet[:200]
            if entry:
                entries.append(entry)

    summary: Dict[str, object] = {
        "ip": data.get("ip_str") or data.get("ip") or data.get("ipv6") or data.get("ipv4"),
        "ports": ports,
        "hostnames": hostnames,
        "org": data.get("org"),
        "os": data.get("os"),
        "isp": data.get("isp"),
        "asn": data.get("asn"),
        "city": data.get("city"),
        "country": data.get("country_name") or data.get("country_code"),
        "last_update": data.get("last_update"),
        "tags": data.get("tags"),
        "vulns": vulns,
        "services": entries,
    }
    return summary


def run_shodan_lookups(ips: Sequence[str], api_key: Optional[str]) -> None:
    if not ips:
        return
    if not api_key:
        echo("[!] Skipping Shodan lookups – API key not provided", essential=True)
        return

    echo(f"[+] Stage 3 – querying Shodan for {len(ips)} host(s)", essential=True)

    for ip in ips:
        payload: Dict[str, object] = {
            "ip": ip,
            "timestamp": datetime.now(timezone.utc).isoformat(),
        }
        url = f"https://api.shodan.io/shodan/host/{urlquote(ip)}?key={urlquote(api_key)}"
        try:
            request = Request(url, headers={"User-Agent": "ReconWorkflow/1.0"})
            with urlopen(request, timeout=30) as response:
                raw = response.read()
        except HTTPError as exc:
            payload["error"] = f"HTTP {exc.code}: {exc.reason}"
            _write_enrichment_file(SHODAN_DIR, ip, payload)
            continue
        except (URLError, OSError) as exc:
            payload["error"] = str(exc)
            _write_enrichment_file(SHODAN_DIR, ip, payload)
            continue

        try:
            decoded = json.loads(raw.decode("utf-8"))
        except json.JSONDecodeError as exc:
            payload["error"] = f"decode error: {exc}"
            _write_enrichment_file(SHODAN_DIR, ip, payload)
            continue

        if isinstance(decoded, Mapping):
            payload["summary"] = _collect_shodan_summary(decoded)
        else:
            payload["error"] = "unexpected response format"

        _write_enrichment_file(SHODAN_DIR, ip, payload)


def aggregate_results() -> None:
    # Invoke the aggregation helper to merge outputs from every stage into the
    # consolidated inventory artefacts.
    _ensure_directory(REPORT_DIR)
    cmd = [
        sys.executable or "python3",
        str(ROOT / "tools" / "aggregate.py"),
        "--nmap-dir",
        str(NMAP_DIR),
        "--nikto-dir",
        str(NIKTO_DIR),
        "--masscan-json",
        str(MASSCAN_JSON),
        "--smrib-json",
        str(SMRIB_JSON),
        "--harv-dir",
        str(HARVESTER_DIR),
        "--dns-dir",
        str(DNS_ENUM_DIR),
        "--banner-dir",
        str(BANNER_DIR),
        "--whois-dir",
        str(WHOIS_DIR),
        "--ct-dir",
        str(CT_DIR),
        "--shodan-dir",
        str(SHODAN_DIR),
        "--mac-dir",
        str(MAC_DIR),
        "--out-json",
        str(INVENTORY_JSON),
        "--out-csv",
        str(INVENTORY_CSV),
    ]
    description = (
        "Aggregating scan outputs – merging Masscan, Nmap, Nikto, smrib, and theHarvester artefacts"
    )
    run_command(cmd, description=description, check=False)
    ensure_tree_owner(REPORT_DIR)


def display_inventory_contents() -> None:
    # Print the contents of the aggregated inventory for quick inspection,
    # helping operators gauge the breadth of results without opening files.

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
        shodan_data = host.get("shodan")
        if isinstance(shodan_data, Mapping) and shodan_data:
            echo("      Shodan summary:", essential=True)
            org = shodan_data.get("org") or shodan_data.get("isp")
            if org:
                echo(f"        Organisation: {org}", essential=True)
            location_bits: List[str] = []
            city = shodan_data.get("city")
            if city:
                location_bits.append(str(city))
            country = shodan_data.get("country")
            if country:
                location_bits.append(str(country))
            if location_bits:
                echo(f"        Location: {', '.join(location_bits)}", essential=True)
            ports = shodan_data.get("ports") or []
            if ports:
                echo(
                    f"        Observed ports: {', '.join(str(port) for port in ports)}",
                    essential=True,
                )
            tags = shodan_data.get("tags") or []
            if tags:
                echo(f"        Tags: {', '.join(tags)}", essential=True)
            vulns = shodan_data.get("vulns") or []
            if vulns:
                echo(f"        Vulnerabilities: {', '.join(vulns)}", essential=True)
            services = shodan_data.get("services") or []
            if services:
                echo("        Services:", essential=True)
                for service in services[:5]:
                    if not isinstance(service, Mapping):
                        continue
                    descriptor: List[str] = []
                    port = service.get("port")
                    if port is not None:
                        descriptor.append(f"port {port}")
                    product = service.get("product")
                    if product:
                        descriptor.append(str(product))
                    version = service.get("version")
                    if version:
                        descriptor.append(str(version))
                    summary_line = "          - " + " – ".join(descriptor) if descriptor else "          - Service"
                    echo(summary_line, essential=True)
                    snippet = service.get("data")
                    if isinstance(snippet, str) and snippet.strip():
                        preview = snippet.strip().splitlines()[0][:120]
                        echo(f"            {preview}", essential=True)
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
            enrichment = summary.get("enrichment")
            if isinstance(enrichment, Mapping) and enrichment:
                echo("      Enrichment:", essential=True)
                dns_info = enrichment.get("dns_records")
                if isinstance(dns_info, Mapping):
                    records = dns_info.get("records")
                    if isinstance(records, Mapping):
                        record_bits: List[str] = []
                        for rtype, values in sorted(records.items()):
                            if isinstance(values, list) and values:
                                record_bits.append(f"{rtype.upper()}={', '.join(values[:5])}")
                        if record_bits:
                            echo(f"        DNS: {'; '.join(record_bits)}", essential=True)
                banner_info = enrichment.get("banners")
                if isinstance(banner_info, Mapping):
                    banners = banner_info.get("banners")
                    if isinstance(banners, list) and banners:
                        samples: List[str] = []
                        for entry in banners[:3]:
                            if not isinstance(entry, Mapping):
                                continue
                            port = entry.get("port")
                            proto = entry.get("protocol") or "tcp"
                            server = entry.get("server") or entry.get("banner")
                            status = entry.get("status")
                            parts = [f"{port}/{proto}"] if port is not None else []
                            if status:
                                parts.append(str(status))
                            if server:
                                parts.append(str(server))
                            if parts:
                                samples.append(" ".join(parts))
                        if samples:
                            echo(f"        Banners: {'; '.join(samples)}", essential=True)
                whois_info = enrichment.get("whois")
                if isinstance(whois_info, Mapping):
                    parsed = whois_info.get("parsed")
                    if isinstance(parsed, Mapping):
                        registrar = parsed.get("registrar")
                        created = parsed.get("creation_date") or parsed.get("creation_date_utc")
                        details: List[str] = []
                        if registrar:
                            details.append(f"Registrar {registrar}")
                        if created:
                            details.append(f"Created {created}")
                        if details:
                            echo(f"        WHOIS: {', '.join(details)}", essential=True)
                ct_info = enrichment.get("certificate_transparency")
                if isinstance(ct_info, Mapping):
                    entries = ct_info.get("entries")
                    if isinstance(entries, list) and entries:
                        names = [
                            entry.get("name")
                            for entry in entries[:5]
                            if isinstance(entry, Mapping) and entry.get("name")
                        ]
                        if names:
                            echo(f"        Certificate names: {', '.join(names)}", essential=True)
            echo("", essential=True)


def collect_http_urls(inventory: List[Mapping[str, object]]) -> List[str]:
    # Walk the aggregated inventory and build a deduplicated list of HTTP(S)
    # endpoints that EyeWitness should visit.
    urls: Set[str] = set()
    hosts: Dict[str, List[Mapping[str, object]]] = {}

    def _format_host(value: str) -> str:
        # Enclose IPv6 addresses in brackets so generated URLs remain valid.
        try:
            address = ipaddress.ip_address(value)
        except ValueError:
            return value
        if address.version == 6:
            return f"[{value}]"
        return value

    for entry in inventory:
        ip = entry.get("ip")
        if not isinstance(ip, str):
            continue
        services = entry.get("services", []) or []
        hosts.setdefault(ip, []).extend(
            [service for service in services if isinstance(service, Mapping)]
        )

    for ip, services in hosts.items():
        formatted_host = _format_host(ip)
        ports = {
            service.get("port")
            for service in services
            if isinstance(service.get("port"), int)
        }
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
                url = f"{scheme}://{formatted_host}"
            else:
                url = f"{scheme}://{formatted_host}:{port}"
            urls.add(url)

        # When 443 is the only standard web port exposed, ensure we still visit it.
        https_root = f"https://{formatted_host}"
        if ports == {443} and https_root not in urls:
            urls.add(https_root)

    return sorted(urls)


def run_eyewitness(urls: Sequence[str], args: argparse.Namespace) -> List[Path]:
    # Capture screenshots of HTTP services using EyeWitness when the binary is
    # installed and the operator has not opted out of this stage.
    if args.skip_eyewitness:
        return []

    ensure_writable_directory(EYEWITNESS_DIR)
    ensure_tree_owner(EYEWITNESS_DIR)
    pretty_print_stage_inputs("EyeWitness URLs", [(url,) for url in urls])

    if not urls:
        return []

    eyewitness_path = shutil.which("eyewitness")
    if not eyewitness_path:
        echo("[!] EyeWitness not installed – skipping screenshot capture.", essential=True)
        return []

    screenshots: List[Path] = []
    report_files: Set[Path] = set()
    for url in urls:
        safe_dir = re.sub(r"[^0-9A-Za-z_.-]", "_", url)
        output_dir = EYEWITNESS_DIR / safe_dir
        _ensure_directory(output_dir)
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
        ensure_tree_owner(output_dir)
        screenshots.extend(output_dir.rglob("*.png"))
        for candidate in output_dir.rglob("*.html"):
            if candidate.is_file():
                report_files.add(candidate.resolve())

    if args.show_eyewitness and report_files:
        _launch_eyewitness_reports(sorted(report_files))

    return screenshots


def _launch_eyewitness_reports(report_paths: Sequence[Path]) -> None:
    # Open the generated EyeWitness HTML reports in Firefox for quick review.
    firefox_path = shutil.which("firefox")
    if not firefox_path:
        echo("[!] Firefox not available – cannot display EyeWitness reports.", essential=True)
        return

    for report in report_paths:
        try:
            echo(f"[+] Opening EyeWitness report in Firefox: {report}", essential=True)
            subprocess.Popen([firefox_path, str(report)], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        except OSError as exc:
            echo(f"[!] Failed to launch Firefox for {report}: {exc}", essential=True)


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
    _ensure_directory(OUT_DIR)

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
                    nikto_findings = service.get("nikto_findings") or []
                    for finding in nikto_findings:
                        if not isinstance(finding, Mapping):
                            continue
                        summary_bits: List[str] = []
                        risk = finding.get("risk")
                        if risk:
                            summary_bits.append(str(risk).upper())
                        description = finding.get("description")
                        if description:
                            summary_bits.append(str(description))
                        identifier = finding.get("id")
                        if identifier:
                            summary_bits.append(f"id={identifier}")
                        url = finding.get("url")
                        if url:
                            summary_bits.append(f"url={url}")
                        references = finding.get("references")
                        if isinstance(references, list) and references:
                            ref_text = ", ".join(str(ref) for ref in references if ref)
                            if ref_text:
                                summary_bits.append(f"refs={ref_text}")
                        extras.append(
                            f"nikto: {' – '.join(bit for bit in summary_bits if bit)}"
                        )
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
            shodan_data = entry.get("shodan")
            if isinstance(shodan_data, Mapping) and shodan_data:
                shodan_bits: List[str] = []
                org = shodan_data.get("org") or shodan_data.get("isp")
                if org:
                    shodan_bits.append(f"Organisation {org}")
                location_pieces: List[str] = []
                city = shodan_data.get("city")
                if city:
                    location_pieces.append(str(city))
                country = shodan_data.get("country")
                if country:
                    location_pieces.append(str(country))
                if location_pieces:
                    shodan_bits.append(f"Location {'/'.join(location_pieces)}")
                ports = shodan_data.get("ports") or []
                if ports:
                    shodan_bits.append(f"Ports {', '.join(str(port) for port in ports)}")
                tags = shodan_data.get("tags") or []
                if tags:
                    shodan_bits.append(f"Tags {', '.join(tags)}")
                vulns = shodan_data.get("vulns") or []
                if vulns:
                    shodan_bits.append(f"Vulnerabilities {', '.join(vulns)}")
                services = shodan_data.get("services") or []
                if services:
                    for service in services[:5]:
                        if not isinstance(service, Mapping):
                            continue
                        descriptor: List[str] = []
                        port = service.get("port")
                        if port is not None:
                            descriptor.append(f"port {port}")
                        product = service.get("product")
                        if product:
                            descriptor.append(str(product))
                        version = service.get("version")
                        if version:
                            descriptor.append(str(version))
                        snippet = service.get("data")
                        if isinstance(snippet, str) and snippet.strip():
                            descriptor.append(snippet.strip().splitlines()[0][:80])
                        if descriptor:
                            shodan_bits.append(f"Service {' – '.join(descriptor)}")
                if shodan_bits:
                    lines.append("- **Shodan summary**:")
                    for item in shodan_bits:
                        lines.append(f"    - {item}")

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
            enrichment = summary.get("enrichment")
            if isinstance(enrichment, Mapping) and enrichment:
                dns_info = enrichment.get("dns_records")
                if isinstance(dns_info, Mapping):
                    records = dns_info.get("records")
                    if isinstance(records, Mapping):
                        record_bits: List[str] = []
                        for rtype, values in sorted(records.items()):
                            if isinstance(values, list) and values:
                                record_bits.append(f"{rtype.upper()}={', '.join(values[:5])}")
                        if record_bits:
                            lines.append(f"- **DNS**: {'; '.join(record_bits)}")
                banner_info = enrichment.get("banners")
                if isinstance(banner_info, Mapping):
                    banners = banner_info.get("banners")
                    if isinstance(banners, list) and banners:
                        samples: List[str] = []
                        for entry in banners[:3]:
                            if not isinstance(entry, Mapping):
                                continue
                            port = entry.get("port")
                            proto = entry.get("protocol") or "tcp"
                            server = entry.get("server") or entry.get("banner")
                            status = entry.get("status")
                            parts = [f"{port}/{proto}"] if port is not None else []
                            if status:
                                parts.append(str(status))
                            if server:
                                parts.append(str(server))
                            if parts:
                                samples.append(" ".join(parts))
                        if samples:
                            lines.append(f"- **Banners**: {'; '.join(samples)}")
                whois_info = enrichment.get("whois")
                if isinstance(whois_info, Mapping):
                    parsed = whois_info.get("parsed")
                    if isinstance(parsed, Mapping):
                        registrar = parsed.get("registrar")
                        created = parsed.get("creation_date") or parsed.get("creation_date_utc")
                        details: List[str] = []
                        if registrar:
                            details.append(f"Registrar {registrar}")
                        if created:
                            details.append(f"Created {created}")
                        if details:
                            lines.append(f"- **WHOIS**: {', '.join(details)}")
                ct_info = enrichment.get("certificate_transparency")
                if isinstance(ct_info, Mapping):
                    entries = ct_info.get("entries")
                    if isinstance(entries, list) and entries:
                        names = [
                            entry.get("name")
                            for entry in entries[:5]
                            if isinstance(entry, Mapping) and entry.get("name")
                        ]
                        if names:
                            lines.append(f"- **Certificate names**: {', '.join(names)}")
                mac_info = enrichment.get("mac_addresses") if isinstance(enrichment, Mapping) else None
                if isinstance(mac_info, Mapping):
                    addresses = mac_info.get("mac_addresses")
                    if isinstance(addresses, list) and addresses:
                        samples: List[str] = []
                        for entry in addresses[:5]:
                            if not isinstance(entry, Mapping):
                                continue
                            address = entry.get("address") or entry.get("mac_address")
                            vendor = entry.get("vendor")
                            if not address:
                                continue
                            if isinstance(vendor, str) and vendor.strip():
                                samples.append(f"{address} ({vendor.strip()})")
                            else:
                                samples.append(str(address))
                        if samples:
                            lines.append(f"- **MAC addresses**: {', '.join(samples)}")
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

    _ensure_directory(REPORT_DIR)
    REPORT_PATH.write_text("\n".join(lines), encoding="utf-8")
    ensure_path_owner(REPORT_PATH)
    echo(f"[+] Wrote report to {REPORT_PATH}", essential=True)


def main(argv: Optional[Sequence[str]] = None) -> None:
    # Tie together all pipeline stages in the intended execution order.
    args = parse_args(argv)
    global _SILENT_MODE
    _SILENT_MODE = args.silent

    git_message = _format_git_version_message()
    if git_message:
        echo(git_message, essential=True)

    if args.scanner == "smrib":
        smrib_path = Path(args.smrib_path).expanduser()
        if args.smrib_path == DEFAULT_SMRIB_PATH and not smrib_path.is_file():
            if not ensure_scanner_repository():
                echo(
                    "[!] Falling back to Nmap for discovery because smrib.py could not be retrieved from GitHub.",
                    essential=True,
                )
                args.scanner = "nmap"
            else:
                args.smrib_path = DEFAULT_SMRIB_PATH
        elif not smrib_path.is_file():
            echo(
                f"[!] smrib.py not found at {smrib_path} – switching discovery scanner to Nmap.",
                essential=True,
            )
            args.scanner = "nmap"

    if not args.preserve_output:
        reset_output_tree()
    else:
        echo(
            "[!] Preserving existing output files – prior results may appear in the current run.",
            essential=True,
        )

    echo("[+] Starting reconnaissance workflow", essential=True)
    port_selection = build_port_selection(args)
    nmap_tuning_args = build_nmap_tuning_args(args)
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
    use_sudo = args.sudo

    stage_one_batches: List[Tuple[List[str], PortSelection]] = []
    stage_one_printable: List[Tuple[Tuple[str, ...], str]] = []

    for key, subset in groups.items():
        if not subset:
            continue
        if key is None:
            selection = port_selection
        else:
            selection = _port_selection_from_ports(list(key))
        subset_list = list(subset)
        stage_one_batches.append((subset_list, selection))
        stage_one_printable.append((tuple(subset_list), selection.description))
        if selection.description not in discovery_descriptions:
            discovery_descriptions.append(selection.description)

    pretty_print_stage_inputs("Stage 1 – discovery", stage_one_printable)

    for subset, selection in stage_one_batches:
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
            results = run_smrib(
                subset,
                selection,
                args.smrib_path,
                args.smrib_parameters,
                use_sudo,
            )
            _merge_result_maps(smrib_results, results)
        else:
            results = run_nmap_discovery(subset, selection, use_sudo, nmap_tuning_args)
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
    stage_two_tools: List[str] = []
    if args.stage2_use_nmap:
        stage_two_tools.append("Nmap")
    if args.stage2_use_nikto:
        stage_two_tools.append("Nikto")

    if stage_two_tools:
        if len(stage_two_tools) == 1:
            tool_phrase = stage_two_tools[0]
        else:
            tool_phrase = ", ".join(stage_two_tools[:-1]) + f" and {stage_two_tools[-1]}"
        stage_two_summary = (
            f"Fingerprinting {actionable_hosts} host(s) with confirmed open ports using {tool_phrase}."
        )
    else:
        stage_two_summary = "Fingerprinting skipped – no stage 2 tools selected."
    echo_stage(2, "Fingerprinting", summary=stage_two_summary)

    stage_two_inputs = [
        (label, tuple(sorted(ports)) if ports else tuple())
        for label, ports in sorted(discovered_hosts.items())
    ]
    pretty_print_stage_inputs("Stage 2 – fingerprinting", stage_two_inputs)

    if args.stage2_use_nmap:
        run_nmap_fingerprinting(discovered_hosts, use_sudo, nmap_tuning_args)
    if args.stage2_use_nikto:
        run_nikto_scans(discovered_hosts, use_sudo)

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

    stage_three_tools: List[str] = []
    if args.stage3_harvester:
        stage_three_tools.append("theHarvester")
    if args.stage3_dns:
        stage_three_tools.append("DNS enumeration")
    if args.stage3_banners:
        stage_three_tools.append("banner grabbing")
    if args.stage3_whois:
        stage_three_tools.append("WHOIS")
    if args.stage3_ct:
        stage_three_tools.append("certificate transparency lookups")
    if args.stage3_shodan and args.shodan_api_key:
        stage_three_tools.append("Shodan")
    elif args.stage3_shodan:
        stage_three_tools.append("Shodan (pending API key)")
    if args.stage3_mac:
        stage_three_tools.append("MAC address enrichment")

    if not stage_three_tools:
        tools_phrase = "no enabled Stage 3 tools"
    elif len(stage_three_tools) == 1:
        tools_phrase = stage_three_tools[0]
    else:
        tools_phrase = ", ".join(stage_three_tools[:-1]) + f" and {stage_three_tools[-1]}"

    if stage_three_tools:
        stage_three_summary = (
            f"Gathering OSINT with {tools_phrase} for "
            f"{len(domains)} domain(s) linked to discovered assets."
        )
    else:
        stage_three_summary = "OSINT enrichment skipped – no stage 3 tools enabled."
    echo_stage(3, "OSINT enrichment", summary=stage_three_summary)

    stage_three_inputs = [(domain,) for domain in sorted(domains)]
    pretty_print_stage_inputs("Stage 3 – OSINT enrichment", stage_three_inputs)

    processed_domains: Set[str] = set()
    pending_domains: Set[str] = set()
    scanned_targets: Set[str] = {_normalise_target(target) for target in targets}
    for ip in discovered_hosts:
        scanned_targets.add(_normalise_target(ip))
    not_processed_related: Set[str] = set()

    if not args.stage3_harvester:
        echo("[!] Stage 3 – theHarvester disabled via flag; skipping execution.", essential=True)
    elif not domains:
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
                discovery_subset = run_nmap_discovery(
                    resolved_targets,
                    port_selection,
                    use_sudo,
                    nmap_tuning_args,
                )
                for host, ports in discovery_subset.items():
                    discovered_hosts.setdefault(host, set()).update(ports)
                    _note_known_ip(host)
                display_discovered_hosts(discovery_subset)
                run_nmap_fingerprinting(discovery_subset, use_sudo, nmap_tuning_args)
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

    enrichment_domains = {
        domain
        for domain in all_domains
        if isinstance(domain, str) and domain.strip()
    }
    if not enrichment_domains:
        enrichment_domains = {
            domain for domain in domains if isinstance(domain, str) and domain.strip()
        }

    enrichment_domain_list = sorted(enrichment_domains)

    dns_payloads: Dict[str, Dict[str, object]] = {}
    if args.stage3_dns:
        if enrichment_domain_list:
            dns_payloads = run_dns_enumeration(enrichment_domain_list)
        else:
            echo(
                "[!] Stage 3 – DNS enumeration skipped because no domains were available.",
                essential=True,
            )

    if args.stage3_banners:
        if enrichment_domain_list:
            run_banner_grabbing(enrichment_domain_list)
        else:
            echo(
                "[!] Stage 3 – banner grabbing skipped because no domains were available.",
                essential=True,
            )

    if args.stage3_whois:
        whois_targets = {
            _registered_domain(domain) or domain
            for domain in enrichment_domain_list
            if domain
        }
        whois_list = sorted({item for item in whois_targets if item})
        if whois_list:
            run_whois_lookups(whois_list)
        else:
            echo(
                "[!] Stage 3 – WHOIS lookups skipped because no registrable domains were identified.",
                essential=True,
            )

    if args.stage3_ct:
        ct_targets = {
            _registered_domain(domain) or domain
            for domain in enrichment_domain_list
            if domain
        }
        ct_list = sorted({item for item in ct_targets if item})
        if ct_list:
            run_certificate_transparency(ct_list)
        else:
            echo(
                "[!] Stage 3 – certificate transparency lookups skipped because no registrable domains were identified.",
                essential=True,
            )

    if args.stage3_shodan:
        shodan_candidates: Set[str] = set()
        for label in discovered_hosts:
            ip_normalised = _normalise_ip(label)
            if ip_normalised:
                shodan_candidates.add(ip_normalised)
        shodan_candidates.update(ip_host_assignments.keys())
        for payload in dns_payloads.values():
            records = payload.get("records")
            if isinstance(records, Mapping):
                for key in ("a", "aaaa"):
                    values = records.get(key)
                    if isinstance(values, list):
                        for value in values:
                            ip_normalised = _normalise_ip(value)
                            if ip_normalised:
                                shodan_candidates.add(ip_normalised)

        run_shodan_lookups(sorted(shodan_candidates), args.shodan_api_key)

    if args.stage3_mac:
        run_mac_address_search()

    export_not_processed_targets(not_processed_related)

    aggregate_results()

    inventory = load_inventory()
    echo(f"[+] Aggregated inventory entries: {len(inventory)}", essential=True)
    if args.show_inventory:
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
