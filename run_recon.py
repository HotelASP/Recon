#!/usr/bin/env python3
"""Orchestrate a three-stage reconnaissance workflow.

The pipeline performs the following actions:

1. **Discovery scan** – run Masscan (default), ``smrib.py``, or Nmap across the
   provided targets to identify live hosts and open ports.
2. **Detailed fingerprinting** – execute Nmap with service, version, and OS
   detection against the discovered host/port combinations, persisting the XML
   output.
3. **OSINT collection** – leverage theHarvester (when available) to gather
   related hostnames and subdomains based on the domains resolved during the
   Nmap phase.

Once all stages finish, the script calls :mod:`tools.aggregate` to merge the
results into ``inventory.json`` and ``inventory.csv`` and then generates a short
``report.md`` that summarises the run and references any screenshots captured by
EyeWitness.
"""

from __future__ import annotations

import argparse
import ipaddress
import json
import os
import re
import shutil
import subprocess
import sys
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Dict, Iterable, List, Mapping, Optional, Sequence, Set

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


@dataclass
class PortSelection:
    """Represents the chosen discovery port strategy."""

    description: str
    masscan_args: List[str]
    nmap_args: List[str]
    smrib_args: List[str]
    fallback_range: Optional[str]


def parse_args(argv: Optional[Sequence[str]] = None) -> argparse.Namespace:
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
        help="Scan only the top N ports instead of the full range.",
    )
    parser.add_argument(
        "--port-range",
        help="Explicit port range or comma separated list (default: 1-65535).",
    )
    parser.add_argument(
        "--masscan-rate",
        type=int,
        default=1000,
        help="Packet rate to use with masscan (default: 1000).",
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

    return parser.parse_args(argv)


def build_port_selection(args: argparse.Namespace) -> PortSelection:
    if args.top_ports is not None and args.top_ports <= 0:
        raise SystemExit("--top-ports must be a positive integer")

    if args.port_range and args.top_ports is not None:
        raise SystemExit("Specify either --top-ports or --port-range, not both.")

    if args.port_range:
        if not re.fullmatch(r"[0-9,-]+", args.port_range):
            raise SystemExit("--port-range must contain only digits, commas, and hyphens")
        description = f"ports {args.port_range}"
        masscan_args = ["-p", args.port_range]
        nmap_args = ["-p", args.port_range]
        smrib_args = ["--ports", args.port_range]
        fallback = args.port_range
    elif args.top_ports is not None:
        description = f"top {args.top_ports} ports"
        value = str(args.top_ports)
        masscan_args = ["--top-ports", value]
        nmap_args = ["--top-ports", value]
        smrib_args = ["--top-ports", value]
        fallback = None
    else:
        description = "ports 1-65535"
        masscan_args = ["-p", "1-65535"]
        nmap_args = ["-p", "1-65535"]
        smrib_args = ["--ports", "1-65535"]
        fallback = "1-65535"

    return PortSelection(description, masscan_args, nmap_args, smrib_args, fallback)


def load_targets(path: Path) -> List[str]:
    if not path.exists():
        raise SystemExit(f"Targets file not found: {path}")

    targets: List[str] = []
    for line in path.read_text(encoding="utf-8").splitlines():
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue
        targets.append(stripped)

    if not targets:
        raise SystemExit("No targets defined in targets.txt")

    return targets


def prefix_command(cmd: List[str], use_sudo: bool) -> List[str]:
    if not use_sudo:
        return cmd
    sudo_path = shutil.which("sudo")
    if sudo_path:
        return [sudo_path] + cmd
    return cmd


def run_command(cmd: List[str], *, description: str, check: bool = False) -> bool:
    print(f"\n[+] {description}")
    print("    " + " ".join(cmd))
    try:
        completed = subprocess.run(cmd, check=check)
        return completed.returncode == 0
    except FileNotFoundError:
        print(f"[!] Command not found: {cmd[0]}")
    except subprocess.CalledProcessError as exc:
        print(f"[!] Command failed with exit code {exc.returncode}")
    return False


def run_masscan(
    targets: Sequence[str],
    port_selection: PortSelection,
    rate: int,
    use_sudo: bool,
) -> Mapping[str, Set[int]]:
    if not shutil.which("masscan"):
        print("[!] masscan is not installed or not in PATH – skipping discovery stage.")
        return {}

    cmd = ["masscan", "--rate", str(rate), "--open", "--output-format", "json", "-oJ", str(MASSCAN_JSON)]
    cmd.extend(port_selection.masscan_args)
    cmd.extend(targets)
    success = run_command(prefix_command(cmd, use_sudo), description=f"Masscan discovery ({port_selection.description})")
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
    script_path = Path(smrib_path).expanduser()
    if not script_path.exists():
        print(f"[!] smrib.py not found at {script_path} – skipping discovery stage.")
        return {}

    cmd: List[str] = [sys.executable or "python3", str(script_path)]
    cmd.extend(port_selection.smrib_args)
    cmd.extend(["--json", str(SMRIB_JSON)])
    cmd.extend(["--targets", ",".join(targets)])
    if extra_args:
        cmd.extend(extra_args)

    success = run_command(prefix_command(cmd, use_sudo), description=f"smrib discovery ({port_selection.description})")
    if not success:
        return {}

    results = aggregate.parse_smrib_json(str(SMRIB_JSON))
    return {ip: set(data.get("smrib_ports", [])) for ip, data in results.items()}


def run_nmap_discovery(
    targets: Sequence[str],
    port_selection: PortSelection,
    use_sudo: bool,
) -> Mapping[str, Set[int]]:
    if not shutil.which("nmap"):
        print("[!] nmap not installed – unable to perform discovery stage.")
        return {}

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
        run_command(prefix_command(cmd, use_sudo), description=f"Nmap discovery scan for {target} ({port_selection.description})")

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
    fallback_range: Optional[str],
) -> Dict[str, Optional[Set[int]]]:
    merged: Dict[str, Optional[Set[int]]] = {}

    for result in (masscan_results, smrib_results, nmap_results):
        for ip, ports in result.items():
            merged.setdefault(ip, set()).update(ports)

    if not merged:
        for target in targets:
            merged[target] = None if fallback_range else set()

    for ip, ports in list(merged.items()):
        if ports:
            merged[ip] = set(sorted(ports))
        elif fallback_range:
            merged[ip] = None

    return merged


def run_nmap_fingerprinting(
    hosts: Mapping[str, Optional[Set[int]]],
    fallback_range: Optional[str],
    use_sudo: bool,
) -> None:
    if not shutil.which("nmap"):
        print("[!] nmap is required for the fingerprinting stage; skipping.")
        return

    NMAP_DIR.mkdir(parents=True, exist_ok=True)
    for target, ports in hosts.items():
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
        if ports:
            port_list = ",".join(str(port) for port in sorted(ports))
            cmd.extend(["-p", port_list])
        elif fallback_range:
            cmd.extend(["-p", fallback_range])
        cmd.append(target)
        run_command(prefix_command(cmd, use_sudo), description=f"Nmap fingerprinting for {target}")


def extract_domains_from_nmap() -> Set[str]:
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


def run_harvester(domains: Iterable[str], args: argparse.Namespace) -> None:
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
                "-o",
                f"{prefix}.json",
            ]
            run_command(cmd, description=f"theHarvester OSINT for {domain}")
        else:
            print(f"[!] theHarvester not available – collecting basic DNS data for {domain}")
            host_out = HARVESTER_DIR / f"{domain}.host.txt"
            dig_out = HARVESTER_DIR / f"{domain}.dig.txt"
            with host_out.open("w", encoding="utf-8") as hfile:
                subprocess.run(["host", domain], stdout=hfile, stderr=subprocess.STDOUT)
            with dig_out.open("w", encoding="utf-8") as dfile:
                subprocess.run(["dig", "+short", "any", domain], stdout=dfile, stderr=subprocess.STDOUT)


def aggregate_results() -> None:
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
    run_command(cmd, description="Aggregating scan outputs", check=False)


def collect_http_urls(inventory: List[Mapping[str, object]]) -> List[str]:
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
    if args.skip_eyewitness or not urls:
        return []

    eyewitness_path = shutil.which("eyewitness")
    if not eyewitness_path:
        print("[!] EyeWitness not installed – skipping screenshot capture.")
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
        run_command(cmd, description=f"EyeWitness capture for {url}")
        screenshots.extend(output_dir.rglob("*.png"))

    return screenshots


def load_inventory() -> List[Mapping[str, object]]:
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
    inventory = load_inventory()
    OUT_DIR.mkdir(parents=True, exist_ok=True)

    timestamp = datetime.utcnow().strftime("%Y-%m-%d %H:%M UTC")
    total_hosts = len(inventory)
    total_services = sum(len(entry.get("services", [])) for entry in inventory)

    lines: List[str] = ["# Reconnaissance Report", ""]
    lines.append(f"*Generated*: {timestamp}")
    lines.append(f"*Discovery scanner*: {discovery_description}")
    lines.append(f"*Targets*: {', '.join(targets)}")
    lines.append(f"*Hosts in inventory*: {total_hosts}")
    lines.append(f"*Total services recorded*: {total_services}")
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
            port_list = "(fallback range)"
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
    print(f"[+] Wrote report to {REPORT_PATH}")


def main(argv: Optional[Sequence[str]] = None) -> None:
    args = parse_args(argv)
    port_selection = build_port_selection(args)
    targets = load_targets(TARGETS_FILE)

    OUT_DIR.mkdir(parents=True, exist_ok=True)
    for path in (DISCOVERY_DIR, NMAP_DIR, HARVESTER_DIR, EYEWITNESS_DIR):
        path.mkdir(parents=True, exist_ok=True)

    discovery_description = f"{args.scanner} ({port_selection.description})"
    masscan_results: Mapping[str, Set[int]] = {}
    smrib_results: Mapping[str, Set[int]] = {}
    nmap_results: Mapping[str, Set[int]] = {}

    if args.scanner == "masscan":
        masscan_results = run_masscan(targets, port_selection, args.masscan_rate, args.sudo)
    elif args.scanner == "smrib":
        smrib_results = run_smrib(targets, port_selection, args.smrib_path, args.smrib_extra, args.sudo)
    else:
        nmap_results = run_nmap_discovery(targets, port_selection, args.sudo)

    discovered_hosts = merge_discovered_hosts(
        targets,
        masscan_results,
        smrib_results,
        nmap_results,
        port_selection.fallback_range,
    )

    run_nmap_fingerprinting(discovered_hosts, port_selection.fallback_range, args.sudo)

    domains = extract_domains_from_nmap()
    if domains:
        run_harvester(domains, args)
    else:
        print("[!] No domains discovered in Nmap XML – skipping theHarvester stage.")

    aggregate_results()

    inventory = load_inventory()
    urls = collect_http_urls(inventory)
    screenshots = run_eyewitness(urls, args)

    write_report(args, targets, discovery_description, discovered_hosts, screenshots)

    print(f"[+] Recon workflow completed. Inventory: {INVENTORY_JSON}, CSV: {INVENTORY_CSV}")


if __name__ == "__main__":
    main()
