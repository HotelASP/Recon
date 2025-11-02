# Recon

`Recon` is an automation wrapper that glues together common network-reconnaissance
steps. The entry point, [`run_recon.py`](./run_recon.py), walks through discovery
scans, detailed Nmap fingerprinting, optional OSINT collection with theHarvester,
and screenshot capture with EyeWitness before aggregating everything into a single
inventory and Markdown report.

## Overview

- Automates a complete reconnaissance run: discovery, fingerprinting, OSINT, and
  reporting.
- Normalises results from Masscan, Nmap, smrib, and theHarvester into a single
  inventory (`inventory.json`/`inventory.csv`).
- Captures HTTP(S) screenshots with EyeWitness for rapid visual triage.
- Generates an opinionated Markdown report that highlights the discovered hosts,
  associated domains, and OSINT artefacts.

## Quick Start

1. Populate [`targets.txt`](./targets.txt) with hosts or networks to probe
   (see [Targets](#targets)).
2. Install the tools listed below and ensure they are on `PATH`.
3. Execute a reconnaissance run:

   ```bash
   python3 run_recon.py --scanner masscan --top-ports 200
   ```

   The command wipes `out/` (unless `--preserve-output` is set), performs a fast
   Masscan sweep of the top 200 ports, fingerprints the responsive services with
   Nmap, runs theHarvester for OSINT, and collates everything into
   `out/report/`.

## Prerequisites

The Python script shells out to several third-party tools. Install whichever
components you intend to use and make sure they are discoverable in `PATH`:

- [`masscan`](https://github.com/robertdavidgraham/masscan) for fast discovery
  scans.
- [`nmap`](https://nmap.org/) for both discovery (if selected) and the required
  fingerprinting stage.
- [`theHarvester`](https://github.com/laramies/theHarvester) for OSINT lookups.
- [`EyeWitness`](https://github.com/ChrisTruncer/EyeWitness) for HTTP
  screenshots.
- [`smrib.py`](https://github.com/dievus/smrib) if you prefer that script for
  the discovery pass.

Python 3.8+ is recommended. The included [`tools/aggregate.py`](./tools/aggregate.py)
module performs the final data merge and is invoked automatically.

## Targets

Populate [`targets.txt`](./targets.txt) with one host, IP address, or network per
line. Blank lines and comments starting with `#` are ignored. Inline annotations
such as `example.com # staging box` are supported—the portion after `#` is
discarded before the target list is processed. The script aborts if no valid
targets are present.

Each entry may optionally include a comma-separated list of TCP ports after a
space (for example `example.com 80,443`). When ports are provided, discovery and
fingerprinting focus exclusively on that list for the corresponding host. Leave
the port list empty to fall back to the global CLI options (`--ports`,
`--top-ports`, or `--port-range`).

## Usage

```bash
python3 run_recon.py [options]
```

### Example Workflows

- **Full TCP sweep with Nmap only** – useful when Masscan is unavailable or
  firewall policies block SYN scans:

  ```bash
  python3 run_recon.py --scanner nmap --port-range 1-65535 --skip-eyewitness
  ```

- **Iterative OSINT enrichment** – discover additional domains via theHarvester
  and feed them back into Nmap automatically:

  ```bash
  python3 run_recon.py \
    --scanner smrib \
    --targets-file targets.txt \
    --search-related-data \
    --harvester-sources 'crtsh,bing'
  ```

- **Follow-up run against newly observed services** – export the refreshed
  target list and run a narrower scan:

  ```bash
  python3 run_recon.py --targets-new-export --ports 80,443,8443
  python3 run_recon.py --targets-file targets_new.txt --scanner masscan
  ```

| Option | Description |
| --- | --- |
| `--scanner {masscan,smrib,nmap}` | Selects the discovery stage implementation (default: `masscan`). |
| `--top-ports N` | Scans only the top `N` ports for discovery (mutually exclusive with `--port-range` and `--ports`). |
| `--port-range RANGE` | Explicit port range or comma-separated list, e.g. `1-1024,3389`. Overrides `--top-ports` and is mutually exclusive with `--ports`. |
| `--ports LIST` | Comma-separated list of TCP ports to scan and fingerprint (overrides discovery results and disables other port selectors). |
| `--masscan-rate RATE` | Packet rate for Masscan when it is the chosen scanner (default: `1000`). |
| `--masscan-status-interval SECONDS` | Seconds between Masscan status updates (use `0` to silence the progress lines). |
| `--smrib-path PATH` | Filesystem location of `smrib.py` (default: `$SMRIB_PATH` env var or `~/Desktop/RT/smrib.py`). |
| `--smrib-extra ...` | Additional arguments appended to the `smrib.py` command. Everything after this flag is forwarded. |
| `--harvester-sources SOURCES` | Comma-separated data sources for theHarvester (default: `all`). |
| `--harvester-source SOURCE` | Repeatable flag to list individual theHarvester sources (overrides `--harvester-sources`). |
| `--harvester-limit N` | Result limit per source for theHarvester queries (default: `500`). |
| `--skip-eyewitness` | Skip the EyeWitness screenshot stage entirely. |
| `--eyewitness-timeout SECONDS` | HTTP request timeout used by EyeWitness (default: `10`). |
| `--eyewitness-threads N` | Number of parallel EyeWitness browser threads (default: `4`). |
| `--preserve-output` | Skip the automatic cleanup of `out/` so previous artefacts remain available. |
| `--targets-new-export` | Write all discovered hosts/domains and their ports to `targets_new.txt` for reuse. |
| `--sudo` | Prefix scanner commands with `sudo` when the binary is available. |

Passing more than one of `--top-ports`, `--port-range`, or `--ports` results in
an error. When none is supplied, the script scans the top 100 ports.

## Workflow

1. **Discovery scan** – Runs Masscan, `smrib.py`, or Nmap (depending on
   `--scanner`) to enumerate open ports. If the selected tool is missing, the
   stage is skipped gracefully.
2. **Nmap fingerprinting** – Executes service, version, and OS detection against
   the discovered host/port pairs. If discovery found nothing, Nmap falls back to
   the requested port range.
3. **OSINT (optional)** – Extracts domains from Nmap XML and queries
   theHarvester. When theHarvester is unavailable, the script records basic `host`
   and `dig` output instead.
4. **Aggregation** – Invokes [`tools/aggregate.py`](./tools/aggregate.py) to
   consolidate Nmap, Masscan, smrib, and theHarvester artefacts into structured
   JSON/CSV files.
5. **EyeWitness (optional)** – Builds a list of detected HTTP/HTTPS services and
   captures screenshots in headless mode unless `--skip-eyewitness` is supplied
   or EyeWitness is missing.
6. **Reporting** – Generates `out/report/report.md` with a structured host and
   domain breakdown, summarises the run, and embeds any screenshots.

## Output Layout

All artefacts live under [`out/`](./out) (created on demand). The directory is
now tracked by Git so results from previous runs can be versioned or shared when
that context is useful:

- `out/discovery/` – Raw discovery outputs when Nmap is used for stage one.
- `out/nmap/` – Nmap XML/normal/grepable files for the fingerprinting stage.
- `out/harvester/` – theHarvester JSON/HTML exports or fallback DNS lookups.
- `out/eyewitness/` – Screenshot directories produced by EyeWitness.
- `out/masscan/` – JSON exports created by Masscan (for example `masscan.json`).
- `out/smrib/` – JSON exports produced by `smrib.py`.
- `out/report/` – Aggregated inventory (`inventory.json`/`inventory.csv`) and the
  Markdown report (`report.md`).
- `out/log/` – `recon.log` capturing a transcript of the workflow.
- `targets_related_not_processed.txt` – Domains/hosts discovered during OSINT
  that were intentionally skipped to avoid scanning infrastructure outside the
  defined scope.

The script wipes the directories at the start of each run to avoid mixing
artefacts from different sessions. Use `--preserve-output` if you prefer to keep
older data (be aware that aggregation will then include historic results).

## Tips

- Use `--sudo` when the selected scanner requires elevated privileges for raw
  sockets.
- Tune `--masscan-rate` to match network capacity and avoid packet loss.
- Provide additional arguments to `smrib.py` via `--smrib-extra`, for example to
  change logging verbosity or output flags.
- EyeWitness can be time-consuming. Disable it with `--skip-eyewitness` when you
  only need the textual inventory.
- Review `targets_related_not_processed.txt` after runs that enable
  `--search-related-data` to see which related assets were skipped because they
  fell outside the permitted scope.

Happy scanning!
