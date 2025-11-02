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
   `out/report/`. When `--scanner smrib` is selected (the default),
   [`run_recon.py`](./run_recon.py) automatically downloads the upstream
   `smrib.py` helper from GitHub into `scanner/`. If that download fails, the
   workflow emits a warning and transparently falls back to Nmap for the
   discovery pass so the run can continue.

## Prerequisites

The Python script shells out to several third-party tools. Install whichever
components you intend to use and make sure they are discoverable in `PATH`:

- [`masscan`] for fast discovery
  scans.
- [`nmap`] for both discovery (if selected) and the required
  fingerprinting stage.
- [`theHarvester`] for OSINT lookups.
- [`EyeWitness`] for HTTP
  screenshots.
- [`smrib.py`] for the discovery pass (retrieved automatically when you rely on
  the default scanner).

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

By default the discovery stage starts with `smrib.py`. The script downloads the
HotelASP/Scanner repository on-demand into `scanner/` the first time it is
needed and reuses that cached copy on subsequent runs. smrib is invoked with
`--show-only-open` so its JSON output contains only confirmed open ports,
avoiding noise when the results are merged later. If the download cannot be
completed, the tool notifies you and automatically switches the discovery stage
to Nmap—mirroring what you would achieve manually with `--scanner nmap`.

### Getting Help

```bash
python3 run_recon.py --help
python3 run_recon.py --?
```

Both switches print the same detailed usage summary.

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

### Command-line Options

| Option | Description | Example |
| --- | --- | --- |
| `-h`, `--help`, `--?` | Show the built-in help text and exit. | `python3 run_recon.py --help` |
| `--scanner {masscan,smrib,nmap}` | Select the discovery stage implementation (default: `smrib`). | `python3 run_recon.py --scanner nmap` |
| `--top-ports N` | Scan only the top `N` ports (mutually exclusive with `--port-range`/`--ports`). | `--top-ports 200` |
| `--port-range RANGE` | Explicit port range or comma-separated list (overrides `--top-ports`). | `--port-range 1-1024,3389` |
| `--ports LIST` | Comma-separated list of TCP ports to probe and fingerprint (bypasses discovery results). | `--ports 80,443,8443` |
| `--masscan-rate RATE` | Packet rate for Masscan scans (default: `1000`). | `--masscan-rate 5000` |
| `--masscan-status-interval SECONDS` | Seconds between Masscan status updates (`0` silences progress). | `--masscan-status-interval 5` |
| `--smrib-path PATH` | Filesystem location of `smrib.py` (default: `./scanner/smrib.py` or `$SMRIB_PATH`). | `--smrib-path ~/tools/smrib.py` |
| `--smrib-parameters ...` | Extra arguments forwarded verbatim to `smrib.py` (everything after the flag is passed through). | `--smrib-parameters -- --timeout 3 --delay 0.5` |
| `--harvester-sources SOURCES` | Comma-separated list of theHarvester backends (default: `all`). | `--harvester-sources crtsh,bing` |
| `--harvester-source SOURCE` | Repeatable alternative to `--harvester-sources` for per-source control. | `--harvester-source crtsh --harvester-source urlscan` |
| `--harvester-limit N` | Result limit per source for theHarvester queries (default: `500`). | `--harvester-limit 150` |
| `--search-related-data` | Re-query Nmap and theHarvester for newly discovered hosts/domains (up to three rounds). | `--search-related-data` |
| `--skip-eyewitness` | Skip the EyeWitness screenshot stage entirely. | `--skip-eyewitness` |
| `--eyewitness-timeout SECONDS` | HTTP timeout for EyeWitness requests (default: `10`). | `--eyewitness-timeout 20` |
| `--eyewitness-threads N` | Number of parallel EyeWitness browser threads (default: `4`). | `--eyewitness-threads 8` |
| `--preserve-output` | Keep existing files under `out/` instead of wiping them at the start of a run. | `--preserve-output` |
| `--sudo` | Prefix scanner commands with `sudo` when the binary is available. | `--sudo` |
| `--targets TARGET [TARGET ...]` | Inline targets (hostnames, IPs, or CIDR ranges). Entries accept comma-separated values and the flag is repeatable. | `--targets 10.0.0.0/24,db.local` |
| `--targets-file FILE` | Load additional targets from a file (one per line). | `--targets-file scope.txt` |
| `--targets-new-export` | Write discovered hosts/domains and ports to `targets_new.txt` for follow-up runs. | `--targets-new-export` |
| `--silent` | Display only essential status messages (full output still lands in `out/log/recon.log`). | `--silent` |

### Targeted Option Examples

- Tune Masscan's cadence and status output:

  ```bash
  python3 run_recon.py --scanner masscan --top-ports 100 --masscan-rate 7500 --masscan-status-interval 10 --targets 192.0.2.0/24
  ```

- Run the default smrib workflow with a custom executable and extra parameters:

  ```bash
  python3 run_recon.py --scanner smrib --smrib-path ~/tools/smrib.py --smrib-parameters -- --timeout 5 --delay 0.25 --targets example.com
  ```

- Focus theHarvester on explicit sources with a tighter result limit while looping through related data:

  ```bash
  python3 run_recon.py --harvester-source crtsh --harvester-source urlscan --harvester-limit 200 --search-related-data --targets-file domains.txt
  ```

- Capture more EyeWitness screenshots while keeping previous artefacts on disk:

  ```bash
  python3 run_recon.py --eyewitness-timeout 20 --eyewitness-threads 8 --preserve-output --targets staging.example.com --ports 80,443
  ```

- Operate quietly with elevated privileges while combining inline and file-based target definitions:

  ```bash
  python3 run_recon.py --sudo --silent --targets prod.example.com,db.internal --targets-file scope.txt --targets-new-export
  ```

Passing more than one of `--top-ports`, `--port-range`, or `--ports` results in
an error. When none is supplied, the script scans the top 100 ports.

## Workflow

1. **Discovery scan** – Runs `smrib.py`, Masscan, or Nmap (depending on
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
- Provide additional arguments to `smrib.py` via `--smrib-parameters`, for example to
  change logging verbosity or output flags.
- EyeWitness can be time-consuming. Disable it with `--skip-eyewitness` when you
  only need the textual inventory.
- Review `targets_related_not_processed.txt` after runs that enable
  `--search-related-data` to see which related assets were skipped because they
  fell outside the permitted scope.

Happy scanning!
