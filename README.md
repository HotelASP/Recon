# Recon

Automation wrapper for running reconnaissance scans and consolidating the
results. The workflow is orchestrated by `run_recon.sh`, which coordinates port
scans, optional discovery with masscan, information gathering with
theHarvester, and aggregation via `tools/aggregate.py`.

## Usage

```
./run_recon.sh [options]
```

Key options:

* `--scanner <smrib|nmap|masscan>` &mdash; select the port scanner to execute.
  The default is the external `smrib.py` scanner located at
  `~/Desktop/RT/smrib.py`. Use `--smrib-path` to override the location if
  needed.
* `--top-ports <n>` &mdash; scan the top `n` ports (default: 200).
* `--port-range <range>` &mdash; specify an explicit port range or comma-separated
  list (for example `1-1024` or `80,443,8080`). When this option is provided it
  replaces `--top-ports`.

Environment variables:

* `MASSCAN_RATE` &mdash; rate for masscan executions (default: 1000).
* `SKIP_MASSCAN` &mdash; set to `1` to skip the discovery masscan stage (default:
  `1`).
* `SMRIB_EXTRA_ARGS` &mdash; extra arguments appended when invoking `smrib.py`.
* `SMRIB_OUTPUT_FLAG` &mdash; flag used to pass the output directory to
  `smrib.py` (default: `--output-dir`). Set it to an empty string to omit the
  argument entirely or to a different flag if the script expects another name.

All scan artefacts are stored under `out/`:

* `out/nmap/` &mdash; Nmap (or smrib) XML outputs used by the aggregator.
* `out/masscan.json` &mdash; JSON export from masscan when enabled.
* `out/harvester/` &mdash; theHarvester outputs.
* `out/inventory.json` and `out/inventory.csv` &mdash; consolidated inventory files.
