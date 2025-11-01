# Reconnaissance Report

*Generated*: 2025-11-01 16:51 UTC
*Discovery scanner*: smrib (ports 1-443)
*Targets*: hotelasp.com
*Hosts in inventory*: 2
*Total services recorded*: 5

## Target Scope
1. hotelasp.com

## Tool Activities
- **Masscan**: Masscan performs a high-speed TCP SYN sweep to quickly spot responsive hosts and their open ports. It favours breadth and speed, trading some accuracy for rapid coverage of large target lists.
- **Nmap**: Nmap is used twice: optionally for discovery and always for in-depth fingerprinting. During fingerprinting it runs default scripts, probes service banners, and attempts OS detection to build a rich host profile.
- **theHarvester**: theHarvester enriches the scan by querying OSINT sources for subdomains, hostnames, and related infrastructure connected to discovered domains.
- **EyeWitness**: EyeWitness drives a headless browser against detected HTTP(S) services to capture screenshots, providing a quick visual triage of exposed web interfaces.

## Host Overview
- **160.153.248.110** – Hostnames: 110.248.153.160.host.secureserver.net; Ports: 21, 80, 443; OS: Oracle Virtualbox Slirp NAT bridge
- **192.124.249.38** – Hostnames: cloudproxy10038.sucuri.net; Ports: 80, 443; OS: Nokia 3600i mobile phone

## Discovery Summary
- 160.153.248.110: 21, 80, 443
- 192.124.249.38: 80, 443

## Screenshots
No screenshots captured (EyeWitness unavailable or no HTTP services detected).