# Reconnaissance Report

*Generated*: 2025-11-01 16:58 UTC
*Discovery scanner*: smrib (ports 1-65535)
*Targets*: hackthissite.org
*Hosts in inventory*: 1
*Total services recorded*: 2

## Target Scope
1. hackthissite.org

## Tool Activities
- **Masscan**: Masscan performs a high-speed TCP SYN sweep to quickly spot responsive hosts and their open ports. It favours breadth and speed, trading some accuracy for rapid coverage of large target lists.
- **Nmap**: Nmap is used twice: optionally for discovery and always for in-depth fingerprinting. During fingerprinting it runs default scripts, probes service banners, and attempts OS detection to build a rich host profile.
- **theHarvester**: theHarvester enriches the scan by querying OSINT sources for subdomains, hostnames, and related infrastructure connected to discovered domains.
- **EyeWitness**: EyeWitness drives a headless browser against detected HTTP(S) services to capture screenshots, providing a quick visual triage of exposed web interfaces.

## Host Overview
- **137.74.187.102** – Hostnames: hackthissite.org; Ports: 80, 443; OS: 3Com 4500G switch

## Discovery Summary
- 137.74.187.102: 80, 443

## Screenshots
No screenshots captured (EyeWitness unavailable or no HTTP services detected).