# Reconnaissance Report

*Generated*: 2025-11-01 14:16 UTC
*Discovery scanner*: masscan (top 100 ports)
*Targets*: hackthissite.org
*Hosts in inventory*: 5
*Total services recorded*: 7

## Target Scope
1. hackthissite.org

## Tool Activities
- **Masscan**: Masscan performs a high-speed TCP SYN sweep to quickly spot responsive hosts and their open ports. It favours breadth and speed, trading some accuracy for rapid coverage of large target lists.
- **Nmap**: Nmap is used twice: optionally for discovery and always for in-depth fingerprinting. During fingerprinting it runs default scripts, probes service banners, and attempts OS detection to build a rich host profile.
- **theHarvester**: theHarvester enriches the scan by querying OSINT sources for subdomains, hostnames, and related infrastructure connected to discovered domains.
- **EyeWitness**: EyeWitness drives a headless browser against detected HTTP(S) services to capture screenshots, providing a quick visual triage of exposed web interfaces.

## Host Overview
- **137.74.187.100** – Hostnames: hackthissite.org; Ports: 80, 443; OS: Oracle Virtualbox Slirp NAT bridge
- **137.74.187.103** – Hostnames: hackthissite.org; Ports: 443; OS: Oracle Virtualbox Slirp NAT bridge
- **137.74.187.101** – Hostnames: hackthissite.org; Ports: 80; OS: Oracle Virtualbox Slirp NAT bridge
- **137.74.187.102** – Hostnames: hackthissite.org; Ports: 80; OS: Oracle Virtualbox Slirp NAT bridge
- **137.74.187.104** – Hostnames: hackthissite.org; Ports: 80; OS: Oracle Virtualbox Slirp NAT bridge

## Discovery Summary
- 137.74.187.102: 80
- 137.74.187.104: 80
- 137.74.187.103: 443
- 137.74.187.100: 80
- 137.74.187.101: 80

## Screenshots
No screenshots captured (EyeWitness unavailable or no HTTP services detected).