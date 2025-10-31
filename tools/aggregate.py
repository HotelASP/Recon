#!/usr/bin/env python3
import argparse, json, os, csv
import xml.etree.ElementTree as ET

def parse_masscan_json(path):
    if not os.path.exists(path) or os.path.getsize(path) == 0:
        return {}
    try:
        with open(path, 'r', encoding='utf-8') as f:
            mass = json.load(f)
    except Exception:
        return {}
    hosts = {}
    if isinstance(mass, list):
        for entry in mass:
            ip = entry.get('ip')
            if not ip: continue
            ports = [p.get('port') for p in entry.get('ports', []) if 'port' in p]
            hosts[ip] = {'masscan_ports': sorted(set([int(p) for p in ports if isinstance(p, int) or str(p).isdigit()]))}
    return hosts

def parse_nmap_dir(nmap_dir):
    inventory = {}
    if not os.path.isdir(nmap_dir):
        return inventory
    for fname in os.listdir(nmap_dir):
        if not fname.endswith('.xml'): continue
        xml_file = os.path.join(nmap_dir, fname)
        try:
            root = ET.parse(xml_file).getroot()
        except Exception:
            continue
        for host in root.findall('host'):
            addr = None
            for a in host.findall('address'):
                if a.get('addrtype') in ('ipv4','ipv6'):
                    addr = a.get('addr'); break
            if not addr:
                addrs = host.findall('address')
                if addrs: addr = addrs[0].get('addr')
            if not addr: continue
            info = inventory.setdefault(addr, {'nmap_ports': [], 'hostnames': [], 'os': None})
            for h in host.findall('hostnames/hostname'):
                name = h.get('name')
                if name and name not in info['hostnames']: info['hostnames'].append(name)
            osnode = host.find('os/osmatch')
            if osnode is not None and not info.get('os'): info['os'] = osnode.get('name')
            for p in host.findall('ports/port'):
                portnum = int(p.get('portid'))
                proto = p.get('protocol')
                state_el = p.find('state'); state = state_el.get('state') if state_el is not None else None
                svc = p.find('service')
                svcname = svc.get('name') if svc is not None else None
                version = None
                if svc is not None:
                    parts = [svc.get(k) for k in ('product','version','extrainfo') if svc.get(k)]
                    if parts: version = ' '.join(parts)
                info['nmap_ports'].append({'port': portnum,'proto': proto,'state': state,'service': svcname,'version': version})
    return inventory

def parse_harvester_dir(harv_dir):
    mapping = {}
    if not os.path.isdir(harv_dir): return mapping
    for fname in os.listdir(harv_dir):
        path = os.path.join(harv_dir, fname)
        if os.path.isdir(path): continue
        domain = fname.split('.')[0]
        hosts = []
        try:
            with open(path, 'r', encoding='utf-8', errors='ignore') as f:
                for line in f:
                    line = line.strip()
                    if '@' in line: continue
                    if '.' in line and len(line) > 5 and ' ' not in line:
                        hosts.append(line)
        except Exception:
            continue
        mapping[domain] = sorted(set(hosts))
    return mapping

def build_inventory(nmap_inv, masscan_inv, harv_map):
    inv = {}
    for ip, data in nmap_inv.items():
        inv[ip] = {
            'ip': ip,
            'open_ports': [p['port'] for p in data.get('nmap_ports', []) if p.get('state') == 'open'],
            'services': [{'port': p['port'], 'service': p.get('service'), 'version': p.get('version')} for p in data.get('nmap_ports', [])],
            'hostnames': data.get('hostnames', []),
            'os': data.get('os')
        }
    for ip, m in masscan_inv.items():
        if ip not in inv:
            inv[ip] = {'ip': ip, 'open_ports': m.get('masscan_ports', []), 'services': [], 'hostnames': [], 'os': None}
        else:
            inv[ip]['open_ports'] = sorted(set(inv[ip].get('open_ports', []) + m.get('masscan_ports', [])))
    for _, hosts in harv_map.items():
        for ip, entry in inv.items():
            for h in hosts:
                if h not in entry['hostnames']:
                    entry['hostnames'].append(h)
    return inv

def export_json(inv, outpath):
    with open(outpath, 'w', encoding='utf-8') as f:
        json.dump(list(inv.values()), f, indent=2)

def export_csv(inv, outpath):
    with open(outpath, 'w', newline='', encoding='utf-8') as f:
        w = csv.writer(f)
        w.writerow(['ip','hostnames','os','open_ports','services'])
        for ip, e in inv.items():
            hostnames = ';'.join(e.get('hostnames', []))
            osname = e.get('os') or ''
            ports = ';'.join(str(p) for p in e.get('open_ports', []))
            services = ';'.join(f"{s.get('port')}:{s.get('service') or ''}:{s.get('version') or ''}" for s in e.get('services', []))
            w.writerow([ip, hostnames, osname, ports, services])

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--nmap-dir', default='out/nmap')
    ap.add_argument('--masscan-json', default='out/masscan.json')
    ap.add_argument('--harv-dir', default='out/harvester')
    ap.add_argument('--out-json', default='out/inventory.json')
    ap.add_argument('--out-csv', default='out/inventory.csv')
    a = ap.parse_args()

    mass = parse_masscan_json(a.masscan_json)
    nmap = parse_nmap_dir(a.nmap_dir)
    harv = parse_harvester_dir(a.harv_dir)

    inv = build_inventory(nmap, mass, harv)
    os.makedirs(os.path.dirname(a.out_json), exist_ok=True)
    export_json(inv, a.out_json)
    export_csv(inv, a.out_csv)
    print(f"Wrote {a.out_json} and {a.out_csv}")

if __name__ == '__main__':
    main()
