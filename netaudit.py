#!/usr/bin/env python3
"""
netaudit - lightweight network discovery and audit tool.

Sweeps an IPv4 subnet, identifies live hosts, resolves hostnames, pulls MAC
addresses from the local ARP cache, maps the MAC OUI to a vendor, scans common
TCP service ports, and writes CSV / HTML / JSON reports.

Can also save a baseline snapshot and diff future scans against it to flag new
devices, missing devices, changed MAC addresses, and newly opened ports.

Pure Python standard library. No pip installs, runs on Windows / macOS / Linux.

Usage:
    python netaudit.py 192.168.1.0/24
    python netaudit.py 192.168.1.0/24 --ports quick --out home-scan
    python netaudit.py 192.168.1.0/24 --baseline baseline.json
    python netaudit.py 192.168.1.0/24 --baseline baseline.json --update-baseline

Only scan networks you own or are authorized to scan.
"""

import argparse
import concurrent.futures
import csv
import html
import ipaddress
import json
import os
import platform
import re
import socket
import subprocess
import sys
from datetime import datetime

__version__ = "1.1.0"

# ---------------------------------------------------------------------------
# Reference data
# ---------------------------------------------------------------------------

PORT_SETS = {
    "quick": {22: "SSH", 80: "HTTP", 443: "HTTPS", 445: "SMB", 3389: "RDP"},
    "common": {
        21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP", 53: "DNS",
        80: "HTTP", 110: "POP3", 135: "MSRPC", 139: "NetBIOS", 143: "IMAP",
        443: "HTTPS", 445: "SMB", 515: "LPD", 631: "IPP", 993: "IMAPS",
        1433: "MSSQL", 3306: "MySQL", 3389: "RDP", 5432: "PostgreSQL",
        5900: "VNC", 8080: "HTTP-Alt", 8443: "HTTPS-Alt", 9100: "JetDirect",
    },
}

# Partial IEEE OUI table. Extend from http://standards-oui.ieee.org/oui/oui.csv
OUI_VENDORS = {
    "000C29": "VMware", "005056": "VMware", "080027": "VirtualBox",
    "525400": "QEMU/KVM", "001C42": "Parallels",
    "00000C": "Cisco", "001B54": "Cisco", "F866F2": "Cisco",
    "00180A": "Cisco Meraki", "00259C": "Cisco-Linksys", "001D7E": "Cisco-Linksys",
    "24A43C": "Ubiquiti", "788A20": "Ubiquiti", "FCECDA": "Ubiquiti",
    "00146C": "Netgear", "20E52A": "Netgear", "A040A0": "Netgear",
    "F81A67": "TP-Link", "50C7BF": "TP-Link", "A42BB0": "TP-Link",
    "00179A": "D-Link", "1CBDB9": "D-Link",
    "AC220B": "ASUSTek", "1C872C": "ASUSTek", "9C5C8E": "ASUSTek",
    "B827EB": "Raspberry Pi", "DCA632": "Raspberry Pi", "E45F01": "Raspberry Pi",
    "246F28": "Espressif", "3C71BF": "Espressif", "A4CF12": "Espressif",
    "001451": "Apple", "6C4008": "Apple", "ACBC32": "Apple", "D0817A": "Apple",
    "001B21": "Intel", "A0369F": "Intel", "94659C": "Intel",
    "B8CA3A": "Dell", "00188B": "Dell", "F8BC12": "Dell",
    "001B78": "HP", "3C4A92": "HP", "9457A5": "HP",
    "0017FA": "Microsoft", "7CED8D": "Microsoft",
    "5CE8EB": "Samsung", "8C7712": "Samsung", "F408D5": "Samsung",
    "747548": "Amazon", "44650D": "Amazon", "F0272D": "Amazon",
    "B0A737": "Roku", "CC6DA0": "Roku", "000E58": "Sonos",
    "001A11": "Google", "F4F5D8": "Google", "3C5AB4": "Google",
    "00005E": "IANA (VRRP/HSRP)",
}

IS_WINDOWS = platform.system().lower().startswith("win")
IS_MAC = platform.system().lower() == "darwin"

MAC_RE = re.compile(r"(?:[0-9a-fA-F]{2}[:-]){5}[0-9a-fA-F]{2}")
IP_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")


# ---------------------------------------------------------------------------
# Discovery
# ---------------------------------------------------------------------------

def ping(ip, timeout_ms=800):
    """Return True if the host answers a single ICMP echo request."""
    if IS_WINDOWS:
        cmd = ["ping", "-n", "1", "-w", str(timeout_ms), ip]
    elif IS_MAC:
        cmd = ["ping", "-c", "1", "-W", str(timeout_ms), ip]
    else:
        cmd = ["ping", "-c", "1", "-W", str(max(1, timeout_ms // 1000)), ip]
    try:
        result = subprocess.run(
            cmd,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            timeout=(timeout_ms / 1000) + 2,
        )
        return result.returncode == 0
    except (subprocess.TimeoutExpired, OSError):
        return False


def tcp_probe(ip, port, timeout=0.6):
    """Fallback liveness check + port scan primitive."""
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.settimeout(timeout)
            return sock.connect_ex((ip, port)) == 0
    except OSError:
        return False


def resolve_hostname(ip):
    try:
        return socket.gethostbyaddr(ip)[0]
    except (socket.herror, socket.gaierror, OSError):
        return ""


def load_arp_table():
    """Parse the local ARP cache into {ip: mac}.

    Run this AFTER the ping sweep -- the sweep is what populates the cache.
    """
    table = {}
    try:
        out = subprocess.run(
            ["arp", "-a"],
            capture_output=True,
            text=True,
            timeout=15,
        ).stdout
    except (OSError, subprocess.TimeoutExpired):
        return table

    for line in out.splitlines():
        ip_match = IP_RE.search(line)
        mac_match = MAC_RE.search(line)
        if ip_match and mac_match:
            table[ip_match.group(0)] = mac_match.group(0).lower().replace("-", ":")
    return table


def lookup_vendor(mac):
    if not mac:
        return ""
    oui = re.sub(r"[^0-9A-Fa-f]", "", mac)[:6].upper()
    return OUI_VENDORS.get(oui, "")


def scan_ports(ip, ports, timeout=0.6):
    open_ports = []
    if not ports:
        return open_ports
    with concurrent.futures.ThreadPoolExecutor(max_workers=min(len(ports), 32)) as pool:
        futures = {pool.submit(tcp_probe, ip, p, timeout): p for p in ports}
        for future in concurrent.futures.as_completed(futures):
            if future.result():
                open_ports.append(futures[future])
    return sorted(open_ports)


def discover(network, ports, workers=64, timeout_ms=800, port_timeout=0.6, verbose=True):
    """Sweep the network and return a sorted list of live-host dicts."""
    net = ipaddress.ip_network(network, strict=False)
    targets = [str(h) for h in net.hosts()] or [str(net.network_address)]

    if verbose:
        print(f"[*] Sweeping {net} ({len(targets)} addresses) ...", flush=True)

    live = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=workers) as pool:
        futures = {pool.submit(ping, ip, timeout_ms): ip for ip in targets}
        for future in concurrent.futures.as_completed(futures):
            if future.result():
                live.append(futures[future])

    # Hosts that block ICMP but answer TCP still count as live.
    if ports:
        silent = [ip for ip in targets if ip not in live]
        ranked = [p for p in (443, 80, 22, 445, 3389) if p in ports]
        ranked += [p for p in sorted(ports) if p not in ranked]
        probe_ports = ranked[:4]
        with concurrent.futures.ThreadPoolExecutor(max_workers=workers) as pool:
            futures = {
                pool.submit(tcp_probe, ip, port, 0.4): ip
                for ip in silent for port in probe_ports
            }
            for future in concurrent.futures.as_completed(futures):
                if future.result():
                    live.append(futures[future])

    live = sorted(set(live), key=lambda x: ipaddress.ip_address(x))
    if verbose:
        print(f"[*] {len(live)} live host(s). Collecting details ...", flush=True)

    arp = load_arp_table()
    hosts = []
    for ip in live:
        mac = arp.get(ip, "")
        open_ports = scan_ports(ip, ports, port_timeout)
        hosts.append({
            "ip": ip,
            "hostname": resolve_hostname(ip),
            "mac": mac,
            "vendor": lookup_vendor(mac),
            "open_ports": open_ports,
            "services": [ports.get(p, "?") for p in open_ports] if ports else [],
        })
        if verbose:
            label = hosts[-1]["hostname"] or hosts[-1]["vendor"] or "unknown"
            print(f"    {ip:<16} {label:<28} {open_ports}", flush=True)
    return hosts


# ---------------------------------------------------------------------------
# Baseline comparison
# ---------------------------------------------------------------------------

def compare_to_baseline(hosts, baseline):
    """Return a dict describing what changed since the baseline snapshot."""
    old = {h["ip"]: h for h in baseline.get("hosts", [])}
    new = {h["ip"]: h for h in hosts}

    changes = {
        "new_hosts": [],
        "missing_hosts": [],
        "mac_changed": [],
        "new_ports": [],
    }

    for ip, host in new.items():
        if ip not in old:
            changes["new_hosts"].append(host)
            continue
        prev = old[ip]
        if host["mac"] and prev.get("mac") and host["mac"] != prev["mac"]:
            changes["mac_changed"].append({
                "ip": ip, "was": prev["mac"], "now": host["mac"],
            })
        added = sorted(set(host["open_ports"]) - set(prev.get("open_ports", [])))
        if added:
            changes["new_ports"].append({"ip": ip, "ports": added})

    for ip, host in old.items():
        if ip not in new:
            changes["missing_hosts"].append(host)

    return changes


def print_changes(changes):
    total = sum(len(v) for v in changes.values())
    print("\n=== Changes since baseline ===")
    if total == 0:
        print("    No changes detected.")
        return
    for host in changes["new_hosts"]:
        print(f"    [NEW]     {host['ip']:<16} {host['mac'] or '-':<18} "
              f"{host['vendor'] or host['hostname'] or ''}")
    for host in changes["missing_hosts"]:
        print(f"    [MISSING] {host['ip']:<16} {host.get('mac') or '-'}")
    for item in changes["mac_changed"]:
        print(f"    [MAC]     {item['ip']:<16} {item['was']} -> {item['now']}")
    for item in changes["new_ports"]:
        print(f"    [PORTS]   {item['ip']:<16} newly open: {item['ports']}")


# ---------------------------------------------------------------------------
# Reporting
# ---------------------------------------------------------------------------

def write_csv(path, hosts):
    with open(path, "w", newline="", encoding="utf-8") as fh:
        writer = csv.writer(fh)
        writer.writerow(["IP", "Hostname", "MAC", "Vendor", "Open Ports", "Services"])
        for h in hosts:
            writer.writerow([
                h["ip"],
                h["hostname"],
                h["mac"],
                h["vendor"],
                " ".join(str(p) for p in h["open_ports"]),
                " ".join(h["services"]),
            ])


def write_json(path, payload):
    with open(path, "w", encoding="utf-8") as fh:
        json.dump(payload, fh, indent=2)


def write_html(path, payload, changes=None):
    esc = html.escape
    meta = payload["scan"]
    rows = []
    for h in payload["hosts"]:
        port_cells = ", ".join(
            f"{p}/{s}" for p, s in zip(h["open_ports"], h["services"])
        ) or "&mdash;"
        rows.append(
            "<tr>"
            f"<td class='mono'>{esc(h['ip'])}</td>"
            f"<td>{esc(h['hostname']) or '&mdash;'}</td>"
            f"<td class='mono'>{esc(h['mac']) or '&mdash;'}</td>"
            f"<td>{esc(h['vendor']) or '&mdash;'}</td>"
            f"<td class='mono'>{port_cells}</td>"
            "</tr>"
        )

    change_html = ""
    if changes is not None:
        items = []
        for host in changes["new_hosts"]:
            items.append(f"<li><b class='new'>NEW</b> {esc(host['ip'])} "
                         f"{esc(host['vendor'] or host['hostname'] or '')}</li>")
        for host in changes["missing_hosts"]:
            items.append(f"<li><b class='gone'>MISSING</b> {esc(host['ip'])}</li>")
        for item in changes["mac_changed"]:
            items.append(f"<li><b class='warn'>MAC CHANGED</b> {esc(item['ip'])}: "
                         f"{esc(item['was'])} &rarr; {esc(item['now'])}</li>")
        for item in changes["new_ports"]:
            items.append(f"<li><b class='warn'>NEW PORTS</b> {esc(item['ip'])}: "
                         f"{esc(str(item['ports']))}</li>")
        body = "<ul>" + "".join(items) + "</ul>" if items else \
            "<p class='ok'>No changes detected since baseline.</p>"
        change_html = f"<h2>Changes since baseline</h2>{body}"

    doc = f"""<!DOCTYPE html>
<html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>netaudit report - {esc(meta['network'])}</title>
<style>
  :root {{ --bg:#ffffff; --fg:#1b1b1b; --muted:#666; --line:#e2e2e2; --accent:#0b5fff; }}
  @media (prefers-color-scheme: dark) {{
    :root {{ --bg:#15171a; --fg:#e8e8e8; --muted:#9aa0a6; --line:#2c3035; --accent:#6ea8ff; }}
  }}
  body {{ margin:0; padding:2rem 1.25rem; background:var(--bg); color:var(--fg);
         font-family:system-ui,-apple-system,Segoe UI,Roboto,sans-serif; line-height:1.5; }}
  .wrap {{ max-width:1000px; margin:0 auto; }}
  h1 {{ font-size:1.5rem; margin:0 0 .25rem; }}
  h2 {{ font-size:1.1rem; margin:2rem 0 .5rem; }}
  .meta {{ color:var(--muted); font-size:.875rem; margin-bottom:1.5rem; }}
  .stats {{ display:flex; gap:1.5rem; flex-wrap:wrap; margin-bottom:1.5rem; }}
  .stat {{ border:1px solid var(--line); border-radius:8px; padding:.6rem 1rem; }}
  .stat b {{ display:block; font-size:1.35rem; color:var(--accent); }}
  .stat span {{ font-size:.75rem; color:var(--muted); text-transform:uppercase; }}
  .scroll {{ overflow-x:auto; }}
  table {{ border-collapse:collapse; width:100%; font-size:.9rem; }}
  th, td {{ text-align:left; padding:.5rem .6rem; border-bottom:1px solid var(--line); }}
  th {{ font-size:.75rem; text-transform:uppercase; color:var(--muted); }}
  .mono {{ font-family:ui-monospace,SFMono-Regular,Consolas,monospace; font-size:.85rem; }}
  ul {{ padding-left:1.1rem; }}
  li {{ margin:.25rem 0; }}
  .new {{ color:#1a7f37; }} .gone {{ color:#8a8a8a; }}
  .warn {{ color:#b35c00; }} .ok {{ color:var(--muted); }}
  footer {{ margin-top:2.5rem; color:var(--muted); font-size:.8rem;
            border-top:1px solid var(--line); padding-top:.75rem; }}
</style></head><body><div class="wrap">
<h1>Network audit report</h1>
<div class="meta">{esc(meta['network'])} &middot; scanned {esc(meta['timestamp'])}
  &middot; {esc(meta['scanner'])}</div>
<div class="stats">
  <div class="stat"><b>{meta['live_hosts']}</b><span>Live hosts</span></div>
  <div class="stat"><b>{meta['addresses_scanned']}</b><span>Addresses scanned</span></div>
  <div class="stat"><b>{meta['open_ports_found']}</b><span>Open ports</span></div>
  <div class="stat"><b>{meta['duration_seconds']}s</b><span>Duration</span></div>
</div>
{change_html}
<h2>Discovered hosts</h2>
<div class="scroll"><table>
<thead><tr><th>IP</th><th>Hostname</th><th>MAC</th><th>Vendor</th><th>Open ports</th></tr></thead>
<tbody>{''.join(rows) or "<tr><td colspan='5'>No hosts responded.</td></tr>"}</tbody>
</table></div>
<footer>Generated by netaudit v{__version__}. MAC addresses are read from the local ARP
cache and are only visible for hosts on the same broadcast domain.</footer>
</div></body></html>"""

    with open(path, "w", encoding="utf-8") as fh:
        fh.write(doc)


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def parse_ports(value):
    if value in PORT_SETS:
        return PORT_SETS[value]
    if value == "none":
        return {}
    ports = {}
    for chunk in value.split(","):
        chunk = chunk.strip()
        if not chunk:
            continue
        if not chunk.isdigit():
            raise argparse.ArgumentTypeError(f"invalid port: {chunk}")
        port = int(chunk)
        ports[port] = PORT_SETS["common"].get(port, "custom")
    return ports


def main(argv=None):
    parser = argparse.ArgumentParser(
        prog="netaudit",
        description="Discover and audit devices on an IPv4 network.",
    )
    parser.add_argument("network", help="target network in CIDR form, e.g. 192.168.1.0/24")
    parser.add_argument("--ports", default="common", type=parse_ports,
                        help="quick | common | none | comma-separated list (default: common)")
    parser.add_argument("--workers", type=int, default=64, help="concurrent ping workers")
    parser.add_argument("--timeout", type=int, default=800, help="ping timeout in ms")
    parser.add_argument("--port-timeout", type=float, default=0.6,
                        help="TCP connect timeout in seconds")
    parser.add_argument("--out", help="output file prefix (default: netaudit_<timestamp>)")
    parser.add_argument("--outdir", default="reports", help="output directory")
    parser.add_argument("--baseline", help="baseline JSON file to compare against")
    parser.add_argument("--update-baseline", action="store_true",
                        help="write this scan to the baseline file after comparing")
    parser.add_argument("--quiet", action="store_true", help="suppress per-host output")
    parser.add_argument("--version", action="version", version=f"netaudit {__version__}")
    args = parser.parse_args(argv)

    try:
        ipaddress.ip_network(args.network, strict=False)
    except ValueError as exc:
        parser.error(f"bad network: {exc}")

    started = datetime.now()
    hosts = discover(
        args.network,
        args.ports,
        workers=args.workers,
        timeout_ms=args.timeout,
        port_timeout=args.port_timeout,
        verbose=not args.quiet,
    )
    elapsed = (datetime.now() - started).total_seconds()

    net = ipaddress.ip_network(args.network, strict=False)
    payload = {
        "scan": {
            "network": str(net),
            "timestamp": started.strftime("%Y-%m-%d %H:%M:%S"),
            "scanner": f"{platform.system()} {platform.release()}",
            "addresses_scanned": max(net.num_addresses - 2, 1),
            "live_hosts": len(hosts),
            "open_ports_found": sum(len(h["open_ports"]) for h in hosts),
            "duration_seconds": round(elapsed, 1),
        },
        "hosts": hosts,
    }

    changes = None
    if args.baseline and os.path.exists(args.baseline):
        with open(args.baseline, encoding="utf-8") as fh:
            baseline = json.load(fh)
        changes = compare_to_baseline(hosts, baseline)
        print_changes(changes)
    elif args.baseline:
        print(f"[!] No baseline at {args.baseline} - this scan will create it.")

    os.makedirs(args.outdir, exist_ok=True)
    prefix = args.out or f"netaudit_{started.strftime('%Y%m%d_%H%M%S')}"
    base = os.path.join(args.outdir, prefix)

    write_csv(f"{base}.csv", hosts)
    write_json(f"{base}.json", payload)
    write_html(f"{base}.html", payload, changes)

    if args.baseline and (args.update_baseline or not os.path.exists(args.baseline)):
        write_json(args.baseline, payload)
        print(f"[*] Baseline written to {args.baseline}")

    print(f"\n[*] {len(hosts)} host(s) in {elapsed:.1f}s")
    print(f"[*] Reports: {base}.csv  {base}.json  {base}.html")
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except KeyboardInterrupt:
        print("\n[!] Interrupted.")
        sys.exit(130)
