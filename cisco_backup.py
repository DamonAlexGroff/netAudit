#!/usr/bin/env python3
"""
cisco_backup - pull running-configs off network devices and track changes.

Connects to each device over SSH, saves the running-config to a timestamped
file, and diffs it against the most recent previous backup so config drift is
visible immediately.

Requires netmiko:   pip install netmiko

Devices are defined in a JSON inventory file:

    {
      "devices": [
        {
          "name": "core-sw01",
          "host": "192.168.1.2",
          "device_type": "cisco_ios",
          "username": "admin"
        }
      ]
    }

The password is read from the CISCO_BACKUP_PASSWORD environment variable, or
prompted once at runtime. Never hard-code credentials in the inventory file.

Usage:
    export CISCO_BACKUP_PASSWORD='...'
    python cisco_backup.py inventory.json
    python cisco_backup.py inventory.json --outdir configs --no-diff

Tested against Cisco IOS. device_type accepts any Netmiko platform string
(cisco_ios, cisco_nxos, arista_eos, juniper_junos, hp_procurve, ...).
No lab gear? GNS3 or EVE-NG will run IOS images you can SSH into.
"""

import argparse
import difflib
import getpass
import glob
import json
import os
import re
import sys
from datetime import datetime

try:
    from netmiko import ConnectHandler
    from netmiko.exceptions import NetmikoAuthenticationException, NetmikoTimeoutException
except ImportError:
    ConnectHandler = None

__version__ = "1.0.0"

# Lines that change on every read and would otherwise create noisy diffs.
NOISE_PATTERNS = [
    re.compile(r"^! Last configuration change"),
    re.compile(r"^! NVRAM config last updated"),
    re.compile(r"^ntp clock-period"),
    re.compile(r"^Building configuration"),
    re.compile(r"^Current configuration : \d+ bytes"),
]


def strip_noise(config):
    return [
        line.rstrip()
        for line in config.splitlines()
        if not any(pattern.match(line) for pattern in NOISE_PATTERNS)
    ]


def latest_backup(outdir, name):
    matches = sorted(glob.glob(os.path.join(outdir, f"{name}_*.cfg")))
    return matches[-1] if matches else None


def backup_device(device, password, outdir, show_diff=True):
    name = device["name"]
    params = {
        "device_type": device.get("device_type", "cisco_ios"),
        "host": device["host"],
        "username": device["username"],
        "password": password,
        "secret": device.get("secret", password),
        "fast_cli": False,
    }

    print(f"[*] {name} ({device['host']}) ...", flush=True)
    try:
        with ConnectHandler(**params) as conn:
            if device.get("enable"):
                conn.enable()
            config = conn.send_command("show running-config")
    except NetmikoAuthenticationException:
        print(f"    [FAIL] authentication rejected")
        return False
    except NetmikoTimeoutException:
        print(f"    [FAIL] unreachable or SSH timed out")
        return False
    except Exception as exc:  # noqa: BLE001 - report and continue to next device
        print(f"    [FAIL] {type(exc).__name__}: {exc}")
        return False

    previous = latest_backup(outdir, name)
    stamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    path = os.path.join(outdir, f"{name}_{stamp}.cfg")
    with open(path, "w", encoding="utf-8") as fh:
        fh.write(config)
    print(f"    [OK] saved {path} ({len(config.splitlines())} lines)")

    if show_diff and previous:
        with open(previous, encoding="utf-8") as fh:
            old = strip_noise(fh.read())
        new = strip_noise(config)
        diff = list(difflib.unified_diff(
            old, new,
            fromfile=os.path.basename(previous),
            tofile=os.path.basename(path),
            lineterm="",
            n=1,
        ))
        if diff:
            print(f"    [CHANGED] {len(diff)} diff line(s) vs previous backup:")
            for line in diff[:40]:
                print(f"      {line}")
            if len(diff) > 40:
                print(f"      ... {len(diff) - 40} more line(s)")
        else:
            print("    [SAME] no change since last backup")
    return True


def main(argv=None):
    parser = argparse.ArgumentParser(
        prog="cisco_backup",
        description="Back up network device running-configs and diff for drift.",
    )
    parser.add_argument("inventory", help="path to JSON inventory file")
    parser.add_argument("--outdir", default="configs", help="backup directory")
    parser.add_argument("--no-diff", action="store_true", help="skip the drift diff")
    parser.add_argument("--version", action="version", version=f"cisco_backup {__version__}")
    args = parser.parse_args(argv)

    if ConnectHandler is None:
        print("[!] netmiko is not installed. Run: pip install netmiko")
        return 1

    with open(args.inventory, encoding="utf-8") as fh:
        devices = json.load(fh)["devices"]

    password = os.environ.get("CISCO_BACKUP_PASSWORD") or getpass.getpass("Device password: ")
    os.makedirs(args.outdir, exist_ok=True)

    succeeded = sum(
        backup_device(device, password, args.outdir, show_diff=not args.no_diff)
        for device in devices
    )
    print(f"\n[*] {succeeded}/{len(devices)} device(s) backed up to {args.outdir}/")
    return 0 if succeeded == len(devices) else 1


if __name__ == "__main__":
    try:
        sys.exit(main())
    except KeyboardInterrupt:
        print("\n[!] Interrupted.")
        sys.exit(130)
