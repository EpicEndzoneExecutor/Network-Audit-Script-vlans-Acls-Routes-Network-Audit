#!/usr/bin/env python3
"""
Network Audit Script – VLANs, ACLs, and Routing Tables

Author: Gabriel Hurtado
Created: 2025-09-05

Overview
--------
This script connects to network devices (Cisco IOS/IOS-XE and NX-OS out of the box)
via SSH and gathers:
  • VLANs (ID, name, status, ports when available)
  • ACLs (list of ACL names and entry counts)
  • Routing table summary (route counts by protocol + default route presence)

It then runs simple compliance checks against an optional policy file and
produces a per-device JSON report plus a concise terminal summary. You can
extend the OS command/parse maps to support other vendors.

Dependencies
------------
  pip install netmiko pyyaml rich

Quick Start
-----------
1) Create an inventory YAML (example embedded below) and a policy YAML (optional).
2) Export credentials as environment variables (recommended).
3) Run:
   python network_audit.py --inventory inventory.yaml --policy policy.yaml --output ./reports --threads 10

Inventory example (inventory.yaml)
----------------------------------
# Replace the env placeholders with your env var names or literal strings.
# device_type values: cisco_ios, cisco_xe (alias of cisco_ios), cisco_nxos

devices:
  - name: CORE1
    host: 10.0.0.1
    device_type: cisco_ios
    username: "{{env:NET_USER}}"
    password: "{{env:NET_PASS}}"
    secret:   "{{env:NET_ENABLE}}"   # optional; used for enable mode
  - name: DIST1
    host: 10.0.1.2
    device_type: cisco_nxos
    username: "{{env:NET_USER}}"
    password: "{{env:NET_PASS}}"

Policy example (policy.yaml)
----------------------------
required_acls: [EDGE-IN, EDGE-OUT]
require_default_route: true
allowed_vlans: [1,10,20,30,99,100]
forbidden_vlans: [666]
required_vlan_names:
  "10": USERS
  "20": SERVERS
min_routes: 1

Notes
-----
• The parser is intentionally lightweight to avoid external template deps; it handles common IOS/NX-OS outputs.
• If you have ntc-templates configured for TextFSM, you can easily swap in structured parsers.
• Extend COMMANDS and parsers to add more checks (e.g., interfaces, VRFs, IPv6 routes, prefix-lists).
"""

from __future__ import annotations

import argparse
import json
import os
import re
import sys
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Dict, Any, List, Tuple, Optional

import yaml
from rich.console import Console
from rich.table import Table
from rich import box

# Netmiko imports
from netmiko import ConnectHandler
from netmiko.ssh_exception import NetMikoAuthenticationException, NetMikoTimeoutException

console = Console()

# ----------------------- Utility & Inventory Loading ----------------------- #

def load_yaml(path: str | Path) -> Dict[str, Any]:
    with open(path, "r", encoding="utf-8") as f:
        return yaml.safe_load(f) or {}

ENV_REF_RE = re.compile(r"^\{\{env:([A-Za-z_][A-Za-z0-9_]*)\}\}$")

def resolve_env(value: Any) -> Any:
    """Replace values like "{{env:VAR}}" with os.environ["VAR"]."""
    if isinstance(value, str):
        m = ENV_REF_RE.match(value.strip())
        if m:
            return os.environ.get(m.group(1), "")
        return value
    if isinstance(value, dict):
        return {k: resolve_env(v) for k, v in value.items()}
    if isinstance(value, list):
        return [resolve_env(v) for v in value]
    return value

# ------------------------- Command Maps per Platform ----------------------- #

COMMANDS: Dict[str, Dict[str, str]] = {
    # Cisco IOS / IOS-XE
    "cisco_ios": {
        "enable": "enable",
        "vlans": "show vlan brief",
        "acls": "show access-lists",
        "routes": "show ip route",
    },
    # alias
    "cisco_xe": {
        "enable": "enable",
        "vlans": "show vlan brief",
        "acls": "show access-lists",
        "routes": "show ip route",
    },
    # Cisco NX-OS
    "cisco_nxos": {
        "enable": "enable",
        "vlans": "show vlan brief",
        "acls": "show access-lists",
        "routes": "show ip route",
    },
}

SUPPORTED_PLATFORMS = set(COMMANDS.keys())

# ------------------------------ Data Models -------------------------------- #

@dataclass
class VLAN:
    vlan_id: int
    name: str
    status: str = ""
    ports: List[str] = field(default_factory=list)

@dataclass
class ACL:
    name: str
    type: str = "unknown"  # standard/extended/ipv6/role-based/unknown
    entry_count: int = 0

@dataclass
class RoutesSummary:
    total_lines: int
    by_protocol: Dict[str, int] = field(default_factory=dict)
    has_default: bool = False

@dataclass
class DeviceAudit:
    device: Dict[str, Any]
    vlans: List[VLAN]
    acls: List[ACL]
    routes: RoutesSummary
    compliance: Dict[str, Any]
    raw: Dict[str, str]  # raw command outputs
    collected_at: str

# ------------------------------ Parsers ------------------------------------ #

VLAN_LINE_RE = re.compile(r"^\s*(?P<id>\d+)\s+(?P<name>\S+)\s+(?P<status>active|suspended|act\/unsup|shutdown|oper\S*)\s*(?P<ports>.*)$",
                           re.IGNORECASE)

ACL_HEADER_RES = [
    re.compile(r"^Standard IP access list\s+(?P<name>\S+)", re.IGNORECASE),
    re.compile(r"^Extended IP access list\s+(?P<name>\S+)", re.IGNORECASE),
    re.compile(r"^IP access list\s+(?P<name>\S+)", re.IGNORECASE),  # NX-OS style
    re.compile(r"^IPv6 access list\s+(?P<name>\S+)", re.IGNORECASE),
]

ROUTE_CODE_RE = re.compile(r"^(?P<code>[A-ZisbdOEURMLNK])\S*\s", re.IGNORECASE)
DEFAULT_RE = re.compile(r"\b0\.0\.0\.0/0\b|\bdefault network\b", re.IGNORECASE)


def parse_vlans(output: str) -> List[VLAN]:
    vlans: List[VLAN] = []
    for line in output.splitlines():
        m = VLAN_LINE_RE.match(line)
        if m:
            vlan_id = int(m.group("id"))
            name = m.group("name").strip()
            status = (m.group("status") or "").strip()
            ports_raw = (m.group("ports") or "").strip()
            ports = [p.strip() for p in ports_raw.split(",") if p.strip()]
            vlans.append(VLAN(vlan_id=vlan_id, name=name, status=status, ports=ports))
    # Deduplicate (some platforms repeat header chunks)
    uniq = {(v.vlan_id, v.name): v for v in vlans}
    return list(uniq.values())


def parse_acls(output: str) -> List[ACL]:
    acls: List[ACL] = []
    current: Optional[ACL] = None
    for line in output.splitlines():
        header_hit = False
        for rx in ACL_HEADER_RES:
            m = rx.match(line)
            if m:
                # finalize prior
                if current:
                    acls.append(current)
                acl_type = "standard" if "Standard" in rx.pattern else (
                    "extended" if "Extended" in rx.pattern else (
                        "ipv6" if "IPv6" in rx.pattern else "unknown"
                    )
                )
                current = ACL(name=m.group("name"), type=acl_type, entry_count=0)
                header_hit = True
                break
        if header_hit:
            continue
        # entries tend to be indented; count non-empty non-header lines until next header
        if current and line.strip() and not any(rx.match(line) for rx in ACL_HEADER_RES):
            current.entry_count += 1
    if current:
        acls.append(current)
    # Deduplicate by name (keep max entry_count)
    by_name: Dict[str, ACL] = {}
    for a in acls:
        if a.name not in by_name or a.entry_count > by_name[a.name].entry_count:
            by_name[a.name] = a
    return list(by_name.values())


def parse_routes(output: str) -> RoutesSummary:
    by_protocol: Dict[str, int] = {}
    total = 0
    has_default = False
    for line in output.splitlines():
        if DEFAULT_RE.search(line):
            has_default = True
        m = ROUTE_CODE_RE.match(line)
        if m:
            code = m.group("code").upper()
            by_protocol[code] = by_protocol.get(code, 0) + 1
            total += 1
    return RoutesSummary(total_lines=total, by_protocol=by_protocol, has_default=has_default)

# --------------------------- Compliance Checks ----------------------------- #

def evaluate_compliance(vlans: List[VLAN], acls: List[ACL], routes: RoutesSummary, policy: Dict[str, Any]) -> Dict[str, Any]:
    result = {"passed": [], "failed": []}

    def passf(msg: str):
        result["passed"].append(msg)

    def failf(msg: str):
        result["failed"].append(msg)

    # VLAN checks
    allowed = set(map(int, policy.get("allowed_vlans", [])))
    forbidden = set(map(int, policy.get("forbidden_vlans", [])))
    vlan_ids = {v.vlan_id for v in vlans}

    if allowed:
        unknown = vlan_ids - allowed
        if unknown:
            failf(f"Unexpected VLANs present: {sorted(unknown)} (allowed={sorted(allowed)})")
        else:
            passf("All VLANs are within allowed list.")

    if forbidden:
        present_forbidden = vlan_ids & forbidden
        if present_forbidden:
            failf(f"Forbidden VLANs present: {sorted(present_forbidden)}")
        else:
            passf("No forbidden VLANs found.")

    # Required VLAN names
    req_names: Dict[str, str] = policy.get("required_vlan_names", {})
    if req_names:
        by_id = {str(v.vlan_id): v for v in vlans}
        for vid, expected_name in req_names.items():
            if vid not in by_id:
                failf(f"Required VLAN {vid} not found.")
            else:
                actual = by_id[vid].name.upper()
                if actual != str(expected_name).upper():
                    failf(f"VLAN {vid} name mismatch: expected '{expected_name}', got '{by_id[vid].name}'.")
                else:
                    passf(f"VLAN {vid} name matches '{expected_name}'.")

    # ACL presence
    required_acls = set(map(str, policy.get("required_acls", [])))
    if required_acls:
        acl_names = {a.name for a in acls}
        missing = required_acls - acl_names
        if missing:
            failf(f"Missing required ACLs: {sorted(missing)}")
        else:
            passf("All required ACLs found.")

    # Default route requirement
    if policy.get("require_default_route", False):
        if routes.has_default:
            passf("Default route is present.")
        else:
            failf("Default route is missing.")

    # Minimal route count
    min_routes = policy.get("min_routes")
    if isinstance(min_routes, int):
        if routes.total_lines >= min_routes:
            passf(f"Route count OK (>= {min_routes}).")
        else:
            failf(f"Route count too low: {routes.total_lines} < {min_routes}.")

    return result

# ----------------------------- Collection Logic ---------------------------- #

@dataclass
class DeviceConnInfo:
    name: str
    host: str
    device_type: str
    username: str
    password: str
    secret: Optional[str] = None
    port: int = 22
    fast_cli: bool = True


def connect_and_collect(dev: DeviceConnInfo) -> Tuple[Optional[Dict[str, str]], Optional[str]]:
    """Return (outputs_by_command_key, error)."""
    if dev.device_type not in SUPPORTED_PLATFORMS:
        return None, f"Unsupported platform: {dev.device_type}"

    params = {
        "device_type": dev.device_type,
        "host": dev.host,
        "username": dev.username,
        "password": dev.password,
        "port": dev.port,
        "fast_cli": dev.fast_cli,
    }
    if dev.secret:
        params["secret"] = dev.secret

    try:
        with ConnectHandler(**params) as conn:
            # Enter enable if we have secret and platform needs it
            if dev.secret:
                try:
                    conn.enable()
                except Exception:
                    pass  # continue even if enable is not needed

            outputs = {}
            for key in ("vlans", "acls", "routes"):
                cmd = COMMANDS[dev.device_type][key]
                outputs[key] = conn.send_command(cmd, use_textfsm=False)
            return outputs, None
    except NetMikoAuthenticationException as e:
        return None, f"Authentication failed: {e}"
    except NetMikoTimeoutException as e:
        return None, f"Timeout connecting: {e}"
    except Exception as e:
        return None, f"Unexpected error: {e}"


def audit_device(dev: Dict[str, Any], policy: Dict[str, Any]) -> DeviceAudit:
    # Resolve env refs
    dev = resolve_env(dev)
    info = DeviceConnInfo(
        name=dev.get("name") or dev.get("host"),
        host=dev["host"],
        device_type=dev.get("device_type", "cisco_ios"),
        username=dev.get("username", ""),
        password=dev.get("password", ""),
        secret=dev.get("secret"),
        port=int(dev.get("port", 22)),
        fast_cli=bool(dev.get("fast_cli", True)),
    )

    outputs, error = connect_and_collect(info)
    if error:
        # Build a minimal audit with the error captured
        return DeviceAudit(
            device=dev,
            vlans=[],
            acls=[],
            routes=RoutesSummary(total_lines=0, by_protocol={}, has_default=False),
            compliance={"passed": [], "failed": [error]},
            raw={"error": error},
            collected_at=datetime.utcnow().isoformat() + "Z",
        )

    vlans = parse_vlans(outputs["vlans"]) if outputs else []
    acls = parse_acls(outputs["acls"]) if outputs else []
    routes = parse_routes(outputs["routes"]) if outputs else RoutesSummary(0, {}, False)

    compliance = evaluate_compliance(vlans, acls, routes, policy or {})

    return DeviceAudit(
        device=dev,
        vlans=vlans,
        acls=acls,
        routes=routes,
        compliance=compliance,
        raw=outputs or {},
        collected_at=datetime.utcnow().isoformat() + "Z",
    )

# ------------------------------- Reporting --------------------------------- #

def to_json(obj: Any) -> str:
    def default(o):
        if hasattr(o, "__dict__"):
            return o.__dict__
        return str(o)
    return json.dumps(obj, default=default, indent=2)


def save_report(report_dir: Path, audit: DeviceAudit) -> Path:
    report_dir.mkdir(parents=True, exist_ok=True)
    fname = f"audit_{audit.device.get('name') or audit.device.get('host')}.json"
    path = report_dir / fname
    with open(path, "w", encoding="utf-8") as f:
        f.write(to_json(audit))
    return path


def print_summary(audits: List[DeviceAudit]):
    table = Table(title="Network Audit Summary", box=box.SIMPLE_HEAVY)
    table.add_column("Device", style="bold")
    table.add_column("VLANs")
    table.add_column("ACLs")
    table.add_column("Routes")
    table.add_column("Default Route")
    table.add_column("Compliance Pass/Fail")

    for a in audits:
        vlan_count = str(len(a.vlans))
        acl_count = str(len(a.acls))
        route_count = str(a.routes.total_lines)
        default_present = "Yes" if a.routes.has_default else "No"
        passes = len(a.compliance.get("passed", []))
        fails = len(a.compliance.get("failed", []))
        device_label = a.device.get("name") or a.device.get("host")
        table.add_row(device_label, vlan_count, acl_count, route_count, default_present, f"{passes}/{fails}")

    console.print(table)

    # Print failures for quick visibility
    for a in audits:
        if a.compliance.get("failed"):
            console.print(f"\n[bold red]Compliance issues for {a.device.get('name') or a.device.get('host')}[/bold red]")
            for item in a.compliance["failed"]:
                console.print(f"  • {item}")

# --------------------------------- Main ------------------------------------ #

def main():
    parser = argparse.ArgumentParser(description="Audit VLANs, ACLs, and Routes on network devices.")
    parser.add_argument("--inventory", required=True, help="Path to inventory YAML with 'devices' list")
    parser.add_argument("--policy", required=False, help="Path to policy YAML for compliance checks")
    parser.add_argument("--output", default="./reports", help="Directory to write JSON reports")
    parser.add_argument("--threads", type=int, default=10, help="Max parallel threads")
    args = parser.parse_args()

    inv = load_yaml(args.inventory)
    policy = load_yaml(args.policy) if args.policy else {}

    devices: List[Dict[str, Any]] = inv.get("devices", [])
    if not devices:
        console.print("[red]No devices found in inventory.[/red]")
        sys.exit(2)

    audits: List[DeviceAudit] = []
    with ThreadPoolExecutor(max_workers=max(1, args.threads)) as pool:
        futures = {pool.submit(audit_device, dev, policy): dev for dev in devices}
        for fut in as_completed(futures):
            audits.append(fut.result())

    # Save per-device reports
    outdir = Path(args.output)
    for a in audits:
        path = save_report(outdir, a)
        console.print(f"Saved report: {path}")

    print_summary(audits)


if __name__ == "__main__":
    main()
