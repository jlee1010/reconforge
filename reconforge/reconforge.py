#!/usr/bin/env python3
"""ReconForge: a small, consent-based TCP reconnaissance tool."""
from __future__ import annotations

import argparse
import json
import socket
import sys
from datetime import datetime, timezone
from pathlib import Path

COMMON_PORTS = [
    21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143, 443, 445, 465,
    587, 993, 995, 1433, 1521, 2049, 3306, 3389, 5432, 5900, 6379,
    8000, 8080, 8443, 8888, 9200, 27017,
]
SERVICE_HINTS = {
    21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP", 53: "DNS",
    80: "HTTP", 110: "POP3", 111: "RPCBind", 135: "MS-RPC",
    139: "NetBIOS", 143: "IMAP", 443: "HTTPS", 445: "SMB",
    465: "SMTPS", 587: "SMTP submission", 993: "IMAPS", 995: "POP3S",
    1433: "Microsoft SQL Server", 1521: "Oracle DB", 2049: "NFS",
    3306: "MySQL", 3389: "RDP", 5432: "PostgreSQL", 5900: "VNC",
    6379: "Redis", 8000: "HTTP alternate", 8080: "HTTP proxy/alternate",
    8443: "HTTPS alternate", 8888: "HTTP alternate", 9200: "Elasticsearch",
    27017: "MongoDB",
}

def parse_ports(spec: str) -> list[int]:
    """Parse comma-separated ports and ranges, e.g. '22,80,8000-8010'."""
    ports: set[int] = set()
    for part in spec.split(","):
        part = part.strip()
        if not part:
            raise ValueError("Empty port item; use e.g. 22,80,8000-8010")
        if "-" in part:
            bits = part.split("-")
            if len(bits) != 2:
                raise ValueError(f"Invalid range: {part}")
            start, end = map(int, bits)
            if start > end:
                raise ValueError(f"Range start exceeds end: {part}")
            ports.update(range(start, end + 1))
        else:
            ports.add(int(part))
    if not ports or any(p < 1 or p > 65535 for p in ports):
        raise ValueError("Ports must be between 1 and 65535")
    if len(ports) > 4096:
        raise ValueError("Limit scans to 4096 ports per run")
    return sorted(ports)

def resolve_target(target: str) -> tuple[str, str]:
    try:
        info = socket.getaddrinfo(target, None, type=socket.SOCK_STREAM)
    except socket.gaierror as exc:
        raise ValueError(f"Could not resolve target '{target}': {exc}") from exc
    if not info:
        raise ValueError(f"No address found for target '{target}'")
    # Use the first resolved address so the report clearly identifies the scanned host.
    return target, info[0][4][0]

def scan_port(ip: str, port: int, timeout: float) -> dict | None:
    """Attempt one TCP connection. No exploit payloads or authentication attempts."""
    sock = socket.socket(socket.AF_INET6 if ":" in ip else socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(timeout)
    try:
        address = (ip, port, 0, 0) if ":" in ip else (ip, port)
        result = sock.connect_ex(address)
        if result != 0:
            return None
        banner = ""
        try:
            sock.settimeout(min(timeout, 0.5))
            data = sock.recv(256)
            banner = data.decode("utf-8", errors="replace").strip()
        except (socket.timeout, OSError):
            pass
        return {
            "port": port,
            "protocol": "tcp",
            "service_hint": SERVICE_HINTS.get(port, "unknown"),
            "banner": banner[:160],
        }
    finally:
        sock.close()

def build_report(target: str, ip: str, results: list[dict], started: str) -> dict:
    return {
        "tool": "ReconForge",
        "version": "1.0.0",
        "target": target,
        "resolved_ip": ip,
        "started_utc": started,
        "completed_utc": datetime.now(timezone.utc).isoformat(),
        "method": "TCP connect scan; passive banner read only",
        "open_ports": results,
        "summary": {
            "ports_open": len(results),
            "ports_with_banners": sum(bool(item["banner"]) for item in results),
        },
    }

def markdown_report(report: dict) -> str:
    lines = [
        "# ReconForge Scan Report", "",
        f"- **Target:** `{report['target']}`",
        f"- **Resolved address:** `{report['resolved_ip']}`",
        f"- **Started (UTC):** {report['started_utc']}",
        f"- **Completed (UTC):** {report['completed_utc']}",
        f"- **Method:** {report['method']}", "",
        "## Summary", "",
        f"- Open TCP ports: **{report['summary']['ports_open']}**",
        f"- Ports returning a banner: **{report['summary']['ports_with_banners']}**", "",
        "## Findings", "",
    ]
    if not report["open_ports"]:
        lines.append("No open TCP ports were found in the selected port list.")
    else:
        lines += ["| Port | Service hint | Banner |", "|---:|---|---|"]
        for item in report["open_ports"]:
            banner = item["banner"].replace("|", "\\|").replace("\n", " ")
            lines.append(f"| {item['port']} | {item['service_hint']} | {banner or '—'} |")
    lines += [
        "", "## Interpretation", "",
        "A listening port is an observation, not proof of a vulnerability. Validate service "
        "identity, version, exposure, and configuration before assigning severity.",
        "", "## Scope and limitations", "",
        "This report covers only the selected TCP ports from this single vantage point. "
        "Closed or filtered ports may be indistinguishable. Banner collection is passive; "
        "the tool does not authenticate, exploit services, or run UDP checks.",
        "", "## Authorization", "",
        "Run only against systems you own or are explicitly authorized to assess.", "",
    ]
    return "\n".join(lines)

def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Small TCP reconnaissance tool for systems you are authorized to test."
    )
    parser.add_argument("target", help="IP address or hostname in your authorized scope")
    parser.add_argument("--ports", default=",".join(map(str, COMMON_PORTS)),
                        help="Comma-separated ports/ranges (default: common TCP ports)")
    parser.add_argument("--timeout", type=float, default=0.4,
                        help="Connection timeout in seconds (default: 0.4)")
    parser.add_argument("--out", default="reconforge-report",
                        help="Output file prefix (default: reconforge-report)")
    parser.add_argument("--i-have-authorization", action="store_true",
                        help="Confirm you are authorized to scan this target")
    args = parser.parse_args(argv)

    if not args.i_have_authorization:
        parser.error("confirm authorized scope with --i-have-authorization")
    if not 0.1 <= args.timeout <= 5:
        parser.error("--timeout must be between 0.1 and 5 seconds")
    try:
        ports = parse_ports(args.ports)
        target, ip = resolve_target(args.target)
    except (ValueError, OSError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2

    started = datetime.now(timezone.utc).isoformat()
    print(f"ReconForge 1.0.0 | target={target} ({ip}) | ports={len(ports)}")
    print("TCP connect scan in progress. Only scan systems you are authorized to test.")
    results = []
    for index, port in enumerate(ports, 1):
        item = scan_port(ip, port, args.timeout)
        if item:
            results.append(item)
            print(f"[OPEN] {port}/tcp  {item['service_hint']}")
        if index % 25 == 0 or index == len(ports):
            print(f"Progress: {index}/{len(ports)} ports checked")

    report = build_report(target, ip, results, started)
    prefix = Path(args.out)
    json_path = prefix.with_suffix(".json")
    md_path = prefix.with_suffix(".md")
    json_path.write_text(json.dumps(report, indent=2), encoding="utf-8")
    md_path.write_text(markdown_report(report), encoding="utf-8")
    print(f"\nComplete: {len(results)} open port(s)")
    print(f"Reports: {json_path} and {md_path}")
    return 0

if __name__ == "__main__":
    raise SystemExit(main())
