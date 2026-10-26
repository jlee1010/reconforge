# ReconForge

**A lightweight TCP reconnaissance and reporting tool built in Python.**

ReconForge demonstrates a practical pentesting workflow: define scope, enumerate exposed TCP services, preserve evidence in machine-readable JSON, and produce a human-readable Markdown report.

> **Authorized use only.** Scan systems you own or have explicit permission to assess. The tool requires an authorization confirmation flag and does not exploit services, attempt logins, or send service-specific attack payloads.

## Features

- TCP connect scan of common ports or a custom port list/range
- Basic service hints and passive banner collection
- JSON output for follow-on analysis
- Markdown report with findings, limitations, and interpretation
- Input validation and a small unit test suite
- No third-party dependencies

## Requirements

- Python 3.10+
- Linux, macOS, or Windows

## Quick start

```bash
python reconforge.py 127.0.0.1 --ports 22,80,443,8000-8010 --i-have-authorization
```

This writes `reconforge-report.json` and `reconforge-report.md` in the current directory.

Scan a local lab VM:

```bash
python reconforge.py 192.168.56.10 --ports 1-1024 --timeout 0.5 \
  --out reports/lab-scan --i-have-authorization
```

The output directory must already exist. Keep scans within your authorized scope.

## Example output

```text
ReconForge 1.0.0 | target=127.0.0.1 (127.0.0.1) | ports=5
TCP connect scan in progress. Only scan systems you are authorized to test.
[OPEN] 8000/tcp  HTTP alternate
Progress: 5/5 ports checked

Complete: 1 open port(s)
Reports: reconforge-report.json and reconforge-report.md
```

## Run tests

```bash
python -m unittest discover -s tests -v
```

## How it works

1. Resolves the target to an IP address.
2. Attempts a TCP connection to each selected port with a bounded timeout.
3. Records ports where the TCP connection succeeds.
4. Reads a small amount of data if the service sends a banner without prompting.
5. Writes JSON and Markdown reports.

## Limitations and responsible interpretation

- A port number only suggests a service; it does not identify it with certainty.
- Open ports are not automatically vulnerabilities. Verify software versions, configuration, exposure, and business context.
- This is a TCP-only scanner, not a replacement for Nmap or a full vulnerability scanner.
- It does not perform UDP scans, OS fingerprinting, authentication testing, exploitation, or stealth/evasion.
- Results reflect the scanner's network vantage point and may be affected by firewalls or filtering.

## Project roadmap

- [ ] Add CSV export
- [ ] Add optional concurrency with a conservative rate limit
- [ ] Add tests for report generation and target resolution
- [ ] Add a comparison mode to highlight changes between two scans
- [ ] Add a sample report from a deliberately configured local lab

## Portfolio note

This project is intentionally small and transparent. The value is in readable code, scope control, repeatable output, and honest interpretation of findings. Before presenting it as completed work, run it in your own lab, inspect the output, and be prepared to explain the design choices and limitations.
