<p align="center">
  <img src="assets/netsentinel-logo.svg" alt="NetSentinel logo" width="180" />
</p>

<h1 align="center">NetSentinel</h1>

<p align="center">
  <strong>A terminal-based Intrusion Detection System written in modern C++.</strong>
</p>

<p align="center">
  <a href="#features"><img alt="IDS" src="https://img.shields.io/badge/type-intrusion%20detection-blue"></a>
  <a href="#tech-stack"><img alt="C++" src="https://img.shields.io/badge/C%2B%2B-17-00599C?logo=cplusplus"></a>
  <a href="#terminal-first"><img alt="Terminal" src="https://img.shields.io/badge/UI-terminal%20only-111827"></a>
  <a href="#security-scope"><img alt="Scope" src="https://img.shields.io/badge/scope-defensive%20security-green"></a>
</p>

---

## Overview

**NetSentinel** is a defensive, terminal-first Intrusion Detection System built in modern C++17.
It analyzes live network packets or simulated network events, detects suspicious behavior, prints color-coded alerts directly in the terminal, and stores local event and alert logs for later review.

The project focuses on practical blue-team use cases such as TCP port scan detection, SSH brute force detection, event logging, alert filtering, configurable thresholds, and real-time terminal monitoring.

## Keywords

`intrusion-detection-system` `ids` `network-security` `cybersecurity` `cpp` `cplusplus` `terminal` `cli` `blue-team` `security-monitoring` `port-scan-detection` `ssh-bruteforce-detection` `packet-analysis` `real-time-monitoring` `network-analysis` `threat-detection` `security-tool` `defensive-security`

## Features

- Live packet analysis with `libpcap`
- Auto interface selection or explicit interface selection with `--interface`
- Simulation mode for safe defensive testing
- TCP, UDP, and ICMP network event normalization
- TCP port scan detection
- Network-based SSH brute force detection
- Configurable detection thresholds
- Color-coded terminal output
- Severity-specific alert colors
- Local event and alert logging
- CLI-based stored alert filtering
- Modular detection engine
- Lightweight C++ tests for detection rules

## Terminal First

NetSentinel does not use a web dashboard. All interaction happens through the terminal.

Running `./netsentinel` starts live packet analysis using the configured interface. If the interface is set to `auto`, NetSentinel chooses the first non-loopback capture interface found by `libpcap`.

Live capture may require administrator permissions:

```bash
sudo ./netsentinel
```

Use simulation mode when you want safe deterministic test traffic:

```bash
./netsentinel --simulate
```

Example output:

```text
[INFO] NetSentinel started
[INFO] Config: config/ids.conf
[INFO] Analyzing live packets on interface en0 for 100 packets
[EVENT] 2026-06-12 14:20:31 192.168.1.80:50000 -> 192.168.1.10:20 TCP
[ALERT][MEDIUM][PORT_SCAN] 192.168.1.80 contacted 10 unique TCP ports in 10s
[ALERT][HIGH][SSH_BRUTE_FORCE] 192.168.1.50 attempted 15 SSH connections in 30s
[STATUS] Processed events: 65
[STATUS] Generated alerts: 2
```

Alert colors:

- `LOW`: green
- `MEDIUM`: yellow
- `HIGH`: magenta
- `CRITICAL`: bold red background

## Architecture

```text
NetSentinel
├── Capture / Input
│   ├── LiveCapture reads TCP, UDP, and ICMP packets with libpcap
│   └── EventSimulator generates safe defensive test events
├── Event Model
│   └── NetworkEvent represents normalized network activity
├── Detection Engine
│   └── Runs detection rules over event streams
├── Rules
│   ├── PortScanRule
│   └── SshBruteForceRule
├── Alert Manager
│   └── Stores and formats security alerts
├── Storage / Logging
│   └── Writes events and alerts locally
├── Configuration
│   └── Loads thresholds and runtime settings
└── Terminal UI / CLI
    └── Displays live events, alerts, status, and filters
```

## Tech Stack

- **Language:** C++17
- **Interface:** Terminal / CLI
- **Build systems:** Makefile and CMake
- **Packet capture:** `libpcap`
- **Storage:** Local log files
- **Testing:** Lightweight C++ test executable

`libpcap` is the only external runtime dependency. It is used only for defensive packet capture and network event analysis.

## Build

Using Make:

```bash
make
```

Using CMake:

```bash
cmake -S . -B build
cmake --build build
```

## Run

Start live packet analysis with the configured interface and packet count:

```bash
sudo ./netsentinel
```

Analyze a specific Wi-Fi or network interface:

```bash
sudo ./netsentinel --interface en0
sudo ./netsentinel --interface wlan0
```

Analyze a specific number of packets:

```bash
sudo ./netsentinel --interface en0 --count 200
```

Run safe simulation mode:

```bash
./netsentinel --simulate
```

Use a custom config file:

```bash
./netsentinel --config config/ids.conf --simulate
```

Show help:

```bash
./netsentinel --help
```

## CLI Alert Filters

Stored alerts are read from the configured alert log.

```bash
./netsentinel --show-alerts
./netsentinel --show-alerts --type PORT_SCAN
./netsentinel --show-alerts --type SSH_BRUTE_FORCE
./netsentinel --show-alerts --severity HIGH
./netsentinel --show-alerts --source 192.168.1.50
./netsentinel --tail-alerts 20
```

## Configuration

Default configuration lives in `config/ids.conf`.

```ini
port_scan_window_seconds=10
port_scan_port_threshold=10
port_scan_severity=MEDIUM

ssh_port=22
ssh_brute_force_window_seconds=30
ssh_brute_force_attempt_threshold=15
ssh_brute_force_severity=HIGH

log_level=INFO
ansi_color_enabled=true

simulation_enabled=true
simulation_event_rate_per_second=5
simulation_event_count=80

live_capture_interface=auto
live_capture_packet_count=100

event_log_path=logs/events.log
alert_log_path=logs/alerts.log
```

All thresholds should be adjusted to your environment before using NetSentinel for real monitoring.

Supported severities:

- `LOW`
- `MEDIUM`
- `HIGH`
- `CRITICAL`

Supported alert types:

- `PORT_SCAN`
- `SSH_BRUTE_FORCE`

## Detection Rules

### TCP Port Scan Detection

NetSentinel detects potential port scans by tracking how many unique TCP destination ports a single source IP contacts within a configurable time window.

Example rule:

```text
If one source IP contacts 10 or more unique destination ports within 10 seconds,
generate a PORT_SCAN alert.
```

Generated alert metadata includes:

- `unique_ports`
- `port_summary`
- `window_seconds`

### SSH Brute Force Detection

NetSentinel currently performs network-based SSH brute force detection. It does not read authentication logs.

An SSH brute force alert is generated when one source IP makes repeated TCP connections to the configured SSH port within the configured time window.

Example rule:

```text
If one source IP performs 15 or more SSH connections within 30 seconds,
generate an SSH_BRUTE_FORCE alert.
```

Generated alert metadata includes:

- `attempt_count`
- `ssh_port`
- `window_seconds`
- `detection_source=network_connections`

## Logs

NetSentinel stores local logs for later analysis:

```text
logs/events.log
logs/alerts.log
```

Log files are runtime artifacts and are not committed.

## Running Tests

```bash
make test
```

The tests cover:

- Port scan detection above threshold
- Port scan behavior below threshold
- SSH brute force detection above threshold
- SSH brute force behavior below threshold
- Alert field validation
- Configuration loading

## Security Scope

NetSentinel is a defensive security monitoring tool.

This project does not include and should not include:

- Exploit code
- Malware
- Offensive scanning tools
- Brute force tools
- Credential attacks
- Persistence techniques
- Security bypass functionality

The purpose of this project is detection, monitoring, alerting, and learning.

## Roadmap

- Add authentication log parsing for SSH failures
- Add SQLite storage backend
- Add allowlist and blocklist support
- Add export to JSON or CSV
- Add more defensive detection rules
- Improve terminal dashboard view

## Author

Created by **Iliass Alami-Qammouri**.
