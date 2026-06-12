# IDS

IDS is a terminal-only real-time intrusion detection and network analysis application written in modern C++17.

The project is defensive only. It analyzes network events, detects suspicious activity, prints alerts in the terminal, and stores events and alerts in local log files.

## Features

- Terminal-only IDS workflow
- Simulation mode for defensive test data
- Network event model with timestamp, source IP, destination IP, ports, protocol, event type, and metadata
- Configurable TCP port scan detection
- Configurable network-based SSH brute force detection
- Alert model with ID, timestamp, type, severity, source, destination, description, and metadata
- Event logging to `logs/events.log`
- Alert logging to `logs/alerts.log`
- CLI filters for stored alerts
- Lightweight C++ test executable

## Defensive Security Scope

This application does not implement exploits, malware, offensive scanners, brute-force tooling, payloads, bypasses, or persistence mechanisms.

Simulation mode generates defensive test events so the IDS pipeline can be exercised safely without attacking any system.

## Architecture

```text
EventSimulator or future live capture
        |
        v
NetworkEvent
        |
        v
DetectionEngine
        |
        +-- PortScanRule
        +-- SshBruteForceRule
        |
        v
AlertManager + FileLogger
        |
        v
Terminal output and local logs
```

Main components:

- `NetworkEvent`: normalized event structure used by all detection logic.
- `IdsConfig`: key-value configuration loader.
- `DetectionEngine`: routes events through detection rules.
- `PortScanRule`: detects many unique TCP destination ports from one source within a time window.
- `SshBruteForceRule`: detects repeated network connections to the configured SSH port.
- `AlertManager`: prints alerts and status summaries.
- `FileLogger`: writes events and alerts to separate log files and loads stored alerts for filtering.
- `EventSimulator`: generates normal traffic, port scan patterns, and SSH brute force patterns.

## Requirements

- C++17 compiler, tested with `g++`
- `make`
- Optional: CMake 3.16 or newer

No external libraries are required.

## Build

Use the Makefile:

```bash
make
```

Optional CMake build if CMake is installed:

```bash
cmake -S . -B build
cmake --build build
```

## Run

Run defensive simulation mode:

```bash
./ids --simulate
```

Use a specific configuration file:

```bash
./ids --simulate --config config/ids.conf
```

Show CLI help:

```bash
./ids --help
```

## Alert Filtering

Stored alerts are read from the configured alert log path.

```bash
./ids --show-alerts
./ids --show-alerts --type SSH_BRUTE_FORCE
./ids --show-alerts --type PORT_SCAN
./ids --show-alerts --severity HIGH
./ids --show-alerts --source 192.168.1.50
./ids --tail-alerts 20
```

## Configuration

Default configuration lives in `config/ids.conf`.

```text
port_scan_window_seconds=10
port_scan_port_threshold=10
port_scan_severity=MEDIUM

ssh_port=22
ssh_brute_force_window_seconds=30
ssh_brute_force_attempt_threshold=15
ssh_brute_force_severity=HIGH

log_level=INFO
simulation_enabled=true
simulation_event_rate_per_second=5
simulation_event_count=80

event_log_path=logs/events.log
alert_log_path=logs/alerts.log
```

Supported severities:

- `LOW`
- `MEDIUM`
- `HIGH`
- `CRITICAL`

Supported alert types:

- `PORT_SCAN`
- `SSH_BRUTE_FORCE`

## Detection Rules

### TCP Port Scan

A port scan alert is generated when one source IP contacts at least the configured number of unique TCP destination ports within the configured time window.

Example default:

```text
192.168.1.80 contacts 10 or more unique TCP ports within 10 seconds.
```

Generated alert metadata includes:

- `unique_ports`
- `port_summary`
- `window_seconds`

### SSH Brute Force

This IDS currently performs network-based SSH brute force detection. It does not read authentication logs.

An SSH brute force alert is generated when one source IP makes at least the configured number of TCP connections to the configured SSH port within the configured time window.

Example default:

```text
192.168.1.50 makes 15 or more TCP connections to port 22 within 30 seconds.
```

Generated alert metadata includes:

- `attempt_count`
- `ssh_port`
- `window_seconds`
- `detection_source=network_connections`

## Example Terminal Output

```text
[INFO] IDS started
[INFO] Config: config/ids.conf
[EVENT] 2026-06-12 13:55:48 192.168.1.80:50000 -> 192.168.1.10:20 TCP
[ALERT][MEDIUM][PORT_SCAN] 192.168.1.80 contacted 10 unique TCP ports in 10s
[ALERT][HIGH][SSH_BRUTE_FORCE] 192.168.1.50 attempted 15 SSH connections in 30s
[STATUS] Processed events: 65
[STATUS] Generated alerts: 2
[STATUS] Suspicious source IPs: 192.168.1.50(1) 192.168.1.80(1)
```

## Logs

Events are written to:

```text
logs/events.log
```

Alerts are written to:

```text
logs/alerts.log
```

Log files are local runtime artifacts and are not committed.

## Tests

Run the test suite:

```bash
make test
```

The tests cover:

- Port scan detection above threshold
- Port scan behavior below threshold
- SSH brute force detection above threshold
- SSH brute force behavior below threshold
- Expected alert fields and metadata
- Configuration loading

## Simulation Mode vs Live Capture

Simulation mode is implemented and safe to run locally. It generates realistic defensive network events and suspicious patterns.

Live packet capture is not implemented yet. The code is structured so a future capture module can produce `NetworkEvent` objects and feed them into the same `DetectionEngine`.

## Clean Build Artifacts

```bash
make clean
```
