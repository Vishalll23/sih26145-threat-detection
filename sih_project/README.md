# SIH26145 — Passive Threat Intelligence Pipeline

**Problem Statement**: AI/ML-based threat detection for unidirectional (data-diode) network traffic — passive, read-only, no active response.

## Overview

This system detects cyber threats from a one-directional traffic feed without ever contacting the source/destination network. It processes simulated flow-level traffic and flags suspicious activity in near real-time, producing standardized, evidence-backed alerts.

## Current Modules

| Module | Detects | Technique |
|---|---|---|
| `traffic_simulator.py` | Generates normal + attack traffic | Synthetic flow generation |
| `port_scan_detector.py` | Reconnaissance / Port scanning | Fan-out pattern detection (unique ports per source, time-windowed) |
| `ddos_detector.py` | Volumetric DDoS | Packet-rate thresholding + Source-IP Shannon entropy |

*(More modules — DNS/DGA, C2 beaconing, TLS fingerprinting, exfiltration — to be added by team members)*

## Setup

```bash
pip install -r requirements.txt
```

## Usage

Run in order:

```bash
cd detectors
python3 traffic_simulator.py       # generates outputs/simulated_traffic.json
python3 port_scan_detector.py      # generates outputs/port_scan_alerts.json
python3 ddos_detector.py           # generates outputs/ddos_alerts.json
```

## Alert Schema

All detectors output alerts in this standardized format:

```json
{
  "timestamp": "2026-08-22T21:26:30.489821",
  "flow_id": "PS0014",
  "threat_class": "PORT_SCAN",
  "confidence_score": 0.5,
  "evidence": "Source 192.168.1.212 contacted 15 unique ports within 5 seconds",
  "source_ip": "192.168.1.212"
}
```

*(Note: field is `source_ip` for port scan alerts, `target_ip` for DDoS alerts — pipeline should normalize this.)*


## Architecture

```
Simulated Traffic (traffic_simulator.py)
        ↓
Detection Modules (parallel: port_scan, ddos, dns, tls, c2, exfiltration)
        ↓
Alert Aggregator (standardizes schema, merges all alerts)
        ↓
Live Dashboard (Streamlit)
```

## Constraints Followed

- **Read-only**: No module ever probes or contacts the traffic source
- **No payload decryption**: Only metadata/flow-level features are used
- **Streaming-first**: Sliding time-windows, not batch processing
- **Explainable**: Every alert includes concrete evidence, no black-box outputs
