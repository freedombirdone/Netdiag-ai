# netdiag-ai

**LLM-assisted network troubleshooting for enterprise NOCs.**

Feed raw network data — syslogs, device configs, packet captures, show command outputs — into a single pipeline. Get back a plain-English diagnosis, exact remediation commands, and a structured HTML/JSON report, all powered by Claude.

```
Input sources → Parsers → Correlator → Claude → NOC Report
```

---

## Why this exists

Most AI log tools are generic. They don't know that `%LINEPROTO-5-UPDOWN` means an interface flap, that a duplex mismatch will cause CRC errors on the far end, or that a BGP peer going down at the same time as a config change is almost certainly not a coincidence.

netdiag-ai bakes in Cisco IOS/NX-OS domain knowledge so the LLM can reason across all your data sources together — correlating a syslog spike with a config change and a packet drop into a single, actionable root-cause diagnosis.

---

## Features

- **Multi-source correlation** — syslog + config + pcap + CLI show commands fed together so Claude can say *"this interface flap in syslog matches the duplex mismatch in your config"*
- **Cisco-aware prompting** — system prompt pre-loaded with IOS/NX-OS knowledge: syslog codes, BGP/OSPF failure modes, common misconfigs
- **Severity triage** — auto-classifies events as P1/P2/P3 before the LLM call, escalating errors in critical facilities (BGP, LINEPROTO, OSPF, HSRP) to P1
- **Streaming output** — diagnosis streams to the terminal in real time via Claude's streaming API
- **Adaptive thinking** — uses Claude's extended reasoning for complex multi-source incidents
- **Suggested commands** — output includes exact Cisco IOS commands to run, not just descriptions
- **NOC report export** — structured HTML (dark-themed, severity badges) and JSON reports for ticketing systems

---

## Installation

```bash
git clone https://github.com/freedombirdone/netdiag-ai
cd netdiag-ai
pip install -e .
```

For pcap support (optional):

```bash
pip install -e ".[pcap]"
# requires tshark/Wireshark for pyshark
```

Set your API key:

```bash
export ANTHROPIC_API_KEY="sk-ant-..."
```

---

## Usage

### Analyse a syslog dump + device config

```bash
netdiag analyze --syslog /var/log/cisco.log --config router.cfg
```

### Feed a pcap + show command output

```bash
netdiag analyze --pcap capture.pcap --cli show_bgp_summary.txt
```

### Inline show command output

```bash
netdiag analyze --syslog cisco.log --cli "show interface GigabitEthernet0/1"
```

### Full NOC report from an incident folder

```bash
netdiag analyze --all-inputs ./incident_2024-04-01/ --output report.html
```

The `--all-inputs` mode auto-detects file types by name/extension:

| Extension / Name pattern | Parsed as |
|---|---|
| `.log`, `.syslog`, `*syslog*` | Syslog |
| `.cfg`, `.conf`, `*config*`, `*router*`, `*switch*` | Cisco config |
| `.pcap`, `.pcapng`, `.cap` | Packet capture |
| `.txt` with `show`/`cli`/`output` in name | CLI output |

### Preview events without an LLM call

```bash
netdiag parse router.cfg --type config
netdiag parse cisco.log --type syslog
```

### Save as JSON (for ServiceNow/Jira integration)

```bash
netdiag analyze --syslog incident.log --output report.json
```

---

## Example output

```
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━ Ingesting inputs ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
  syslog  cisco.log
  config  router.cfg

Events: 47 total — P1:3 P2:8 P3:12 INFO:24
Correlation groups: 2 found
  [P1] Multiple events on GigabitEthernet0/1 from sources: config, syslog (5 events)
  [P2] Multiple source types on router1: config, syslog (11 events)

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━ LLM Analysis ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
Model: claude-opus-4-6

[Thinking...]
...

╭─── netdiag-ai Diagnosis ──────────────────────────────────╮
│ Overall Severity: P1                                       │
╰────────────────────────────────────────────────────────────╯

Diagnosis
GigabitEthernet0/1 on router1 is experiencing repeated link flaps caused by
a duplex mismatch. The syslog shows 14 LINEPROTO-5-UPDOWN events over 4 minutes,
all on the same interface. The running config has 'duplex half' configured while
the connected switch port is autonegotiating to full-duplex...

Root Cause
Half-duplex misconfiguration on GigabitEthernet0/1 causing late collisions and
CRC errors, triggering repeated line protocol flaps.

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━ Remediation Commands ━━━━━━━━━━━━━━━━━━━━━━━━━━━

Step 1 — Fix duplex mismatch on GigabitEthernet0/1
Device: router1
┌─────────────────────────────────────────┐
│  interface GigabitEthernet0/1           │
│  duplex full                            │
│  speed 1000                             │
│  no shutdown                            │
└─────────────────────────────────────────┘

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━ Verification Commands ━━━━━━━━━━━━━━━━━━━━━━━━━━

  > show interface GigabitEthernet0/1
  > show interface GigabitEthernet0/1 counters errors
```

---

## Supported input types

### Syslog
Standard Cisco syslog format with or without device name and timestamp:
```
Apr  1 12:34:56 router1 %LINEPROTO-5-UPDOWN: Line protocol on Interface Gi0/1, changed state to down
%BGP-5-ADJCHG: neighbor 10.0.0.1 Down BGP Notification sent
```

### Cisco device config (IOS / NX-OS)
Running or startup configs. Analysed for:
- Half-duplex / speed-duplex mismatches
- Shutdown interfaces with IP addresses configured
- Non-standard MTU values
- BGP neighbours without MD5 authentication
- Routed interfaces missing IP addresses

### Packet captures
`.pcap` / `.pcapng` files via pyshark or scapy. Flags:
- TCP retransmission rate > 5%
- SYN flood (> 100 SYN/sec)
- Elevated RST rate
- ICMP destination unreachable storms
- Top traffic flows

### CLI show command output
Auto-detected or explicitly typed. Parses:
- `show interfaces` — CRC errors, input/output errors, drops, half-duplex
- `show ip bgp summary` — downed neighbours, sessions with zero messages
- `show ip ospf neighbor` — non-FULL adjacency states

---

## Project structure

```
netdiag-ai/
├── ingestion/
│   ├── syslog.py        Parse Cisco syslog files
│   ├── config.py        Parse IOS/NX-OS configs, flag anomalies
│   ├── pcap.py          Extract anomalies from .pcap via pyshark/scapy
│   └── cli_output.py    Parse show command outputs
├── analysis/
│   ├── correlator.py    Cross-source event correlation
│   ├── context.py       Build LLM prompt (Cisco-aware system prompt + event summary)
│   └── llm.py           Streaming Claude call with adaptive thinking
├── output/
│   ├── diagnosis.py     Rich terminal rendering
│   ├── commands.py      Remediation command formatting
│   └── report.py        HTML and JSON NOC report generation
├── models.py            Shared dataclasses (Event, CorrelatedGroup, DiagnosisResult)
├── cli.py               Click CLI entry point
└── config.yaml          Severity thresholds, LLM settings, device profiles
```

---

## Configuration

`config.yaml` controls severity escalation, pcap thresholds, and LLM settings:

```yaml
llm:
  model: "claude-opus-4-6"
  max_tokens: 8192
  thinking: adaptive

severity_thresholds:
  p1_facilities:
    - LINEPROTO
    - BGP
    - OSPF
    - HSRP
    - REDUNDANCY

pcap:
  retransmit_threshold: 10   # % before flagging
  syn_rate_threshold: 100    # SYN/sec before flagging as flood

devices:
  router1:
    type: "Cisco IOS"
    role: "core"
```

---

## Requirements

- Python 3.10+
- `anthropic` >= 0.40 — Claude API client
- `click` — CLI framework
- `rich` — terminal output
- `pyyaml` — config parsing
- `jinja2` — HTML report templating
- `python-dateutil` — timestamp parsing
- `pyshark` or `scapy` *(optional)* — pcap analysis

---

## Build order / roadmap

- [x] Syslog parser + basic LLM call
- [x] Cisco config parser + correlation logic
- [x] CLI output parser (show command patterns)
- [x] pcap ingestion via pyshark/scapy
- [x] Structured report output + severity triage
- [x] Streaming + HTML NOC report export
- [ ] Live syslog UDP/TCP listener
- [ ] SNMP trap ingestion
- [ ] ServiceNow / Jira ticket auto-creation
- [ ] Web UI for NOC dashboard

---

## License

MIT License

Copyright (c) 2026 freedombirdone

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
