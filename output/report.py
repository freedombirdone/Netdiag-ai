"""Generate structured JSON and HTML NOC reports."""
from __future__ import annotations

import json
from datetime import datetime
from pathlib import Path
from typing import Optional

from jinja2 import Template

from models import DiagnosisResult, Event, CorrelatedGroup
from output.commands import commands_as_text


# ---------------------------------------------------------------------------
# JSON report
# ---------------------------------------------------------------------------

def _event_to_dict(e: Event) -> dict:
    return {
        "source_type": e.source_type,
        "severity": e.severity,
        "message": e.message,
        "timestamp": e.timestamp.isoformat() if e.timestamp else None,
        "device": e.device,
        "interface": e.interface,
        "facility": e.facility,
        "mnemonic": e.mnemonic,
    }


def generate_json_report(
    result: DiagnosisResult,
    events: list[Event],
    groups: list[CorrelatedGroup],
    include_raw_events: bool = False,
) -> dict:
    """Build a structured dict suitable for JSON serialisation."""
    report = {
        "generated_at": datetime.utcnow().isoformat() + "Z",
        "severity": result.severity,
        "diagnosis": result.diagnosis,
        "root_cause": result.root_cause,
        "affected_devices": result.affected_devices,
        "affected_interfaces": result.affected_interfaces,
        "remediation": result.remediation,
        "verification_commands": result.verification,
        "correlations": result.correlations,
        "event_summary": {
            "total": len(events),
            "by_severity": {
                "P1": sum(1 for e in events if e.severity == "P1"),
                "P2": sum(1 for e in events if e.severity == "P2"),
                "P3": sum(1 for e in events if e.severity == "P3"),
                "INFO": sum(1 for e in events if e.severity == "INFO"),
            },
            "by_source": {},
        },
        "correlation_groups": [
            {
                "reason": g.correlation_reason,
                "severity": g.overall_severity,
                "devices": g.devices,
                "interfaces": g.interfaces,
                "event_count": len(g.events),
                "timespan": g.timespan,
            }
            for g in groups
        ],
    }

    # Source breakdown
    for e in events:
        src = e.source_type
        report["event_summary"]["by_source"][src] = (
            report["event_summary"]["by_source"].get(src, 0) + 1
        )

    if include_raw_events:
        report["events"] = [_event_to_dict(e) for e in events]

    return report


# ---------------------------------------------------------------------------
# HTML report
# ---------------------------------------------------------------------------

_HTML_TEMPLATE = """\
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>netdiag-ai NOC Report — {{ report.severity }}</title>
<style>
  * { box-sizing: border-box; margin: 0; padding: 0; }
  body { font-family: 'Segoe UI', system-ui, sans-serif; background: #0f1117; color: #e2e8f0; padding: 2rem; }
  h1 { font-size: 1.6rem; margin-bottom: 0.25rem; }
  h2 { font-size: 1.1rem; margin: 1.5rem 0 0.5rem; color: #94a3b8; text-transform: uppercase; letter-spacing: 0.05em; }
  p  { line-height: 1.6; color: #cbd5e1; }
  .header { display: flex; align-items: center; gap: 1rem; margin-bottom: 1.5rem; }
  .badge { padding: 0.3rem 0.8rem; border-radius: 4px; font-weight: bold; font-size: 0.85rem; }
  .P1  { background: #7f1d1d; color: #fca5a5; }
  .P2  { background: #78350f; color: #fcd34d; }
  .P3  { background: #1e3a5f; color: #93c5fd; }
  .INFO{ background: #1f2937; color: #9ca3af; }
  .card { background: #1e2533; border-radius: 8px; padding: 1.2rem 1.5rem; margin-bottom: 1rem; }
  .card h3 { font-size: 0.9rem; color: #64748b; text-transform: uppercase; margin-bottom: 0.4rem; }
  .card p  { font-size: 1rem; }
  code, pre { background: #0d111a; padding: 0.2em 0.4em; border-radius: 3px; font-family: 'Cascadia Code', 'Fira Code', monospace; font-size: 0.85rem; color: #a3e635; }
  pre { padding: 1rem; overflow-x: auto; white-space: pre-wrap; line-height: 1.5; }
  .cmd-block { background: #0d111a; border-left: 3px solid #22d3ee; padding: 0.8rem 1rem; margin: 0.5rem 0; border-radius: 0 4px 4px 0; }
  .cmd-block .device { font-size: 0.75rem; color: #64748b; margin-bottom: 0.3rem; }
  .cmd-block .desc { font-size: 0.85rem; color: #94a3b8; margin-bottom: 0.4rem; }
  table { width: 100%; border-collapse: collapse; font-size: 0.85rem; }
  th { text-align: left; padding: 0.5rem; background: #0d111a; color: #64748b; font-weight: 600; }
  td { padding: 0.45rem 0.5rem; border-bottom: 1px solid #1e2533; }
  tr.P1 td { color: #fca5a5; }
  tr.P2 td { color: #fcd34d; }
  tr.P3 td { color: #93c5fd; }
  tr.INFO td { color: #6b7280; }
  .meta { font-size: 0.75rem; color: #4b5563; margin-top: 2rem; }
  .tag { display: inline-block; padding: 0.15rem 0.5rem; border-radius: 3px; font-size: 0.7rem; background: #1e2533; color: #64748b; margin-right: 0.3rem; }
</style>
</head>
<body>

<div class="header">
  <h1>netdiag-ai NOC Report</h1>
  <span class="badge {{ report.severity }}">{{ report.severity }}</span>
  <span style="color:#4b5563; font-size:0.85rem">{{ report.generated_at }}</span>
</div>

<div class="card">
  <h3>Diagnosis</h3>
  <p>{{ report.diagnosis }}</p>
</div>

<div class="card">
  <h3>Root Cause</h3>
  <p><em>{{ report.root_cause }}</em></p>
</div>

{% if report.affected_devices or report.affected_interfaces %}
<div class="card">
  <h3>Affected Scope</h3>
  {% if report.affected_devices %}
  <p><strong>Devices:</strong> {{ report.affected_devices | join(', ') }}</p>
  {% endif %}
  {% if report.affected_interfaces %}
  <p><strong>Interfaces:</strong> {{ report.affected_interfaces | join(', ') }}</p>
  {% endif %}
</div>
{% endif %}

{% if report.correlations %}
<h2>Correlations</h2>
{% for c in report.correlations %}
<div class="card"><p>• {{ c }}</p></div>
{% endfor %}
{% endif %}

{% if report.remediation %}
<h2>Remediation Commands</h2>
{% for step in report.remediation %}
<div class="cmd-block">
  <div class="device">Device: {{ step.device }}</div>
  <div class="desc">{{ step.description }}</div>
  <pre>{{ step.commands | join('\n') }}</pre>
</div>
{% endfor %}
{% endif %}

{% if report.verification_commands %}
<h2>Verification Commands</h2>
<div class="cmd-block">
{% for cmd in report.verification_commands %}
  <code>{{ cmd }}</code><br>
{% endfor %}
</div>
{% endif %}

{% if report.event_summary %}
<h2>Event Summary</h2>
<div class="card">
  <p>
    Total: <strong>{{ report.event_summary.total }}</strong> &nbsp;|&nbsp;
    <span class="badge P1">P1: {{ report.event_summary.by_severity.P1 }}</span>
    <span class="badge P2">P2: {{ report.event_summary.by_severity.P2 }}</span>
    <span class="badge P3">P3: {{ report.event_summary.by_severity.P3 }}</span>
    <span class="badge INFO">INFO: {{ report.event_summary.by_severity.INFO }}</span>
  </p>
  <p style="margin-top:0.5rem">
  {% for src, count in report.event_summary.by_source.items() %}
    <span class="tag">{{ src }}: {{ count }}</span>
  {% endfor %}
  </p>
</div>
{% endif %}

{% if report.correlation_groups %}
<h2>Correlation Groups</h2>
<table>
  <tr><th>Severity</th><th>Reason</th><th>Devices</th><th>Interfaces</th><th>Events</th></tr>
  {% for g in report.correlation_groups %}
  <tr class="{{ g.severity }}">
    <td><span class="badge {{ g.severity }}">{{ g.severity }}</span></td>
    <td>{{ g.reason }}</td>
    <td>{{ g.devices | join(', ') or '—' }}</td>
    <td>{{ g.interfaces | join(', ') or '—' }}</td>
    <td>{{ g.event_count }}</td>
  </tr>
  {% endfor %}
</table>
{% endif %}

{% if events %}
<h2>Event Log</h2>
<table>
  <tr><th>Sev</th><th>Source</th><th>Time</th><th>Device</th><th>Interface</th><th>Message</th></tr>
  {% for e in events[:100] %}
  <tr class="{{ e.severity }}">
    <td><span class="badge {{ e.severity }}">{{ e.severity }}</span></td>
    <td>{{ e.source_type }}</td>
    <td>{{ e.timestamp or '—' }}</td>
    <td>{{ e.device or '—' }}</td>
    <td>{{ e.interface or '—' }}</td>
    <td>{{ e.message[:120] }}</td>
  </tr>
  {% endfor %}
</table>
{% endif %}

<p class="meta">Generated by netdiag-ai &mdash; {{ report.generated_at }}</p>
</body>
</html>
"""


def generate_report(
    result: DiagnosisResult,
    events: list[Event],
    groups: list[CorrelatedGroup],
    output_path: Optional[str | Path] = None,
    fmt: str = "html",
    include_raw_events: bool = False,
) -> str:
    """Generate an HTML or JSON NOC report.

    Args:
        result: The LLM DiagnosisResult.
        events: All normalised events.
        groups: Correlated event groups.
        output_path: If given, write the report to this path.
        fmt: "html" or "json".
        include_raw_events: Include per-event detail in JSON reports.

    Returns:
        The report as a string.
    """
    report_data = generate_json_report(result, events, groups, include_raw_events)

    if fmt == "json":
        content = json.dumps(report_data, indent=2, default=str)
    else:
        # HTML
        tmpl = Template(_HTML_TEMPLATE)
        # Pass events as simple dicts for template rendering
        event_dicts = [
            {
                "severity": e.severity,
                "source_type": e.source_type,
                "timestamp": e.timestamp.strftime("%H:%M:%S") if e.timestamp else None,
                "device": e.device,
                "interface": e.interface,
                "message": e.message[:150],
            }
            for e in events[:100]
        ]
        content = tmpl.render(report=report_data, events=event_dicts)

    if output_path:
        path = Path(output_path)
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(content, encoding="utf-8")

    return content
