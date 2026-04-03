#!/usr/bin/env python3
"""netdiag-ai — LLM-assisted network troubleshooting for enterprise NOCs.

Usage examples:
  netdiag analyze --syslog /var/log/cisco.log --config router.txt
  netdiag analyze --pcap capture.pcap --cli "show ip bgp summary"
  netdiag analyze --all-inputs ./incident/ --output report.html
"""
from __future__ import annotations

import os
import sys
from pathlib import Path
from typing import Optional

import click
import yaml
from rich.console import Console
from rich.rule import Rule
from rich.status import Status

console = Console()

# Ensure project root is on sys.path when running as a script
sys.path.insert(0, str(Path(__file__).parent))

from models import Event, CorrelatedGroup
from ingestion import parse_syslog, parse_config, parse_pcap, parse_cli_output
from analysis import correlate_events, build_context, run_diagnosis
from output import render_diagnosis, render_commands, generate_report


def _load_config(config_path: Optional[str] = None) -> dict:
    paths = [config_path, "config.yaml", Path(__file__).parent / "config.yaml"]
    for p in paths:
        if p and Path(p).exists():
            with open(p) as f:
                return yaml.safe_load(f) or {}
    return {}


def _stream_callback(chunk: str, block_type: str = "text") -> None:
    if block_type == "thinking":
        console.print(chunk, end="", style="dim italic")
    elif block_type == "header":
        console.print(chunk, style="bold")
    else:
        console.print(chunk, end="", markup=False)


def _ingest_directory(directory: Path) -> list[Event]:
    """Ingest all recognised files in a directory."""
    events: list[Event] = []

    for path in sorted(directory.rglob("*")):
        if not path.is_file():
            continue
        suffix = path.suffix.lower()
        name = path.name.lower()

        if suffix in (".log", ".syslog") or "syslog" in name:
            console.print(f"  [cyan]syslog[/cyan] {path.name}")
            events.extend(parse_syslog(path))

        elif suffix in (".txt", ".cfg", ".conf") and (
            "config" in name or "running" in name or "startup" in name
            or "router" in name or "switch" in name
        ):
            console.print(f"  [cyan]config[/cyan] {path.name}")
            events.extend(parse_config(path))

        elif suffix in (".pcap", ".pcapng", ".cap"):
            console.print(f"  [cyan]pcap[/cyan]   {path.name}")
            events.extend(parse_pcap(path))

        elif suffix in (".txt",) and (
            "show" in name or "cli" in name or "output" in name
        ):
            console.print(f"  [cyan]cli[/cyan]    {path.name}")
            events.extend(parse_cli_output(path))

    return events


@click.group()
def main():
    """netdiag-ai: LLM-assisted network troubleshooting."""
    pass


@main.command()
@click.option("--syslog", "syslog_inputs", multiple=True, metavar="FILE",
              help="Syslog file(s) to analyse.")
@click.option("--config", "config_inputs", multiple=True, metavar="FILE",
              help="Cisco config file(s) to analyse.")
@click.option("--pcap", "pcap_inputs", multiple=True, metavar="FILE",
              help="PCAP file(s) to analyse.")
@click.option("--cli", "cli_inputs", multiple=True, metavar="TEXT_OR_FILE",
              help="Show command output (file or inline text).")
@click.option("--all-inputs", "all_inputs_dir", default=None, metavar="DIR",
              help="Directory: ingest all recognised files inside.")
@click.option("--device", default=None, metavar="NAME",
              help="Device hostname to associate with CLI/PCAP inputs.")
@click.option("--output", "-o", "output_path", default=None, metavar="FILE",
              help="Write report to FILE (.html or .json).")
@click.option("--no-stream", is_flag=True,
              help="Disable streaming output (wait for full response).")
@click.option("--no-thinking", is_flag=True,
              help="Disable adaptive thinking (faster, less thorough).")
@click.option("--model", default=None, metavar="MODEL",
              help="Override LLM model (default: claude-opus-4-6).")
@click.option("--config-file", default=None, metavar="FILE",
              help="Path to config.yaml.")
@click.option("--show-events", is_flag=True,
              help="Print event table before LLM analysis.")
def analyze(
    syslog_inputs, config_inputs, pcap_inputs, cli_inputs,
    all_inputs_dir, device, output_path, no_stream, no_thinking,
    model, config_file, show_events,
):
    """Analyse network data and produce an AI-powered diagnosis."""
    cfg = _load_config(config_file)
    llm_cfg = cfg.get("llm", {})
    effective_model = model or llm_cfg.get("model", "claude-opus-4-6")

    if not os.environ.get("ANTHROPIC_API_KEY"):
        console.print(
            "[bold red]Error:[/bold red] ANTHROPIC_API_KEY environment variable is not set."
        )
        sys.exit(1)

    # --- Ingestion ---
    console.print(Rule("[bold]Ingesting inputs[/bold]"))
    all_events: list[Event] = []

    if all_inputs_dir:
        d = Path(all_inputs_dir)
        if not d.is_dir():
            console.print(f"[red]Directory not found: {all_inputs_dir}[/red]")
            sys.exit(1)
        all_events.extend(_ingest_directory(d))

    for path in syslog_inputs:
        console.print(f"  [cyan]syslog[/cyan] {path}")
        all_events.extend(parse_syslog(path))

    for path in config_inputs:
        console.print(f"  [cyan]config[/cyan] {path}")
        all_events.extend(parse_config(path, device=device))

    for path in pcap_inputs:
        console.print(f"  [cyan]pcap[/cyan]   {path}")
        all_events.extend(parse_pcap(path, device=device))

    for cli_src in cli_inputs:
        # Check if it's a file path or inline text
        p = Path(cli_src)
        if p.exists():
            console.print(f"  [cyan]cli[/cyan]    {cli_src}")
            all_events.extend(parse_cli_output(p, device=device))
        else:
            console.print(f"  [cyan]cli[/cyan]    (inline text)")
            all_events.extend(parse_cli_output(cli_src, device=device))

    if not all_events:
        console.print("[yellow]No events ingested. Provide at least one input source.[/yellow]")
        console.print("\nExample:")
        console.print("  netdiag analyze --syslog /var/log/cisco.log --config router.cfg\n")
        sys.exit(0)

    # Count by severity
    sev_counts = {"P1": 0, "P2": 0, "P3": 0, "INFO": 0}
    for e in all_events:
        sev_counts[e.severity] = sev_counts.get(e.severity, 0) + 1

    console.print(
        f"\n[bold]Events:[/bold] {len(all_events)} total — "
        f"[red]P1:{sev_counts['P1']}[/red] "
        f"[yellow]P2:{sev_counts['P2']}[/yellow] "
        f"[cyan]P3:{sev_counts['P3']}[/cyan] "
        f"[dim]INFO:{sev_counts['INFO']}[/dim]"
    )

    if show_events:
        from output.diagnosis import render_event_table
        render_event_table(all_events)

    # --- Correlation ---
    with Status("Correlating events…", console=console):
        groups = correlate_events(all_events)

    if groups:
        console.print(f"[bold]Correlation groups:[/bold] {len(groups)} found")
        for g in groups[:5]:
            console.print(
                f"  [{g.overall_severity}] {g.correlation_reason} "
                f"({len(g.events)} events)"
            )

    # --- LLM Analysis ---
    console.print(Rule("[bold]LLM Analysis[/bold]"))
    console.print(f"[dim]Model: {effective_model}[/dim]")

    system_prompt, user_prompt = build_context(all_events, groups)

    stream_cb = None if no_stream else _stream_callback
    use_thinking = not no_thinking

    try:
        result = run_diagnosis(
            system_prompt=system_prompt,
            user_prompt=user_prompt,
            model=effective_model,
            stream_callback=stream_cb,
            use_thinking=use_thinking,
        )
    except Exception as exc:
        console.print(f"\n[red]LLM call failed: {exc}[/red]")
        raise

    # --- Output ---
    console.print("\n")
    console.print(Rule("[bold]Diagnosis[/bold]"))
    render_diagnosis(result, all_events, groups)

    console.print("\n")
    render_commands(result)

    # Write report
    if output_path:
        fmt = "json" if output_path.endswith(".json") else "html"
        console.print(f"\n[dim]Writing {fmt.upper()} report to {output_path}…[/dim]")
        generate_report(result, all_events, groups, output_path=output_path, fmt=fmt)
        console.print(f"[green]Report saved:[/green] {output_path}")
    else:
        # Always offer to save
        console.print(
            "\n[dim]Tip: add --output report.html to save a full NOC report.[/dim]"
        )


@main.command()
@click.argument("input_file", metavar="FILE")
@click.option("--type", "file_type",
              type=click.Choice(["syslog", "config", "pcap", "cli"], case_sensitive=False),
              default=None,
              help="Force input type (auto-detected if omitted).")
@click.option("--device", default=None, metavar="NAME")
def parse(input_file, file_type, device):
    """Parse a single input file and show detected events (no LLM call)."""
    path = Path(input_file)
    if not path.exists():
        console.print(f"[red]File not found: {input_file}[/red]")
        sys.exit(1)

    suffix = path.suffix.lower()
    ftype = file_type or (
        "syslog" if suffix in (".log", ".syslog") else
        "config" if suffix in (".cfg", ".conf") else
        "pcap" if suffix in (".pcap", ".pcapng", ".cap") else
        "cli"
    )

    parsers = {
        "syslog": lambda: parse_syslog(path),
        "config": lambda: parse_config(path, device=device),
        "pcap": lambda: parse_pcap(path, device=device),
        "cli": lambda: parse_cli_output(path, device=device),
    }

    with Status(f"Parsing {ftype}: {path.name}…", console=console):
        events = parsers[ftype]()

    console.print(f"\nFound [bold]{len(events)}[/bold] events in {path.name}\n")
    from output.diagnosis import render_event_table
    render_event_table(events)


if __name__ == "__main__":
    main()
