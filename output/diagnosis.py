"""Render the LLM diagnosis as rich terminal output."""
from __future__ import annotations

from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.text import Text
from rich import box

from models import DiagnosisResult, Event, CorrelatedGroup, SEVERITY_ORDER


_SEV_COLOURS = {
    "P1": "bold red",
    "P2": "bold yellow",
    "P3": "bold cyan",
    "INFO": "dim",
}

_SEV_ICONS = {
    "P1": "[red]CRITICAL[/red]",
    "P2": "[yellow]WARNING[/yellow]",
    "P3": "[cyan]ADVISORY[/cyan]",
    "INFO": "[dim]INFO[/dim]",
}

console = Console()


def _sev_badge(sev: str) -> str:
    colour = _SEV_COLOURS.get(sev, "white")
    return f"[{colour}]{sev}[/{colour}]"


def render_event_table(events: list[Event]) -> None:
    """Print a summary table of all events to the terminal."""
    table = Table(
        title="Ingested Events",
        box=box.SIMPLE_HEAVY,
        show_lines=False,
        expand=True,
    )
    table.add_column("Sev", width=4, justify="center")
    table.add_column("Source", width=7)
    table.add_column("Device", width=14, no_wrap=True)
    table.add_column("Interface", width=20, no_wrap=True)
    table.add_column("Message", ratio=1)

    # Sort by severity then time
    sorted_events = sorted(
        events,
        key=lambda e: (SEVERITY_ORDER.get(e.severity, 99),),
    )

    for e in sorted_events[:50]:  # cap at 50 rows
        sev_text = Text(e.severity, style=_SEV_COLOURS.get(e.severity, "white"))
        table.add_row(
            sev_text,
            e.source_type[:6],
            e.device or "—",
            e.interface or "—",
            e.message[:100],
        )

    if len(events) > 50:
        table.add_row("…", "…", "…", "…", f"…and {len(events) - 50} more events")

    console.print(table)


def render_diagnosis(
    result: DiagnosisResult,
    events: list[Event],
    groups: list[CorrelatedGroup],
) -> None:
    """Print full diagnosis to the terminal using Rich."""
    sev_colour = _SEV_COLOURS.get(result.severity, "white")

    # Header panel
    console.print(Panel(
        f"[bold]Overall Severity:[/bold] [{sev_colour}]{result.severity}[/{sev_colour}]",
        title="[bold white]netdiag-ai Diagnosis[/bold white]",
        border_style=sev_colour,
        expand=False,
    ))

    # Diagnosis text
    console.print("\n[bold underline]Diagnosis[/bold underline]")
    console.print(result.diagnosis)

    console.print("\n[bold underline]Root Cause[/bold underline]")
    console.print(f"[italic]{result.root_cause}[/italic]")

    # Affected scope
    if result.affected_devices or result.affected_interfaces:
        console.print("\n[bold underline]Affected Scope[/bold underline]")
        if result.affected_devices:
            console.print(f"  Devices:    {', '.join(result.affected_devices)}")
        if result.affected_interfaces:
            console.print(f"  Interfaces: {', '.join(result.affected_interfaces)}")

    # Correlations
    if result.correlations:
        console.print("\n[bold underline]Correlations[/bold underline]")
        for c in result.correlations:
            console.print(f"  [cyan]•[/cyan] {c}")

    # Event table
    if events:
        console.print()
        render_event_table(events)
