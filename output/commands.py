"""Render and format suggested remediation and verification commands."""
from __future__ import annotations

from rich.console import Console
from rich.panel import Panel
from rich.syntax import Syntax
from rich.rule import Rule

from models import DiagnosisResult

console = Console()


def render_commands(result: DiagnosisResult) -> None:
    """Print remediation and verification commands to the terminal."""
    if not result.remediation and not result.verification:
        console.print("[dim]No remediation commands suggested.[/dim]")
        return

    console.print(Rule("[bold]Remediation Commands[/bold]"))

    if not result.remediation:
        console.print("[dim]No specific remediation commands provided.[/dim]")
    else:
        for i, item in enumerate(result.remediation, 1):
            device = item.get("device", "unknown")
            description = item.get("description", "")
            commands = item.get("commands", [])

            console.print(f"\n[bold cyan]Step {i}[/bold cyan] — [italic]{description}[/italic]")
            console.print(f"[dim]Device: {device}[/dim]")

            if commands:
                cmd_text = "\n".join(commands)
                syntax = Syntax(
                    cmd_text,
                    "text",
                    theme="monokai",
                    line_numbers=False,
                    padding=(0, 1),
                )
                console.print(Panel(syntax, border_style="cyan", expand=False))

    if result.verification:
        console.print(Rule("[bold]Verification Commands[/bold]"))
        console.print("[dim]Run these after applying the fix to confirm resolution:[/dim]\n")
        for cmd in result.verification:
            console.print(f"  [green]>[/green] [bold]{cmd}[/bold]")


def commands_as_text(result: DiagnosisResult) -> str:
    """Return remediation commands as a plain string for inclusion in reports."""
    lines = []
    for item in result.remediation:
        device = item.get("device", "unknown")
        description = item.get("description", "")
        commands = item.get("commands", [])
        lines.append(f"! Device: {device} — {description}")
        lines.extend(commands)
        lines.append("")

    if result.verification:
        lines.append("! Verification:")
        lines.extend(result.verification)

    return "\n".join(lines)
