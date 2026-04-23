"""Rich terminal and JSON reporters for dep-timemachine results."""
from __future__ import annotations

import json
from datetime import datetime
from pathlib import Path
from typing import TYPE_CHECKING

from rich.console import Console
from rich.table import Table
from rich import box

if TYPE_CHECKING:
    from dep_timemachine.git_walker import VulnEntry

_SEVERITY_COLORS = {
    "CRITICAL": "bold red",
    "HIGH": "red",
    "MEDIUM": "yellow",
    "LOW": "cyan",
    "UNKNOWN": "dim",
}

console = Console()


def print_results(entries: list["VulnEntry"], show_all: bool = False) -> None:
    if not entries:
        console.print("[green]✓ No vulnerabilities found in scanned history.[/green]")
        return

    console.print(f"\n[bold]Found [red]{len(entries)}[/red] CVE entry point(s)[/bold]\n")

    table = Table(box=box.ROUNDED, show_lines=True)
    table.add_column("CVE / ID", style="bold")
    table.add_column("Severity", justify="center")
    table.add_column("Package")
    table.add_column("Introduced commit")
    table.add_column("Date")
    table.add_column("Author")
    table.add_column("Summary", max_width=50)

    for e in entries:
        sev_style = _SEVERITY_COLORS.get(e.vulnerability.severity, "")
        table.add_row(
            e.vulnerability.id,
            f"[{sev_style}]{e.vulnerability.severity}[/{sev_style}]",
            f"{e.dependency.ecosystem}:{e.dependency.name}",
            e.commit.sha,
            e.commit.date,
            e.commit.author,
            e.vulnerability.summary[:100],
        )

    console.print(table)


def export_json(entries: list["VulnEntry"], output: Path) -> None:
    data = {
        "generated_at": datetime.utcnow().isoformat() + "Z",
        "total": len(entries),
        "entries": [
            {
                "cve_id": e.vulnerability.id,
                "aliases": e.vulnerability.aliases,
                "severity": e.vulnerability.severity,
                "summary": e.vulnerability.summary,
                "package": {
                    "ecosystem": e.dependency.ecosystem,
                    "name": e.dependency.name,
                    "version_spec": e.dependency.version_spec,
                },
                "introduced_at": {
                    "sha": e.commit.sha,
                    "date": e.commit.date,
                    "author": e.commit.author,
                    "message": e.commit.message,
                },
            }
            for e in entries
        ],
    }
    output.write_text(json.dumps(data, indent=2), encoding="utf-8")
    console.print(f"[green]JSON report written to[/green] {output}")
