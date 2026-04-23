"""CLI entry point for dep-timemachine."""
from __future__ import annotations

import asyncio
import sys
from pathlib import Path

import click
from rich.console import Console
from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn, TaskProgressColumn

from dep_timemachine import __version__
from dep_timemachine.git_walker import scan_history
from dep_timemachine.reporter import export_json, print_results

console = Console()


@click.group()
@click.version_option(__version__, prog_name="dep-timemachine")
def main() -> None:
    """Travel back through your dependency history to find when CVEs entered your project."""


@main.command()
@click.argument("repo_path", default=".", type=click.Path(exists=True, file_okay=False))
@click.option("-p", "--package", default=None, help="Filter to a specific package name.")
@click.option("-n", "--max-commits", default=500, show_default=True, help="Max git commits to scan.")
@click.option("-o", "--output", default=None, type=click.Path(), help="Export results to JSON file.")
@click.option("--no-color", is_flag=True, help="Disable colored output.")
def scan(repo_path: str, package: str | None, max_commits: int, output: str | None, no_color: bool) -> None:
    """Scan a git repository's history for CVE entry points."""
    if no_color:
        console._highlight = False  # noqa: SLF001

    console.print(f"[bold cyan]dep-timemachine[/bold cyan] v{__version__}")
    console.print(f"Scanning [bold]{Path(repo_path).resolve()}[/bold] (up to {max_commits} commits)\n")

    entries_container: list = []

    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        BarColumn(),
        TaskProgressColumn(),
        console=console,
        transient=True,
    ) as progress:
        task = progress.add_task("Walking commits...", total=max_commits)

        def _progress(current: int, total: int) -> None:
            progress.update(task, completed=current, total=total)

        async def _run() -> None:
            entries = await scan_history(
                repo_path=repo_path,
                max_commits=max_commits,
                target_package=package,
                progress_callback=_progress,
            )
            entries_container.extend(entries)

        try:
            asyncio.run(_run())
        except ValueError as exc:
            console.print(f"[red]Error:[/red] {exc}")
            sys.exit(1)

    print_results(entries_container)

    if output:
        export_json(entries_container, Path(output))


@main.command()
@click.argument("manifest", type=click.Path(exists=True, dir_okay=False))
@click.option("-o", "--output", default=None, type=click.Path(), help="Export results to JSON file.")
def check(manifest: str, output: str | None) -> None:
    """Check a single manifest file for known CVEs (no git history)."""
    from dep_timemachine.parsers import parse_file
    from dep_timemachine.osv_client import query_batch, close_client
    from dep_timemachine.git_walker import CommitSnapshot, VulnEntry
    from dep_timemachine.reporter import print_results, export_json
    import datetime

    p = Path(manifest)
    deps = parse_file(p)
    if not deps:
        console.print(f"[yellow]No dependencies parsed from {p.name}[/yellow]")
        return

    console.print(f"Checking [bold]{len(deps)}[/bold] dependencies from [bold]{p.name}[/bold]\n")

    packages = [(d.ecosystem, d.name, d.version_spec or None) for d in deps]

    async def _run():
        result = await query_batch(packages)
        await close_client()
        return result

    vuln_map = asyncio.run(_run())

    dummy_commit = CommitSnapshot(
        sha="current",
        author="local",
        date=datetime.date.today().isoformat(),
        message="(manifest check)",
        dependencies=deps,
    )

    entries = []
    seen = set()
    for dep in deps:
        key = (dep.ecosystem, dep.name)
        for vuln in vuln_map.get(key, []):
            ek = (dep.ecosystem, dep.name.lower(), vuln.id)
            if ek not in seen:
                seen.add(ek)
                entries.append(VulnEntry(commit=dummy_commit, dependency=dep, vulnerability=vuln, introduced_at_commit=True))

    print_results(entries)
    if output:
        export_json(entries, Path(output))


if __name__ == "__main__":
    main()
