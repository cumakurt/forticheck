"""FortiCheck CLI — Command-line interface for firewall analysis."""

from __future__ import annotations

import logging
import sys
from datetime import datetime
from pathlib import Path

import click
import yaml
from rich.console import Console
from rich.panel import Panel
from rich.progress import Progress, SpinnerColumn, TextColumn
from rich.table import Table

from forticheck import __version__
from forticheck.core import Analyzer
from forticheck.diff import ConfigDiffResult, diff_devices
from forticheck.models.findings import AnalysisResult
from forticheck.normalizer.builder import CanonicalModelBuilder
from forticheck.parsers.fortigate import FortiGateParser
from forticheck.reporting.engine import ReportEngine

console = Console()


def setup_logging(verbose: bool) -> None:
    level = logging.DEBUG if verbose else logging.WARNING
    logging.basicConfig(
        level=level,
        format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
        datefmt="%H:%M:%S",
    )


@click.group()
@click.version_option(__version__, prog_name="forticheck")
def main() -> None:
    """FortiCheck — FortiGate Firewall Configuration Security Analyzer."""
    pass


@main.command()
@click.option(
    "--config", "-c",
    required=True,
    type=click.Path(exists=True, dir_okay=False),
    help="Path to FortiGate configuration file (.conf)",
)
@click.option(
    "--output", "-o",
    default=None,
    help="Output report file path (default: <config_stem>_<YYYY-MM-DD_HHMMSS>.html)",
)
@click.option(
    "--format", "-f",
    "output_format",
    type=click.Choice(["html", "json", "both"]),
    default="html",
    help="Output format (default: html)",
)
@click.option(
    "--zones-trust", "-z",
    type=click.Path(exists=True, dir_okay=False),
    default=None,
    help="YAML file with custom zone trust levels",
)
@click.option(
    "--rules", "-r",
    type=click.Path(exists=True, dir_okay=False),
    default=None,
    help="Path to YAML file with custom security rules (forbid_service, require_security_profile)",
)
@click.option(
    "--min-severity",
    type=click.Choice(["info", "low", "medium", "high", "critical"]),
    default=None,
    help="Include only findings with this severity or higher in the report",
)
@click.option(
    "--verbose", "-v",
    is_flag=True,
    default=False,
    help="Enable verbose logging",
)
def analyze(
    config: str,
    output: str,
    output_format: str,
    zones_trust: str | None,
    rules: str | None,
    min_severity: str | None,
    verbose: bool,
) -> None:
    """Analyze a FortiGate configuration file for security risks."""
    setup_logging(verbose)

    # Default output: config file name + timestamp (e.g. fw_corp_2025-02-13_143022.html)
    if output is None:
        config_stem = Path(config).stem
        timestamp = datetime.now().strftime("%Y-%m-%d_%H%M%S")
        output = f"{config_stem}_{timestamp}.html"

    console.print(Panel.fit(
        "[bold cyan]FortiCheck v{version}[/]\n"
        "[dim]FortiGate Firewall Configuration Security Analyzer[/]".format(
            version=__version__
        ),
        border_style="cyan",
    ))

    # Load trust overrides
    trust_overrides = None
    if zones_trust:
        try:
            with open(zones_trust, encoding="utf-8") as f:
                data = yaml.safe_load(f)
                if data and "zones" in data:
                    trust_overrides = {
                        k: v.get("trust_level", 50) if isinstance(v, dict) else v
                        for k, v in data["zones"].items()
                    }
                    console.print(f"[dim]Loaded custom trust levels from {zones_trust}[/]")
        except (yaml.YAMLError, OSError) as e:
            console.print(
                f"[yellow]Warning: Could not load zone trust file '{zones_trust}': {e}. "
                "Using default zone trust levels.[/]"
            )

    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        console=console,
        transient=True,
    ) as progress:

        # Phase 1: Parse
        task = progress.add_task("Parsing configuration...", total=None)
        parser = FortiGateParser()
        try:
            parser.parse_file(config)
        except Exception as e:
            console.print(f"[red]Error parsing config: {e}[/]")
            sys.exit(1)
        progress.update(task, description="Config parsed", completed=True)

        # Phase 2: Normalize
        task = progress.add_task("Building canonical model...", total=None)
        builder = CanonicalModelBuilder(trust_overrides=trust_overrides)
        device, resolver = builder.build(parser)
        progress.update(task, description="Model built", completed=True)

        # Phase 3: Analyze
        task = progress.add_task("Running security analysis...", total=None)
        analyzer = Analyzer(device, resolver, parser, custom_rules_path=rules)
        result = analyzer.run()
        progress.update(task, description="Analysis complete", completed=True)

        # Apply min-severity filter if requested
        if min_severity:
            severity_order = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}
            threshold = severity_order[min_severity]
            result.findings = [
                f for f in result.findings
                if severity_order.get(f.severity.value, 0) >= threshold
            ]

        # Phase 4: Report
        task = progress.add_task("Generating report...", total=None)
        report_engine = ReportEngine()

        output_path = Path(output)

        if output_format in ("html", "both"):
            html_path = output_path if output_path.suffix == ".html" else output_path.with_suffix(".html")
            report_engine.generate_html(result, str(html_path))
            console.print(f"[green]HTML report written: {html_path}[/]")

        if output_format in ("json", "both"):
            json_path = output_path.with_suffix(".json")
            report_engine.generate_json(result, str(json_path))
            console.print(f"[green]JSON report written: {json_path}[/]")

        progress.update(task, description="Report generated", completed=True)

    # Summary
    console.print()
    _print_summary(result)


def _print_summary(result: AnalysisResult) -> None:
    """Print analysis summary to console."""
    table = Table(title="Analysis Summary", border_style="dim")
    table.add_column("Metric", style="cyan")
    table.add_column("Value", style="white", justify="right")

    table.add_row("Device", result.device_hostname)
    table.add_row("Firmware", result.firmware_version or "N/A")
    table.add_row("Total Policies", str(result.total_policies))
    table.add_row("Total Zones", str(result.total_zones))
    table.add_row("Total Findings", str(len(result.findings)))
    table.add_row("", "")

    sev_colors = {
        "Critical": "red",
        "High": "yellow",
        "Medium": "bright_yellow",
        "Low": "blue",
        "Info": "dim",
    }

    for sev_name, findings in [
        ("Critical", result.critical_findings),
        ("High", result.high_findings),
        ("Medium", result.medium_findings),
        ("Low", result.low_findings),
        ("Info", result.info_findings),
    ]:
        color = sev_colors.get(sev_name, "white")
        table.add_row(
            f"[{color}]{sev_name}[/]",
            f"[{color}]{len(findings)}[/]",
        )

    table.add_row("", "")
    risk_color = "red" if result.device_risk_score >= 70 else "yellow" if result.device_risk_score >= 40 else "green"
    table.add_row(
        f"[bold {risk_color}]Device Risk Score[/]",
        f"[bold {risk_color}]{result.device_risk_score:.1f} / 100[/]",
    )

    console.print(table)

    if result.attack_paths:
        console.print(
            f"\n[bold red]Note: {len(result.attack_paths)} attack path(s) identified. "
            "Review the report for details.[/]"
        )


@main.command()
@click.option(
    "--before", "-b",
    required=True,
    type=click.Path(exists=True, dir_okay=False),
    help="Path to older FortiGate configuration file",
)
@click.option(
    "--after", "-a",
    required=True,
    type=click.Path(exists=True, dir_okay=False),
    help="Path to newer FortiGate configuration file",
)
@click.option(
    "--output", "-o",
    default="forticheck_diff.json",
    help="Output path for diff report (default: forticheck_diff.json)",
)
@click.option("--verbose", "-v", is_flag=True, help="Enable verbose logging")
def diff(before: str, after: str, output: str, verbose: bool) -> None:
    """Compare two FortiGate configuration files (policy add/remove/change)."""
    import dataclasses
    import json

    setup_logging(verbose)
    console.print(Panel.fit(
        f"[bold cyan]FortiCheck v{__version__}[/]\n[dim]Configuration diff[/]",
        border_style="cyan",
    ))

    parser_before = FortiGateParser()
    parser_after = FortiGateParser()
    try:
        parser_before.parse_file(before)
        parser_after.parse_file(after)
    except Exception as e:
        console.print(f"[red]Error parsing config: {e}[/]")
        sys.exit(1)

    builder = CanonicalModelBuilder()
    device_before, _ = builder.build(parser_before)
    device_after, _ = builder.build(parser_after)
    diff_result = diff_devices(device_before, device_after)

    out_path = Path(output)
    out_path.parent.mkdir(parents=True, exist_ok=True)
    data = {
        "before_hostname": diff_result.before_hostname,
        "after_hostname": diff_result.after_hostname,
        "added": [dataclasses.asdict(d) for d in diff_result.added],
        "removed": [dataclasses.asdict(d) for d in diff_result.removed],
        "changed": [dataclasses.asdict(d) for d in diff_result.changed],
    }
    out_path.write_text(json.dumps(data, indent=2, default=str), encoding="utf-8")
    console.print(f"[green]Diff report: {out_path}[/]")
    console.print(
        f"  Added: {len(diff_result.added)}, "
        f"Removed: {len(diff_result.removed)}, "
        f"Changed: {len(diff_result.changed)}"
    )


if __name__ == "__main__":
    main()
