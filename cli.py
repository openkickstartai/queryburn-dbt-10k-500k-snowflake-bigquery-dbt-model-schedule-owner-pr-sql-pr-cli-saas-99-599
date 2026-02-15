"""QueryBurn CLI — Cloud data warehouse query cost gating."""
import json, sys, dataclasses
from pathlib import Path

import click, yaml
from rich.console import Console
from rich.table import Table

from queryburn import analyze_sql, parse_dbt_manifest, gate_check
from dashboard import (
    render_cost_summary, render_pr_impact, render_anti_patterns,
    format_report_json,
)

console = Console()

SEV_COLORS = {"error": "red", "warning": "yellow", "info": "blue"}


def load_config(path: str = "queryburn.yaml") -> dict:
    """Load and validate YAML config with safety checks."""
    p = Path(path)
    if not p.exists():
        return {"warehouse": "snowflake", "max_cost_usd": 10.0, "block_on": ["error"]}
    raw = p.read_text()
    if len(raw) > 1_000_000:
        raise ValueError("Config exceeds 1MB safety limit")
    cfg = yaml.safe_load(raw)
    if not isinstance(cfg, dict):
        raise ValueError("Config must be a YAML mapping")
    return cfg


@click.group()
def cli():
    """QueryBurn — Stop expensive queries before they hit production."""


@cli.command()
@click.argument("sql_file", type=click.Path(exists=True))
@click.option("--warehouse", "-w", default="snowflake",
              type=click.Choice(["snowflake", "bigquery", "redshift"]))
@click.option("--config", "-c", default="queryburn.yaml")
@click.option("--output", "-o", default="table", type=click.Choice(["table", "json"]))
def scan(sql_file, warehouse, config, output):
    """Scan a SQL file for cost anti-patterns and estimate cost."""
    cfg = load_config(config)
    sql = Path(sql_file).read_text()
    wh = cfg.get("warehouse", warehouse)
    result = analyze_sql(sql, wh)
    blocked = gate_check(result, cfg.get("max_cost_usd", 10.0), cfg.get("block_on"))
    if output == "json":
        out = dataclasses.asdict(result)
        out["blocked"] = blocked
        click.echo(json.dumps(out, indent=2))
        if blocked:
            sys.exit(1)
        return
    tbl = Table(title=f"QueryBurn — {sql_file}")
    tbl.add_column("Rule", style="cyan")
    tbl.add_column("Severity")
    tbl.add_column("Message")
    tbl.add_column("Impact", justify="right")
    for f in result.findings:
        c = SEV_COLORS.get(f.severity, "white")
        tbl.add_row(f.rule, f"[{c}]{f.severity}[/]", f.message, f"${f.cost_impact:.2f}")
    console.print(tbl)
    console.print(f"\n\U0001f4b0 Est. cost: [bold]${result.estimated_cost_usd:.4f}[/bold]/exec")
    console.print(f"\U0001f511 Fingerprint: {result.query_fingerprint}")
    if blocked:
        console.print("\n\U0001f6ab [bold red]BLOCKED[/bold red] — exceeds cost policy")
        sys.exit(1)
    else:
        console.print("\n\u2705 [bold green]PASSED[/bold green]")


@cli.command(name="dbt-scan")
@click.argument("manifest", type=click.Path(exists=True))
@click.option("--warehouse", "-w", default="snowflake")
def dbt_scan(manifest, warehouse):
    """Scan all models in a dbt manifest.json for cost issues."""
    models = parse_dbt_manifest(manifest)
    tbl = Table(title="dbt Model Cost Attribution")
    tbl.add_column("Model", style="cyan")
    tbl.add_column("Owner")
    tbl.add_column("Issues", justify="right")
    tbl.add_column("Cost/Run", justify="right")
    total = 0.0
    for name, meta in models.items():
        if not meta.get("sql"):
            continue
        r = analyze_sql(meta["sql"], warehouse, model=name, owner=meta["owner"])
        total += r.estimated_cost_usd
        tbl.add_row(name, meta["owner"], str(len(r.findings)), f"${r.estimated_cost_usd:.4f}")
    console.print(tbl)
    console.print(f"\n\U0001f4b0 Total: [bold]${total:.4f}[/bold]/run")


if __name__ == "__main__":
    cli()


@cli.command()
@click.option("--format", "fmt", default="table", type=click.Choice(["table", "json"]))
@click.option("--config", "-c", default="queryburn.yaml")
@click.argument("sql_files", nargs=-1, type=click.Path(exists=True))
def report(fmt, config, sql_files):
    """Generate cost breakdown report for SQL files."""
    cfg = load_config(config)
    wh = cfg.get("warehouse", "snowflake")

    models = []
    all_issues = []

    for sql_file in sql_files:
        sql = Path(sql_file).read_text()
        result = analyze_sql(sql, wh)
        cost = result.estimated_cost_usd
        models.append({
            "model": Path(sql_file).stem,
            "owner": result.owner or "unassigned",
            "schedule": "daily",
            "monthly_cost": round(cost * 30, 2),
        })
        for f in result.findings:
            all_issues.append({
                "file": sql_file,
                "line": f.line,
                "type": f.rule,
                "severity": f.severity,
                "suggestion": f.message,
            })

    if fmt == "json":
        click.echo(format_report_json(models, {}, all_issues))
    else:
        from dashboard import _make_console as _mc
        rc = _mc()
        render_cost_summary(models, console=rc)
        if all_issues:
            render_anti_patterns(all_issues, console=rc)
