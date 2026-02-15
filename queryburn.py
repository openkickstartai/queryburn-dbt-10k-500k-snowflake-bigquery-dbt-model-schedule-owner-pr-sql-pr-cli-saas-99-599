"""QueryBurn — Query cost attribution & anti-pattern detection engine."""
import json, re, hashlib
from dataclasses import dataclass, field
from pathlib import Path
from typing import List, Dict

PRICE_PER_TB = {"snowflake": 2.0, "bigquery": 5.0, "redshift": 0.25}


@dataclass
class Finding:
    rule: str
    severity: str
    message: str
    line: int = 0
    cost_impact: float = 0.0


@dataclass
class AnalysisResult:
    query_fingerprint: str
    findings: List[Finding] = field(default_factory=list)
    estimated_cost_usd: float = 0.0
    model: str = ""
    owner: str = ""


def sanitize_sql(sql):
    """Validate and sanitize SQL input with strict safety checks."""
    if not sql or not isinstance(sql, str):
        raise ValueError("SQL input must be a non-empty string")
    if len(sql) > 1_000_000:
        raise ValueError("SQL exceeds 1MB safety limit")
    return sql.strip()


def fingerprint(sql: str) -> str:
    """Generate stable SHA-256 fingerprint with literal stripping."""
    norm = re.sub(r'\s+', ' ', sql.upper().strip())
    norm = re.sub(r"'[^']*'", "'?'", norm)
    norm = re.sub(r'\b\d+\b', '?', norm)
    return hashlib.sha256(norm.encode()).hexdigest()[:16]


def detect_antipatterns(sql: str) -> List[Finding]:
    """Detect SQL anti-patterns that cause warehouse cost explosions."""
    findings, upper = [], sql.upper()
    for i, line in enumerate(sql.split('\n')):
        if re.search(r'SELECT\s+\*', line, re.IGNORECASE):
            findings.append(Finding("select-star", "warning",
                "SELECT * — use column pruning to reduce scanned bytes", i + 1, 0.3))
    if re.search(r'\bCROSS\s+JOIN\b', upper):
        findings.append(Finding("cartesian-product", "error",
            "CROSS JOIN — potential cartesian product cost explosion", 0, 10.0))
    joins = len(re.findall(r'\bJOIN\b', upper))
    ons = len(re.findall(r'\bON\b', upper))
    cross = len(re.findall(r'CROSS\s+JOIN', upper))
    if joins > ons + cross and joins > 0:
        findings.append(Finding("join-without-on", "error",
            "JOIN without ON clause — likely cartesian product", 0, 10.0))
    has_from = bool(re.search(r'\bFROM\b', upper))
    has_where = bool(re.search(r'\bWHERE\b', upper))
    has_limit = bool(re.search(r'\bLIMIT\b', upper))
    if has_from and not has_where and not has_limit:
        findings.append(Finding("full-table-scan", "warning",
            "No WHERE or LIMIT — full table scan likely", 0, 1.0))
    if re.search(r'\bUNION\b(?!\s+ALL)', upper):
        findings.append(Finding("union-without-all", "info",
            "UNION without ALL causes unnecessary dedup sort", 0, 0.2))
    if re.search(r'\bORDER\s+BY\b', upper) and not has_limit:
        findings.append(Finding("order-without-limit", "warning",
            "ORDER BY without LIMIT forces full sort", 0, 0.5))
    return findings


def estimate_cost(sql: str, warehouse: str = "snowflake",
                  table_bytes: int = 10_737_418_240) -> float:
    """Estimate query cost in USD using heuristic byte-scan model."""
    upper, price = sql.upper(), PRICE_PER_TB.get(warehouse, 2.0)
    b = float(table_bytes)
    if re.search(r'SELECT\s+\*', upper):
        b *= 1.5
    if re.search(r'\bWHERE\b', upper):
        b *= 0.3
    m = re.search(r'\bLIMIT\s+(\d+)', upper)
    if m and int(m.group(1)) < 1000:
        b *= 0.01
    if re.search(r'\bCROSS\s+JOIN\b', upper):
        b *= 100
    b *= (1 + len(re.findall(r'\bJOIN\b', upper)) * 0.5)
    return round((b / 1e12) * price, 4)


def analyze_sql(sql: str, warehouse: str = "snowflake",
                model: str = "", owner: str = "") -> AnalysisResult:
    """Full analysis: validate, detect anti-patterns, estimate cost."""
    clean = sanitize_sql(sql)
    return AnalysisResult(
        query_fingerprint=fingerprint(clean),
        findings=detect_antipatterns(clean),
        estimated_cost_usd=estimate_cost(clean, warehouse),
        model=model, owner=owner)


def parse_dbt_manifest(path: str) -> Dict[str, Dict]:
    """Parse dbt manifest.json with safety limits."""
    p = Path(path)
    if not p.exists():
        raise FileNotFoundError(f"Manifest not found: {path}")
    if p.stat().st_size > 100_000_000:
        raise ValueError("Manifest exceeds 100MB safety limit")
    data = json.loads(p.read_text())
    models = {}
    for key, node in data.get("nodes", {}).items():
        if node.get("resource_type") == "model":
            models[node["name"]] = {
                "owner": node.get("meta", {}).get("owner", "unknown"),
                "tags": node.get("tags", []),
                "sql": node.get("compiled_sql", node.get("raw_sql", "")),
            }
    return models


def gate_check(result: AnalysisResult, max_cost: float = 10.0,
               block_on: list = None) -> bool:
    """Returns True if the query should be blocked by cost policy."""
    if block_on is None:
        block_on = ["error"]
    if result.estimated_cost_usd > max_cost:
        return True
    return any(f.severity in block_on for f in result.findings)
