"""QueryBurn test suite — input validation, anti-patterns, cost, gating."""
import json, os, tempfile
import pytest
from queryburn import (
    sanitize_sql, fingerprint, detect_antipatterns,
    estimate_cost, analyze_sql, parse_dbt_manifest, gate_check,
)


class TestInputValidation:
    def test_empty_sql_raises(self):
        with pytest.raises(ValueError, match="non-empty"):
            sanitize_sql("")

    def test_none_sql_raises(self):
        with pytest.raises(ValueError, match="non-empty"):
            sanitize_sql(None)

    def test_oversized_sql_raises(self):
        with pytest.raises(ValueError, match="1MB"):
            sanitize_sql("SELECT " + "x" * 1_000_001)

    def test_valid_sql_passes(self):
        assert sanitize_sql("  SELECT 1  ") == "SELECT 1"


class TestAntiPatternDetection:
    def test_select_star_detected(self):
        rules = [f.rule for f in detect_antipatterns("SELECT * FROM users")]
        assert "select-star" in rules

    def test_cartesian_product_detected(self):
        sql = "SELECT a.id FROM orders a CROSS JOIN users b"
        rules = [f.rule for f in detect_antipatterns(sql)]
        assert "cartesian-product" in rules

    def test_full_table_scan_detected(self):
        rules = [f.rule for f in detect_antipatterns("SELECT id FROM users")]
        assert "full-table-scan" in rules

    def test_clean_query_has_no_errors(self):
        sql = "SELECT id, name FROM users WHERE active = 1 LIMIT 100"
        errors = [f for f in detect_antipatterns(sql) if f.severity == "error"]
        assert len(errors) == 0

    def test_union_without_all(self):
        sql = "SELECT id FROM a UNION SELECT id FROM b"
        rules = [f.rule for f in detect_antipatterns(sql)]
        assert "union-without-all" in rules

    def test_union_all_is_clean(self):
        sql = "SELECT id FROM a WHERE x = 1 UNION ALL SELECT id FROM b WHERE y = 2"
        rules = [f.rule for f in detect_antipatterns(sql)]
        assert "union-without-all" not in rules

    def test_order_without_limit(self):
        sql = "SELECT id FROM users WHERE active = 1 ORDER BY created_at"
        rules = [f.rule for f in detect_antipatterns(sql)]
        assert "order-without-limit" in rules


class TestCostEstimation:
    def test_cross_join_costs_much_more(self):
        safe = estimate_cost("SELECT id FROM users WHERE id = 1")
        dangerous = estimate_cost("SELECT * FROM a CROSS JOIN b")
        assert dangerous > safe * 10

    def test_bigquery_more_expensive_per_tb(self):
        cost_sf = estimate_cost("SELECT * FROM t", "snowflake")
        cost_bq = estimate_cost("SELECT * FROM t", "bigquery")
        assert cost_bq > cost_sf

    def test_where_clause_reduces_cost(self):
        no_where = estimate_cost("SELECT id FROM t")
        with_where = estimate_cost("SELECT id FROM t WHERE id = 1")
        assert with_where < no_where


class TestFingerprint:
    def test_stable(self):
        assert fingerprint("SELECT * FROM t") == fingerprint("SELECT * FROM t")

    def test_whitespace_invariant(self):
        assert fingerprint("SELECT  *  FROM  t") == fingerprint("SELECT * FROM t")

    def test_literal_invariant(self):
        assert fingerprint("WHERE id = 1") == fingerprint("WHERE id = 2")


class TestGating:
    def test_blocks_high_cost(self):
        result = analyze_sql("SELECT * FROM a CROSS JOIN b")
        assert gate_check(result, max_cost=0.0001) is True

    def test_passes_safe_query(self):
        result = analyze_sql("SELECT id FROM users WHERE id = 1 LIMIT 10")
        assert gate_check(result, max_cost=100.0, block_on=[]) is False

    def test_blocks_on_error_severity(self):
        result = analyze_sql("SELECT a.id FROM x a CROSS JOIN y b WHERE a.id = 1")
        assert gate_check(result, max_cost=9999, block_on=["error"]) is True


class TestDbtManifest:
    def test_parse_manifest_extracts_models(self):
        manifest = {"nodes": {"model.proj.users": {
            "resource_type": "model", "name": "users",
            "meta": {"owner": "data-team"}, "tags": ["daily"],
            "compiled_sql": "SELECT * FROM raw.users",
            "schema": "public", "database": "analytics"}}}
        with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as f:
            json.dump(manifest, f)
            path = f.name
        try:
            models = parse_dbt_manifest(path)
            assert "users" in models
            assert models["users"]["owner"] == "data-team"
            assert "SELECT" in models["users"]["sql"]
        finally:
            os.unlink(path)
