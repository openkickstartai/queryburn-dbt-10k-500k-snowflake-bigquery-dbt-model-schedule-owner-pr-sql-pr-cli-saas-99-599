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


# ============================================================
# Adversarial & edge-case tests (18 new test cases)
# ============================================================


class TestAdversarialInput:
    """Tests for malicious and malformed SQL input."""

    def test_null_bytes_stripped(self):
        """Null bytes in SQL should be stripped, not crash."""
        sql = "SELECT\x00 id FROM\x00 users WHERE id = 1"
        result = sanitize_sql(sql)
        assert "SELECT" in result
        assert "\x00" not in result

    def test_unicode_control_chars_stripped(self):
        """Unicode control characters should be stripped safely."""
        sql = "SELECT id FROM users\x0b\x0c WHERE active = 1"
        result = sanitize_sql(sql)
        assert "\x0b" not in result
        assert "\x0c" not in result
        findings = detect_antipatterns(result)
        assert isinstance(findings, list)

    def test_deeply_nested_subqueries_no_crash(self):
        """5000-level nested subqueries should not crash or hang."""
        inner = "SELECT 1"
        for _ in range(5000):
            inner = f"SELECT * FROM ({inner}) sub"
        # Should not raise — we only care about no crash
        findings = detect_antipatterns(inner)
        assert isinstance(findings, list)
        # Should detect select-star (the outermost at minimum)
        rules = [f.rule for f in findings]
        assert "select-star" in rules

    def test_bytes_input_raises_valueerror(self):
        """Non-string bytes input should raise ValueError, not TypeError."""
        with pytest.raises(ValueError, match="non-empty"):
            sanitize_sql(b"SELECT 1")

    def test_only_null_bytes_raises(self):
        """SQL containing only null bytes should raise ValueError after stripping."""
        with pytest.raises(ValueError, match="non-empty"):
            sanitize_sql("\x00\x00\x00")


class TestFullTableScanEdgeCases:
    """Edge cases for full table scan detection."""

    def test_where_1_eq_1_not_full_scan(self):
        """SELECT * FROM t WHERE 1=1 has a WHERE clause — no full-table-scan."""
        sql = "SELECT * FROM t WHERE 1=1"
        rules = [f.rule for f in detect_antipatterns(sql)]
        assert "full-table-scan" not in rules
        # But select-star should still fire
        assert "select-star" in rules

    def test_select_star_with_limit_0(self):
        """SELECT * FROM t LIMIT 0 should still detect select-star."""
        sql = "SELECT * FROM t LIMIT 0"
        rules = [f.rule for f in detect_antipatterns(sql)]
        assert "select-star" in rules

    def test_cte_select_star_detected(self):
        """SELECT * inside a CTE body should be detected."""
        sql = "WITH cte AS (SELECT * FROM users) SELECT id FROM cte WHERE id = 1"
        rules = [f.rule for f in detect_antipatterns(sql)]
        assert "select-star" in rules


class TestCartesianProductEdgeCases:
    """Edge cases for cartesian product / join detection."""

    def test_comma_join_detected(self):
        """Comma-separated tables (implicit cross join) should be detected."""
        sql = "SELECT a.id, b.name FROM users a, orders b"
        rules = [f.rule for f in detect_antipatterns(sql)]
        has_join_warning = "join-without-on" in rules or "cartesian-product" in rules
        assert has_join_warning, f"Expected join/cartesian warning, got {rules}"

    def test_self_join_without_on(self):
        """Self-join without ON clause should be detected."""
        sql = "SELECT a.id FROM users a, users b"
        rules = [f.rule for f in detect_antipatterns(sql)]
        has_join_warning = "join-without-on" in rules or "cartesian-product" in rules
        assert has_join_warning, f"Expected join/cartesian warning, got {rules}"

    def test_multi_table_comma_join(self):
        """Three comma-separated tables should be detected."""
        sql = "SELECT * FROM a, b, c"
        rules = [f.rule for f in detect_antipatterns(sql)]
        has_join_warning = "join-without-on" in rules or "cartesian-product" in rules
        assert has_join_warning, f"Expected join/cartesian warning, got {rules}"

    def test_explicit_cross_join_detected(self):
        """Explicit CROSS JOIN keyword must trigger cartesian-product."""
        sql = "SELECT a.x FROM foo a CROSS JOIN bar b"
        rules = [f.rule for f in detect_antipatterns(sql)]
        assert "cartesian-product" in rules


class TestFalsePositivePrevention:
    """Comments and string literals must not trigger false alarms."""

    def test_select_star_in_line_comment_no_alert(self):
        """SELECT * inside a -- comment should NOT trigger select-star."""
        sql = "-- SELECT * FROM users\nSELECT id FROM users WHERE active = 1"
        rules = [f.rule for f in detect_antipatterns(sql)]
        assert "select-star" not in rules

    def test_select_star_in_block_comment_no_alert(self):
        """SELECT * inside /* */ block comment should NOT trigger select-star."""
        sql = "/* SELECT * FROM users */\nSELECT id FROM users WHERE active = 1"
        rules = [f.rule for f in detect_antipatterns(sql)]
        assert "select-star" not in rules

    def test_cross_join_in_string_literal_no_alert(self):
        """CROSS JOIN inside a string literal should NOT trigger cartesian-product."""
        sql = "SELECT id FROM users WHERE note = 'CROSS JOIN is bad' AND active = 1"
        rules = [f.rule for f in detect_antipatterns(sql)]
        assert "cartesian-product" not in rules


class TestAnalyzeSqlEdgeCases:
    """Edge cases for the top-level analyze_sql function."""

    def test_analyze_empty_raises(self):
        """Empty string should raise ValueError."""
        with pytest.raises(ValueError):
            analyze_sql("")

    def test_analyze_none_raises(self):
        """None input should raise ValueError."""
        with pytest.raises(ValueError):
            analyze_sql(None)

    def test_analyze_with_null_bytes_succeeds(self):
        """SQL with embedded null bytes should be analyzed after sanitization."""
        result = analyze_sql("SELECT\x00 id FROM users WHERE id = 1")
        assert result.query_fingerprint
        assert isinstance(result.findings, list)
