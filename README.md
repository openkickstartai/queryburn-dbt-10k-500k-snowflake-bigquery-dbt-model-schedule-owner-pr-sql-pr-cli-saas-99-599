# QueryBurn 🔥

**Stop expensive queries before they hit production.**

QueryBurn detects SQL anti-patterns that cause cost explosions, estimates per-query cost for Snowflake/BigQuery/Redshift, and blocks PRs that would blow up your monthly warehouse bill.

## 🚀 Quick Start

```bash
pip install -r requirements.txt

# Scan a SQL file
python cli.py scan query.sql --warehouse snowflake

# JSON output for CI parsing
python cli.py scan query.sql -o json

# Scan all models in a dbt manifest
python cli.py dbt-scan target/manifest.json
```

## ⚡ What It Detects

| Rule | Severity | Typical Cost Impact |
|------|----------|--------------------|
| `select-star` | warning | +30% bytes scanned |
| `cartesian-product` | error | 100x cost explosion |
| `join-without-on` | error | 100x cost explosion |
| `full-table-scan` | warning | +100% bytes scanned |
| `union-without-all` | info | +20% compute |
| `order-without-limit` | warning | +50% compute |

## 📊 Why Pay for QueryBurn?

> The average data team wastes **30-40%** of warehouse budget on unoptimized queries.
> A single CROSS JOIN in a dbt model running hourly can add **$10K+/month**.
> One blocked bad PR pays for a **full year** of QueryBurn Pro.

## 💰 Pricing

| Feature | Free | Pro $99/mo | Enterprise $599/mo |
|---|---|---|---|
| Anti-pattern detection | ✅ 6 rules | ✅ 20+ rules | ✅ Custom rules engine |
| Cost estimation | ✅ Heuristic | ✅ EXPLAIN-based | ✅ Historical actual costs |
| dbt manifest scan | ✅ | ✅ | ✅ |
| PR gate (CI exit code) | ✅ | ✅ | ✅ |
| Warehouses | 1 | 3 | Unlimited |
| Query fingerprinting | ✅ | ✅ | ✅ |
| Slack / PagerDuty alerts | ❌ | ✅ | ✅ |
| Cost trend dashboard | ❌ | ✅ | ✅ |
| Team chargeback reports | ❌ | ❌ | ✅ (PDF/CSV) |
| SSO / SAML | ❌ | ❌ | ✅ |
| SOC2 audit trail | ❌ | ❌ | ✅ |
| Self-hosted deployment | ❌ | ❌ | ✅ |
| Support | Community | Email (24h) | Dedicated Slack |

## 🔧 Configuration

Create `queryburn.yaml`:

```yaml
warehouse: snowflake
max_cost_usd: 5.0
block_on:
  - error
```

## 🏗️ GitHub Actions Integration

```yaml
- run: pip install -r requirements.txt
- run: python cli.py scan models/my_model.sql -c queryburn.yaml
```

Exit code 1 blocks the PR when cost policy is violated.

## 🔒 Security

- All inputs validated with strict size limits (1MB SQL, 100MB manifest)
- No dynamic SQL execution — static analysis only
- Query fingerprints use SHA-256 (literals stripped)
- Config parsed with safe YAML loader

## License

Business Source License 1.1 — free for teams under 5 engineers.
Contact sales@queryburn.dev for commercial licensing.
