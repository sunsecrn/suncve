# SunCVE Local API & MCP

A self-contained, **read-only** HTTP API and [MCP](https://modelcontextprotocol.io)
server over the SunCVE SQLite snapshot. It lets you (or an AI agent) query the
CVE dataset **locally** as a machine-friendly interface, without the web UI.

This package is completely additive — it does not touch the SunCVE site or its
build. It just reads the same `source.sqlite` that the web app ships.

## Requirements

- Node.js >= 20 (22 recommended)
- `tar` on PATH (for `db:download`)
- Optionally the [`gh` CLI](https://cli.github.com) (used for the download if authenticated)

## Setup

```bash
cd local-api
npm install

# Download the latest SQLite snapshot from the db-snapshots release
# (writes ./data/source.sqlite). Or point SUNCVE_DB at an existing file.
npm run db:download
```

You can skip `db:download` and instead set `SUNCVE_DB=/path/to/source.sqlite`
(e.g. the one under `../public/db/` after `../scripts/setup-db.sh`).

## Run the HTTP API

```bash
npm run start:api          # http://localhost:8787  (override with PORT=…)
```

Examples:

```bash
curl 'http://localhost:8787/api/health'
curl 'http://localhost:8787/api/stats/global'
curl 'http://localhost:8787/api/cves?q=log4j&severity=critical&exploit=true'
curl 'http://localhost:8787/api/cves?nuclei=true&page_size=10'
curl 'http://localhost:8787/api/cves/CVE-2021-44228'
curl 'http://localhost:8787/api/repositories?ecosystem=npm&sort=downloads'
curl 'http://localhost:8787/api/repositories/projectdiscovery/nuclei'
curl 'http://localhost:8787/api/stats/severity-distribution?period=30d'
```

### Endpoints

| Method & path | Description |
|---|---|
| `GET /api/health` | DB path, total CVEs, whether the nuclei column is present |
| `GET /api/cves` | Filtered, paginated CVE search |
| `GET /api/cves/:cveId` | Full CVE detail (scores, CWEs, affected, repos, references, exploits, commits, **nuclei**) |
| `GET /api/cves/stats` | Global stats, or filtered stats when query params are given |
| `GET /api/cves/filter-options` | Top 100 CWEs + top 50 languages |
| `GET /api/repositories` | Filtered, paginated repository search |
| `GET /api/repositories/:owner/:name` | Repository detail + linked-CVE count |
| `GET /api/repositories/:owner/:name/cves` | Paginated CVEs for a repository |
| `GET /api/repositories/stats` | Repository stats (global or filtered) |
| `GET /api/repositories/filter-options` | Top 50 languages |
| `GET /api/stats/recent` | Last-30-day activity counters |
| `GET /api/stats/severity-distribution?period=7d\|30d\|120d` | Severity buckets |
| `GET /api/stats/cves-by-period?period=30d\|1y\|5y` | Time series (with exploit counts) |
| `GET /api/stats/cwe-trend?period=…&top_n=5` | Top-N CWE trend |
| `GET /api/stats/top-cwes?period=…&limit=5` | Most common CWEs |
| `GET /api/stats/critical-cves` | Top 5 critical CVEs with a public exploit |
| `GET /api/stats/global` | Global counts |
| `GET /api/cwe-categories` | CWE category definitions |

CVE query params mirror the web UI's URL keys: `q, cvssMin, cvssMax, severity,
epss, cwes, cwe_cat, exploit, repo, commit, nuclei, ecosystem, lang, starsMin,
starsMax, sizeMin, sizeMax, pop_downloads, pop_downloads_max, period, date,
repo_filter, sort, order, page, page_size`. `severity`, `epss`, `cwes`, `lang`
are comma-separated (`epss` buckets: `very-low, low, moderate, high, critical`). `exploit/repo/commit/nuclei` are tri-state (`true`/`false`/absent).

## Run the MCP server

```bash
npm run start:mcp          # stdio transport
```

Add to an MCP client (e.g. Claude Desktop `claude_desktop_config.json`):

```json
{
  "mcpServers": {
    "suncve": {
      "command": "npx",
      "args": ["tsx", "/absolute/path/to/suncve/local-api/src/mcp.ts"],
      "env": { "SUNCVE_DB": "/absolute/path/to/source.sqlite" }
    }
  }
}
```

Tools: `search_cves`, `get_cve`, `search_repositories`, `get_repository`,
`get_repository_cves`, `cve_stats`, `repository_stats`, `dashboard_recent`,
`severity_distribution`, `cves_by_period`, `cwe_trend`, `top_cwes`,
`critical_cves`, `list_cwe_categories`, `list_filter_options`.

## Testing

```bash
# Smoke test (connect + a few tools):
SUNCVE_DB=/path/to/source.sqlite node scripts/mcp-smoke.mjs
# Exercise all 15 tools and report pass/fail:
SUNCVE_DB=/path/to/source.sqlite node scripts/mcp-testall.mjs
```

Interactive testing: point the [MCP Inspector](https://github.com/modelcontextprotocol/inspector)
at the server — `npx @modelcontextprotocol/inspector npx tsx src/mcp.ts`.

## Notes

- Everything is read-only; the SQLite file is opened read-only, and all MCP tools
  are annotated with `readOnlyHint: true` / `openWorldHint: false`.
- The `nuclei` filter and the `nuclei` array in CVE detail require a snapshot
  built with the Nuclei enrichment step. On older snapshots without the
  `exists_nuclei`/`list_nuclei` columns they degrade gracefully (empty / no-op),
  and `/api/health` reports `has_nuclei_column: false`.
- Query logic is a faithful port of the web app's SQLite hooks
  (`src/lib/sqlite/*`), so results match the UI for the same filters.
