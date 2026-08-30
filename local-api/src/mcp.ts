// Local MCP (stdio) server over the SunCVE SQLite snapshot. Exposes the same
// read-only operations as the HTTP API as MCP tools returning JSON text.
// Start: `npm run start:mcp`.

import { Server } from '@modelcontextprotocol/sdk/server/index.js';
import { StdioServerTransport } from '@modelcontextprotocol/sdk/server/stdio.js';
import {
  CallToolRequestSchema,
  ListToolsRequestSchema,
  type Tool
} from '@modelcontextprotocol/sdk/types.js';
import { openDb } from './db.js';
import { SunCveQueries } from './queries.js';
import { CWE_CATEGORIES } from './cwe-data.js';
import {
  parseCveFilters,
  parseCveSort,
  parseRepoFilters,
  parseRepoSort,
  parsePage,
  parsePageSize,
  type ParamRecord
} from './params.js';

const db = openDb();
const q = new SunCveQueries(db);

const CVE_FILTER_PROPS = {
  q: { type: 'string', description: 'Free-text search on cve_id/title/description' },
  cvssMin: { type: 'number', description: 'Minimum CVSS score (0-10)' },
  cvssMax: { type: 'number', description: 'Maximum CVSS score (0-10)' },
  severity: {
    type: 'string',
    description: 'Comma-separated: critical,high,medium,low,none'
  },
  epss: {
    type: 'string',
    description:
      'Comma-separated EPSS buckets: very-low (<1%), low (1-10%), moderate (10-36%), high (36-70%), critical (>=70%)'
  },
  cwes: { type: 'string', description: 'Comma-separated CWE ids, e.g. CWE-79,CWE-89' },
  cwe_cat: { type: 'string', description: 'CWE category id (rce, xss, sqli, ...)' },
  exploit: { type: 'boolean', description: 'Only CVEs with/without a public exploit' },
  repo: { type: 'boolean', description: 'Only CVEs with/without a linked repository' },
  commit: { type: 'boolean', description: 'Only CVEs with/without a fix commit' },
  nuclei: {
    type: 'boolean',
    description: 'Only CVEs with/without a related Nuclei template'
  },
  ecosystem: { type: 'string', description: 'github | wordpress | npm | packagist' },
  lang: { type: 'string', description: 'Comma-separated repo languages' },
  starsMin: { type: 'number' },
  starsMax: { type: 'number' },
  sizeMin: { type: 'number' },
  sizeMax: { type: 'number' },
  pop_downloads: { type: 'number', description: 'Min repo downloads' },
  pop_downloads_max: { type: 'number', description: 'Max repo downloads' },
  period: {
    type: 'string',
    description: 'today|7d|30d|120d|1y|5y|custom|all'
  },
  date: { type: 'string', description: 'Custom date: YYYY | YYYY-MM | YYYY-MM-DD' },
  repo_filter: { type: 'string', description: 'Exact repository fullpath owner/name' },
  sort: {
    type: 'string',
    description: 'cve_id|date_published|date_updated|score|epss|stars'
  },
  order: { type: 'string', description: 'asc | desc' },
  page: { type: 'number' },
  page_size: { type: 'number', description: 'Default 50, max 500' }
} as const;

const REPO_FILTER_PROPS = {
  q: { type: 'string', description: 'Free-text search on fullpath/name' },
  lang: { type: 'string', description: 'Comma-separated languages' },
  stars_min: { type: 'number' },
  stars_max: { type: 'number' },
  size_min: { type: 'number' },
  size_max: { type: 'number' },
  has_cves: { type: 'boolean' },
  has_commit_fix: { type: 'boolean' },
  ecosystem: { type: 'string', description: 'github | wordpress | npm | packagist' },
  active_installs_min: { type: 'number' },
  downloads_min: { type: 'number' },
  sort: {
    type: 'string',
    description: 'fullpath|name|stars|size|cve_count|commits_fix_count|downloads'
  },
  order: { type: 'string', description: 'asc | desc' },
  page: { type: 'number' },
  page_size: { type: 'number', description: 'Default 50, max 500' }
} as const;

const PERIOD_PROP = {
  period: { type: 'string', description: '30d | 1y | 5y' }
} as const;

const TOOLS: Tool[] = [
  {
    name: 'search_cves',
    description:
      'Search/filter CVEs with the full filter set (severity, CVSS, CWE, exploit, nuclei, ecosystem, dates, repo attributes). Paginated.',
    inputSchema: { type: 'object', properties: CVE_FILTER_PROPS }
  },
  {
    name: 'get_cve',
    description:
      'Get a full CVE record: scores, CWEs, affected products, linked repositories, references, exploits, fix commits, and related Nuclei templates.',
    inputSchema: {
      type: 'object',
      properties: { cve_id: { type: 'string', description: 'e.g. CVE-2021-44228' } },
      required: ['cve_id']
    }
  },
  {
    name: 'search_repositories',
    description: 'Search/filter GitHub/package repositories linked to CVEs. Paginated.',
    inputSchema: { type: 'object', properties: REPO_FILTER_PROPS }
  },
  {
    name: 'get_repository',
    description: 'Get a repository record plus its linked-CVE count.',
    inputSchema: {
      type: 'object',
      properties: { fullpath: { type: 'string', description: 'owner/name' } },
      required: ['fullpath']
    }
  },
  {
    name: 'get_repository_cves',
    description: 'Paginated list of CVEs linked to a repository (default page size 20).',
    inputSchema: {
      type: 'object',
      properties: {
        fullpath: { type: 'string', description: 'owner/name' },
        page: { type: 'number' },
        page_size: { type: 'number' }
      },
      required: ['fullpath']
    }
  },
  {
    name: 'cve_stats',
    description:
      'Global CVE stats, or filtered stats when any CVE filter is provided (totalCVEs, withExploit, withCommit, totalRepos).',
    inputSchema: { type: 'object', properties: CVE_FILTER_PROPS }
  },
  {
    name: 'repository_stats',
    description:
      'Global repository stats, or filtered stats when any repo filter is provided.',
    inputSchema: { type: 'object', properties: REPO_FILTER_PROPS }
  },
  {
    name: 'dashboard_recent',
    description: 'Last-30-day activity: new CVEs, new critical, new with exploit, new with fix.',
    inputSchema: { type: 'object', properties: {} }
  },
  {
    name: 'severity_distribution',
    description: 'Severity buckets for CVEs published in a window (7d|30d|120d).',
    inputSchema: {
      type: 'object',
      properties: { period: { type: 'string', description: '7d | 30d | 120d' } }
    }
  },
  {
    name: 'cves_by_period',
    description: 'CVE counts over time (30d daily / 1y monthly / 5y yearly) with exploit counts.',
    inputSchema: { type: 'object', properties: PERIOD_PROP }
  },
  {
    name: 'cwe_trend',
    description: 'Top-N CWEs over time, bucketed by the given period.',
    inputSchema: {
      type: 'object',
      properties: { ...PERIOD_PROP, top_n: { type: 'number' } }
    }
  },
  {
    name: 'top_cwes',
    description: 'Most common CWEs in a window (30d|1y|5y).',
    inputSchema: {
      type: 'object',
      properties: { ...PERIOD_PROP, limit: { type: 'number' } }
    }
  },
  {
    name: 'critical_cves',
    description: 'Top 5 critical (score >= 9) CVEs with a public exploit, newest first.',
    inputSchema: { type: 'object', properties: {} }
  },
  {
    name: 'list_cwe_categories',
    description: 'The CWE category definitions used by the cwe_cat filter.',
    inputSchema: { type: 'object', properties: {} }
  },
  {
    name: 'list_filter_options',
    description: 'Facet values for filters: top 100 CWEs and top 50 languages by count.',
    inputSchema: { type: 'object', properties: {} }
  }
];

// Todas as tools são consultas read-only sobre um SQLite local e fechado — nenhuma
// muta dados nem acessa o mundo externo. Declaramos os hints para que clientes
// (Claude Desktop/Code, Inspector) as tratem como seguras em vez dos defaults
// (destructive/open-world).
for (const tool of TOOLS) {
  tool.annotations = { readOnlyHint: true, openWorldHint: false };
}

function toPeriod3(v: unknown): '30d' | '1y' | '5y' {
  return v === '1y' || v === '5y' ? v : '30d';
}

function dispatch(name: string, args: ParamRecord): unknown {
  switch (name) {
    case 'search_cves':
      return q.searchCVEs(
        parseCveFilters(args),
        parseCveSort(args),
        parsePage(args),
        parsePageSize(args, 50)
      );
    case 'get_cve': {
      const detail = q.getCVEDetails(String(args.cve_id ?? ''));
      return detail ?? { error: 'CVE not found' };
    }
    case 'search_repositories':
      return q.searchRepositories(
        parseRepoFilters(args),
        parseRepoSort(args),
        parsePage(args),
        parsePageSize(args, 50)
      );
    case 'get_repository': {
      const detail = q.getRepositoryDetails(String(args.fullpath ?? ''));
      return detail ?? { error: 'Repository not found' };
    }
    case 'get_repository_cves':
      return q.getRepositoryCVEs(
        String(args.fullpath ?? ''),
        parsePage(args),
        parsePageSize(args, 20)
      );
    case 'cve_stats':
      return Object.keys(args).length > 0
        ? q.getFilteredStats(parseCveFilters(args))
        : q.getStats();
    case 'repository_stats':
      return Object.keys(args).length > 0
        ? q.getRepoFilteredStats(parseRepoFilters(args))
        : q.getRepoStats();
    case 'dashboard_recent':
      return q.getRecentStats();
    case 'severity_distribution': {
      const p = args.period;
      return q.getSeverityDistribution(p === '7d' || p === '120d' ? p : '30d');
    }
    case 'cves_by_period':
      return q.getCVEsByPeriod(toPeriod3(args.period));
    case 'cwe_trend':
      return q.getCWETrend(toPeriod3(args.period), Number(args.top_n ?? 5) || 5);
    case 'top_cwes':
      return q.getTopCWEs(Number(args.limit ?? 5) || 5, toPeriod3(args.period));
    case 'critical_cves':
      return q.getCriticalCVEsWithPOC();
    case 'list_cwe_categories':
      return CWE_CATEGORIES;
    case 'list_filter_options':
      return q.getFilterOptions();
    default:
      throw new Error(`Unknown tool: ${name}`);
  }
}

const server = new Server(
  { name: 'suncve-local-mcp', version: '1.0.0' },
  { capabilities: { tools: {} } }
);

server.setRequestHandler(ListToolsRequestSchema, async () => ({ tools: TOOLS }));

server.setRequestHandler(CallToolRequestSchema, async (req) => {
  const { name, arguments: args } = req.params;
  try {
    const result = dispatch(name, (args ?? {}) as ParamRecord);
    return { content: [{ type: 'text', text: JSON.stringify(result, null, 2) }] };
  } catch (err) {
    return {
      isError: true,
      content: [
        {
          type: 'text',
          text: `Error: ${err instanceof Error ? err.message : String(err)}`
        }
      ]
    };
  }
});

const transport = new StdioServerTransport();
await server.connect(transport);
console.error('SunCVE local MCP server ready (stdio).');
