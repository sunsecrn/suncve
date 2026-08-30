// Parse a flat record of request params (HTTP query string OR MCP tool
// arguments) into the strongly-typed filter/sort objects. URL keys match
// src/features/search/hooks/use-search-params.ts exactly, with `nuclei` added.

import {
  defaultFilters,
  defaultRepositoryFilters,
  type SearchFilters,
  type SortConfig,
  type SortField,
  type SortOrder,
  type DatePeriod,
  type RepositorySearchFilters,
  type RepositorySortConfig,
  type RepositorySortField
} from './types.js';
import type { Severity } from './severity.js';
import { EPSS_LEVELS, type EpssFilterLevel } from './epss.js';

export type ParamRecord = Record<string, unknown>;

function str(rec: ParamRecord, key: string): string | undefined {
  const v = rec[key];
  if (v === undefined || v === null) return undefined;
  const s = String(v).trim();
  return s === '' ? undefined : s;
}

function num(rec: ParamRecord, key: string): number | null {
  const s = str(rec, key);
  if (s === undefined) return null;
  const n = Number(s);
  return Number.isFinite(n) ? n : null;
}

function numOr(rec: ParamRecord, key: string, fallback: number): number {
  const n = num(rec, key);
  return n === null ? fallback : n;
}

/** Tri-state boolean: "true" -> true, "false" -> false, absent -> null. */
function triBool(rec: ParamRecord, key: string): boolean | null {
  const v = rec[key];
  if (v === undefined || v === null || v === '') return null;
  if (typeof v === 'boolean') return v;
  const s = String(v).toLowerCase();
  if (s === 'true' || s === '1') return true;
  if (s === 'false' || s === '0') return false;
  return null;
}

/** Comma-separated list OR native array -> string[]. */
function csv(rec: ParamRecord, key: string): string[] {
  const v = rec[key];
  if (v === undefined || v === null) return [];
  if (Array.isArray(v)) return v.map(String).filter(Boolean);
  return String(v)
    .split(',')
    .map((s) => s.trim())
    .filter(Boolean);
}

const SEVERITIES: Severity[] = ['critical', 'high', 'medium', 'low', 'none'];
const DATE_PERIODS: DatePeriod[] = [
  'today',
  '7d',
  '30d',
  '120d',
  '1y',
  '5y',
  'custom',
  'all'
];
const CVE_SORT_FIELDS: SortField[] = [
  'cve_id',
  'date_published',
  'date_updated',
  'score',
  'stars',
  'created_repository',
  'updated_repository'
];
const REPO_SORT_FIELDS: RepositorySortField[] = [
  'fullpath',
  'name',
  'stars',
  'size',
  'cve_count',
  'commits_fix_count',
  'created_repository',
  'updated_repository',
  'active_installs',
  'downloads'
];

function order(rec: ParamRecord): SortOrder {
  return str(rec, 'order') === 'asc' ? 'asc' : 'desc';
}

export function parseCveFilters(rec: ParamRecord): SearchFilters {
  const severity = csv(rec, 'severity').filter((s): s is Severity =>
    (SEVERITIES as string[]).includes(s)
  );
  const epssLevel = csv(rec, 'epss').filter((l): l is EpssFilterLevel =>
    (EPSS_LEVELS as string[]).includes(l)
  );
  const periodRaw = str(rec, 'period');
  const datePeriod: DatePeriod = (DATE_PERIODS as string[]).includes(
    periodRaw ?? ''
  )
    ? (periodRaw as DatePeriod)
    : 'all';

  return {
    ...defaultFilters,
    query: str(rec, 'q') ?? '',
    cvssMin: numOr(rec, 'cvssMin', 0),
    cvssMax: numOr(rec, 'cvssMax', 10),
    severity,
    epssLevel,
    cwes: csv(rec, 'cwes'),
    hasExploit: triBool(rec, 'exploit'),
    hasRepository: triBool(rec, 'repo'),
    hasCommitFix: triBool(rec, 'commit'),
    hasNuclei: triBool(rec, 'nuclei'),
    languages: csv(rec, 'lang'),
    starsMin: num(rec, 'starsMin'),
    starsMax: num(rec, 'starsMax'),
    repoSizeMin: num(rec, 'sizeMin'),
    repoSizeMax: num(rec, 'sizeMax'),
    datePeriod,
    customDate: str(rec, 'date') ?? null,
    repository: str(rec, 'repo_filter') ?? null,
    cweCategory: str(rec, 'cwe_cat') ?? null,
    ecosystem: str(rec, 'ecosystem') ?? null,
    popDownloadsMin: num(rec, 'pop_downloads'),
    popDownloadsMax: num(rec, 'pop_downloads_max')
  };
}

export function parseCveSort(rec: ParamRecord): SortConfig {
  const field = str(rec, 'sort');
  return {
    field: (CVE_SORT_FIELDS as string[]).includes(field ?? '')
      ? (field as SortField)
      : 'date_published',
    order: order(rec)
  };
}

export function parseRepoFilters(rec: ParamRecord): RepositorySearchFilters {
  return {
    ...defaultRepositoryFilters,
    query: str(rec, 'q') ?? '',
    languages: csv(rec, 'lang'),
    starsMin: num(rec, 'stars_min'),
    starsMax: num(rec, 'stars_max'),
    sizeMin: num(rec, 'size_min'),
    sizeMax: num(rec, 'size_max'),
    hasCVEs: triBool(rec, 'has_cves'),
    hasCommitFix: triBool(rec, 'has_commit_fix'),
    ecosystem: str(rec, 'ecosystem') ?? null,
    activeInstallsMin: num(rec, 'active_installs_min'),
    downloadsMin: num(rec, 'downloads_min')
  };
}

export function parseRepoSort(rec: ParamRecord): RepositorySortConfig {
  const field = str(rec, 'sort');
  return {
    field: (REPO_SORT_FIELDS as string[]).includes(field ?? '')
      ? (field as RepositorySortField)
      : 'stars',
    order: order(rec)
  };
}

export function parsePage(rec: ParamRecord): number {
  const p = num(rec, 'page');
  return p && p > 0 ? Math.floor(p) : 1;
}

export function parsePageSize(rec: ParamRecord, fallback: number): number {
  const s = num(rec, 'page_size');
  return s && s > 0 ? Math.min(Math.floor(s), 500) : fallback;
}
