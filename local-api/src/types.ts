// Filter/sort/result types ported from src/features/search/types.ts, plus the
// new tri-state `hasNuclei` filter (Nuclei-template enrichment).

import type { Severity } from './severity.js';

export type DatePeriod =
  | 'today'
  | '7d'
  | '30d'
  | '120d'
  | '1y'
  | '5y'
  | 'custom'
  | 'all';

export interface SearchFilters {
  query: string;
  cvssMin: number;
  cvssMax: number;
  severity: Severity[];
  cwes: string[];
  hasExploit: boolean | null;
  hasRepository: boolean | null;
  hasCommitFix: boolean | null;
  hasNuclei: boolean | null;
  languages: string[];
  starsMin: number | null;
  starsMax: number | null;
  repoSizeMin: number | null;
  repoSizeMax: number | null;
  datePeriod: DatePeriod;
  customDate: string | null;
  repository: string | null;
  cweCategory: string | null;
  ecosystem: string | null;
  popDownloadsMin: number | null;
  popDownloadsMax: number | null;
}

export const defaultFilters: SearchFilters = {
  query: '',
  cvssMin: 0,
  cvssMax: 10,
  severity: [],
  cwes: [],
  hasExploit: null,
  hasRepository: null,
  hasCommitFix: null,
  hasNuclei: null,
  languages: [],
  starsMin: null,
  starsMax: null,
  repoSizeMin: null,
  repoSizeMax: null,
  datePeriod: 'all',
  customDate: null,
  repository: null,
  cweCategory: null,
  ecosystem: null,
  popDownloadsMin: null,
  popDownloadsMax: null
};

export type SortField =
  | 'cve_id'
  | 'date_published'
  | 'date_updated'
  | 'score'
  | 'stars'
  | 'created_repository'
  | 'updated_repository';

export type SortOrder = 'asc' | 'desc';

export interface SortConfig {
  field: SortField;
  order: SortOrder;
}

export interface CVESearchResult {
  cve_id: string;
  title: string | null;
  description: string | null;
  date_published: string | null;
  date_updated: string | null;
  exists_exploit: boolean;
  exists_commit: boolean;
  exists_nuclei: boolean;
  max_score: number | null;
  severity: Severity;
  cwe_list: string | null;
  vendor_list: string | null;
  product_list: string | null;
  repo_count: number;
  repo_fullpath: string | null;
  repo_stars: number | null;
  repo_language: string | null;
}

export interface SearchResultsPage {
  results: CVESearchResult[];
  total: number;
  page: number;
  pageSize: number;
  totalPages: number;
}

export interface RepositorySearchFilters {
  query: string;
  languages: string[];
  starsMin: number | null;
  starsMax: number | null;
  sizeMin: number | null;
  sizeMax: number | null;
  hasCVEs: boolean | null;
  hasCommitFix: boolean | null;
  ecosystem: string | null;
  activeInstallsMin: number | null;
  downloadsMin: number | null;
}

export const defaultRepositoryFilters: RepositorySearchFilters = {
  query: '',
  languages: [],
  starsMin: null,
  starsMax: null,
  sizeMin: null,
  sizeMax: null,
  hasCVEs: null,
  hasCommitFix: null,
  ecosystem: null,
  activeInstallsMin: null,
  downloadsMin: null
};

export type RepositorySortField =
  | 'fullpath'
  | 'name'
  | 'stars'
  | 'size'
  | 'cve_count'
  | 'commits_fix_count'
  | 'created_repository'
  | 'updated_repository'
  | 'active_installs'
  | 'downloads';

export interface RepositorySortConfig {
  field: RepositorySortField;
  order: SortOrder;
}

export interface RepositorySearchResult {
  fullpath: string;
  name: string | null;
  stars: number | null;
  size: number | null;
  languageMain: string | null;
  cve_count: number;
  commits_fix_count: number | null;
  created_repository: string | null;
  updated_repository: string | null;
  ecosystem: string | null;
  active_installs: number | null;
  downloads: number | null;
  package_url: string | null;
}

export interface RepositorySearchResultsPage {
  results: RepositorySearchResult[];
  total: number;
  page: number;
  pageSize: number;
  totalPages: number;
}

/** A single Nuclei template linked to a CVE (parsed from cves.list_nuclei). */
export interface NucleiTemplate {
  template_id?: string;
  path?: string;
  severity?: string;
  tags?: string[];
  url?: string;
  source?: string; // undefined = projectdiscovery, 'wordfence' = topscoder/nuclei-wordfence-cve
  [key: string]: unknown;
}
