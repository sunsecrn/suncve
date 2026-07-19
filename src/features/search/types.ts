// CVE Types based on SQLite schema

export interface CVE {
  cve_id: string;
  state: string;
  date_published: string | null;
  date_updated: string | null;
  date_reserved: string | null;
  title: string | null;
  description: string | null;
  exists_exploit: boolean;
  exists_commit: boolean;
  exists_nuclei: boolean;
  in_kev: boolean;
  kev_date_added: string | null;
  kev_due_date: string | null;
  kev_ransomware: boolean;
  missing_nuclei_template: boolean;
  list_exploit: string | null; // JSON string
  list_commit: string | null; // JSON string
  list_references: string | null; // JSON string
  list_nuclei: string | null; // JSON string (array of NucleiTemplate)
}

export interface CVEWithDetails extends CVE {
  scores: CVEScore[];
  cwes: string[];
  affected: CVEAffected[];
  repositories: RepositoryRelation[];
  nuclei: NucleiTemplate[];
}

// Nuclei template metadata (parsed from cves.list_nuclei JSON)
export interface NucleiTemplate {
  template_id: string; // nuclei template id (info/id)
  path: string; // path within projectdiscovery/nuclei-templates
  severity?: string; // info.severity
  tags?: string[]; // info.tags
  url?: string; // raw.githubusercontent.com URL of the template
  source?: string; // enrichment source: undefined = projectdiscovery, 'wordfence' = topscoder/nuclei-wordfence-cve
}

export interface CVEScore {
  id: number;
  cve_id: string;
  version: string; // '2.0', '3.0', '3.1', '4.0'
  score: number;
}

export interface CVECWE {
  cve_id: string;
  cwe_id: string;
}

export interface CVEAffected {
  id: number;
  cve_id: string;
  vendor: string;
  product: string;
}

export interface Repository {
  fullpath: string;
  is_exists: boolean | null;
  name: string | null;
  size: number | null;
  stars: number | null;
  languageMain: string | null;
  languages: string | null; // JSON string
  tags: string | null; // JSON string (array)
  categories: string | null;
  commits_fix: string | null; // JSON
  commits_fix_count: number | null;
  researchs: string | null; // JSON
  researchs_count: number | null;
  scm_id_repository: string | null;
  created_repository: string | null;
  updated_repository: string | null;
  ecosystem: string | null; // 'github' | 'wordpress' | 'npm' | 'packagist'
  active_installs: number | null; // WordPress plugins only
  downloads: number | null; // unified download count (npm/Packagist/WordPress)
  package_url: string | null; // registry URL (npm/Packagist)
}

export interface RepositoryRelation {
  cve_id: string;
  repository_fullpath: string;
  relation_type: string | null;
  repository?: Repository;
}

// Search/Filter Types

export type Severity = 'critical' | 'high' | 'medium' | 'low' | 'none';

export function getSeverityFromScore(score: number): Severity {
  if (score >= 9.0) return 'critical';
  if (score >= 7.0) return 'high';
  if (score >= 4.0) return 'medium';
  if (score > 0) return 'low';
  return 'none';
}

export function getSeverityColor(severity: Severity): string {
  switch (severity) {
    case 'critical':
      return 'bg-red-500 text-white';
    case 'high':
      return 'bg-orange-500 text-white';
    case 'medium':
      return 'bg-yellow-500 text-black';
    case 'low':
      return 'bg-blue-500 text-white';
    default:
      return 'bg-gray-500 text-white';
  }
}

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
  hasKev: boolean | null;
  hasMissingTemplate: boolean | null;
  languages: string[];
  starsMin: number | null;
  starsMax: number | null;
  repoSizeMin: number | null;
  repoSizeMax: number | null;
  datePeriod: DatePeriod;
  customDate: string | null; // For specific date (YYYY-MM-DD)
  repository: string | null; // Filter by specific repository fullpath
  cweCategory: string | null; // Filter by CWE category (e.g., 'rce', 'injection')
  ecosystem: string | null; // Filter by linked repository ecosystem ('github' | 'wordpress' | 'npm' | 'packagist')
  // Downloads range: CVE in a repo whose unified downloads fall within [min, max]
  popDownloadsMin: number | null; // min downloads (npm/Packagist/WordPress)
  popDownloadsMax: number | null; // max downloads (null = no upper bound)
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
  hasKev: null,
  hasMissingTemplate: null,
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

// Search Result Types

export interface CVESearchResult {
  cve_id: string;
  title: string | null;
  description: string | null;
  date_published: string | null;
  date_updated: string | null;
  exists_exploit: boolean;
  exists_commit: boolean;
  exists_nuclei: boolean;
  in_kev: boolean;
  kev_date_added: string | null;
  kev_ransomware: boolean;
  missing_nuclei_template: boolean;
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

// Reference Types (parsed from JSON)

export interface CVEReference {
  url: string;
  tags?: string[];
}

export interface ParsedLanguages {
  [language: string]: number; // percentage
}

// Repository Search Types

export interface RepositorySearchFilters {
  query: string;
  languages: string[];
  starsMin: number | null;
  starsMax: number | null;
  sizeMin: number | null;
  sizeMax: number | null;
  hasCVEs: boolean | null;
  hasCommitFix: boolean | null;
  ecosystem: string | null; // 'github' | 'wordpress' | 'npm' | 'packagist' | null (all)
  activeInstallsMin: number | null; // WordPress plugins
  downloadsMin: number | null; // unified downloads (any ecosystem)
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

export interface RepositoryWithCVEs extends Repository {
  cves: CVESearchResult[];
  cve_count: number;
}
