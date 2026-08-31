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
  epss: number | null; // EPSS probability [0-1]
  epss_percentile: number | null; // EPSS percentile [0-1]
  epss_date: string | null; // score_date do arquivo EPSS (YYYY-MM-DD)
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

// EPSS (Exploit Prediction Scoring System) — probabilidade [0-1] de a CVE ser
// explorada nos próximos 30 dias. Os limiares abaixo são de probabilidade bruta,
// não de percentil: assim "barra cheia" significa risco real e não apenas
// "acima da mediana". A distribuição é fortemente enviesada para baixo — os
// percentuais são do catálogo completo (~366 mil CVEs) em 2026-08-30.
export type EpssLevel =
  | 'none' // sem score publicado
  | 'very-low' // < 1%      — 60,4% das CVEs
  | 'low' // 1% – 10%  — 34,9%
  | 'moderate' // 10% – 36% —  3,1%
  | 'high' // 36% – 70% —  1,0%
  | 'critical'; // >= 70%    —  0,7%

export function getEpssLevel(epss: number | null | undefined): EpssLevel {
  if (epss === null || epss === undefined) return 'none';
  if (epss >= 0.7) return 'critical';
  if (epss >= 0.36) return 'high';
  if (epss >= 0.1) return 'moderate';
  if (epss >= 0.01) return 'low';
  return 'very-low';
}

// 'none' é ausência de score publicado, não um bucket: fica de fora do filtro.
export type EpssFilterLevel = Exclude<EpssLevel, 'none'>;

// Faixas por nível, usadas para montar o WHERE do filtro em SQL.
export const EPSS_LEVEL_RANGE: Record<
  EpssFilterLevel,
  { min: number; max: number | null }
> = {
  'very-low': { min: 0, max: 0.01 },
  low: { min: 0.01, max: 0.1 },
  moderate: { min: 0.1, max: 0.36 },
  high: { min: 0.36, max: 0.7 },
  critical: { min: 0.7, max: null }
};

// Classes Tailwind literais e completas: com output:'export' + Tailwind v4 o JIT
// não detecta classes montadas por template string.
export const EPSS_LEVEL_META: Record<
  EpssLevel,
  { bars: number; barClass: string; textClass: string; badgeClass: string }
> = {
  none: {
    bars: 0,
    barClass: 'bg-muted-foreground/30',
    textClass: 'text-muted-foreground',
    badgeClass: ''
  },
  'very-low': {
    bars: 1,
    barClass: 'bg-slate-400',
    textClass: 'text-slate-600 dark:text-slate-400',
    badgeClass: 'bg-slate-400 hover:bg-slate-500'
  },
  low: {
    bars: 2,
    barClass: 'bg-sky-500',
    textClass: 'text-sky-700 dark:text-sky-400',
    badgeClass: 'bg-sky-500 hover:bg-sky-600'
  },
  moderate: {
    bars: 3,
    barClass: 'bg-yellow-500',
    textClass: 'text-yellow-700 dark:text-yellow-500',
    badgeClass: 'bg-yellow-500 hover:bg-yellow-600 text-black'
  },
  high: {
    bars: 4,
    barClass: 'bg-orange-500',
    textClass: 'text-orange-700 dark:text-orange-400',
    badgeClass: 'bg-orange-500 hover:bg-orange-600'
  },
  critical: {
    bars: 5,
    barClass: 'bg-rose-600',
    textClass: 'text-rose-700 dark:text-rose-400',
    badgeClass: 'bg-rose-600 hover:bg-rose-700'
  }
};

// Contagem de CVEs por faixa, usada pelos cards de distribuição.
export type EpssCounts = Record<EpssFilterLevel, number>;

export const EPSS_LEVELS: EpssFilterLevel[] = [
  'critical',
  'high',
  'moderate',
  'low',
  'very-low'
];

// 0.42371 -> "42%". Porcentagem inteira em todo lugar; só o zero enganoso tem
// piso: 0.002 arredondaria para "0%", que leria como risco nenhum.
export function formatEpss(
  epss: number | null | undefined,
  locale = 'en'
): string {
  if (epss === null || epss === undefined) return '—';
  if (epss > 0 && epss < 0.005) return '< 1%';
  return new Intl.NumberFormat(locale, {
    style: 'percent',
    maximumFractionDigits: 0
  }).format(epss);
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
  epssLevel: EpssFilterLevel[];
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
  epssLevel: [],
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
  | 'epss'
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
  epss: number | null;
  epss_percentile: number | null;
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
