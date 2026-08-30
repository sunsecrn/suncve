'use client';

import {
  useQueryStates,
  parseAsString,
  parseAsFloat,
  parseAsArrayOf,
  parseAsStringLiteral,
  parseAsBoolean,
  parseAsInteger
} from 'nuqs';
import { useCallback, useMemo } from 'react';
import type {
  SearchFilters,
  SortConfig,
  SortField,
  SortOrder,
  Severity,
  EpssFilterLevel,
  DatePeriod
} from '../types';
import { defaultFilters } from '../types';

// Define severity options for parser
const severityOptions = ['critical', 'high', 'medium', 'low', 'none'] as const;
const epssLevelOptions = [
  'very-low',
  'low',
  'moderate',
  'high',
  'critical'
] as const;
const datePeriodOptions = [
  'today',
  '7d',
  '30d',
  '120d',
  '1y',
  '5y',
  'custom',
  'all'
] as const;
const sortFieldOptions = [
  'cve_id',
  'date_published',
  'date_updated',
  'score',
  'epss',
  'stars',
  'created_repository',
  'updated_repository'
] as const;
const sortOrderOptions = ['asc', 'desc'] as const;

// Custom parser for nullable boolean
const parseAsNullableBoolean = {
  parse: (value: string) => {
    if (value === 'true') return true;
    if (value === 'false') return false;
    return null;
  },
  serialize: (value: boolean | null) => {
    if (value === null) return '';
    return value ? 'true' : 'false';
  }
};

// Custom parser for nullable number
const parseAsNullableInt = {
  parse: (value: string) => {
    const num = parseInt(value, 10);
    return isNaN(num) ? null : num;
  },
  serialize: (value: number | null) => {
    return value === null ? '' : value.toString();
  }
};

// URL search params configuration
const searchParamsConfig = {
  // Search query
  q: parseAsString.withDefault(''),

  // CVSS score range
  cvssMin: parseAsFloat.withDefault(0),
  cvssMax: parseAsFloat.withDefault(10),

  // Severity filter (comma-separated)
  severity: parseAsArrayOf(parseAsStringLiteral(severityOptions)).withDefault(
    []
  ),

  // EPSS level filter (comma-separated)
  epss: parseAsArrayOf(parseAsStringLiteral(epssLevelOptions)).withDefault([]),

  // CWE filter (comma-separated)
  cwes: parseAsArrayOf(parseAsString).withDefault([]),

  // Boolean filters
  exploit: parseAsNullableBoolean,
  repo: parseAsNullableBoolean,
  commit: parseAsNullableBoolean,
  nuclei: parseAsNullableBoolean,
  kev: parseAsNullableBoolean,
  missing: parseAsNullableBoolean,

  // Language filter (comma-separated)
  lang: parseAsArrayOf(parseAsString).withDefault([]),

  // Stars range
  starsMin: parseAsNullableInt,
  starsMax: parseAsNullableInt,

  // Repo size range
  sizeMin: parseAsNullableInt,
  sizeMax: parseAsNullableInt,

  // Date period filter
  period: parseAsStringLiteral(datePeriodOptions).withDefault('all'),
  date: parseAsString.withDefault(''),

  // Repository filter
  repo_filter: parseAsString.withDefault(''),

  // CWE Category filter
  cwe_cat: parseAsString.withDefault(''),

  // Ecosystem filter (github | wordpress)
  ecosystem: parseAsString.withDefault(''),

  // Downloads range (repo unified downloads)
  pop_downloads: parseAsNullableInt,
  pop_downloads_max: parseAsNullableInt,

  // Sorting
  sort: parseAsStringLiteral(sortFieldOptions).withDefault('date_published'),
  order: parseAsStringLiteral(sortOrderOptions).withDefault('desc'),

  // Pagination
  page: parseAsInteger.withDefault(1)
};

export function useSearchParams() {
  const [params, setParams] = useQueryStates(searchParamsConfig, {
    history: 'push',
    shallow: true
  });

  // Convert URL params to SearchFilters
  const filters: SearchFilters = useMemo(
    () => ({
      query: params.q,
      cvssMin: params.cvssMin,
      cvssMax: params.cvssMax,
      severity: params.severity as Severity[],
      epssLevel: params.epss as EpssFilterLevel[],
      cwes: params.cwes.filter(Boolean),
      hasExploit: params.exploit,
      hasRepository: params.repo,
      hasCommitFix: params.commit,
      hasNuclei: params.nuclei,
      hasKev: params.kev,
      hasMissingTemplate: params.missing,
      languages: params.lang.filter(Boolean),
      starsMin: params.starsMin,
      starsMax: params.starsMax,
      repoSizeMin: params.sizeMin,
      repoSizeMax: params.sizeMax,
      datePeriod: params.period as DatePeriod,
      customDate: params.date || null,
      repository: params.repo_filter || null,
      cweCategory: params.cwe_cat || null,
      ecosystem: params.ecosystem || null,
      popDownloadsMin: params.pop_downloads,
      popDownloadsMax: params.pop_downloads_max
    }),
    [params]
  );

  // Convert URL params to SortConfig
  const sort: SortConfig = useMemo(
    () => ({
      field: params.sort as SortField,
      order: params.order as SortOrder
    }),
    [params.sort, params.order]
  );

  // Current page
  const page = params.page;

  // Update filters
  const setFilters = useCallback(
    (newFilters: SearchFilters) => {
      setParams({
        q: newFilters.query || null,
        cvssMin: newFilters.cvssMin === 0 ? null : newFilters.cvssMin,
        cvssMax: newFilters.cvssMax === 10 ? null : newFilters.cvssMax,
        severity: newFilters.severity.length > 0 ? newFilters.severity : null,
        epss: newFilters.epssLevel.length > 0 ? newFilters.epssLevel : null,
        cwes: newFilters.cwes.length > 0 ? newFilters.cwes : null,
        exploit: newFilters.hasExploit,
        repo: newFilters.hasRepository,
        commit: newFilters.hasCommitFix,
        nuclei: newFilters.hasNuclei,
        kev: newFilters.hasKev,
        missing: newFilters.hasMissingTemplate,
        lang: newFilters.languages.length > 0 ? newFilters.languages : null,
        starsMin: newFilters.starsMin,
        starsMax: newFilters.starsMax,
        sizeMin: newFilters.repoSizeMin,
        sizeMax: newFilters.repoSizeMax,
        period: newFilters.datePeriod === 'all' ? null : newFilters.datePeriod,
        date: newFilters.customDate || null,
        repo_filter: newFilters.repository || null,
        cwe_cat: newFilters.cweCategory || null,
        ecosystem: newFilters.ecosystem || null,
        pop_downloads: newFilters.popDownloadsMin,
        pop_downloads_max: newFilters.popDownloadsMax,
        // Reset page when filters change
        page: 1
      });
    },
    [setParams]
  );

  // Update sort
  const setSort = useCallback(
    (newSort: SortConfig) => {
      setParams({
        sort: newSort.field === 'date_published' ? null : newSort.field,
        order: newSort.order === 'desc' ? null : newSort.order,
        // Reset page when sort changes
        page: 1
      });
    },
    [setParams]
  );

  // Update page
  const setPage = useCallback(
    (newPage: number) => {
      setParams({ page: newPage === 1 ? null : newPage });
    },
    [setParams]
  );

  // Reset all filters
  const resetFilters = useCallback(() => {
    setParams({
      q: null,
      cvssMin: null,
      cvssMax: null,
      severity: null,
      epss: null,
      cwes: null,
      exploit: null,
      repo: null,
      commit: null,
      nuclei: null,
      kev: null,
      missing: null,
      lang: null,
      starsMin: null,
      starsMax: null,
      sizeMin: null,
      sizeMax: null,
      period: null,
      date: null,
      repo_filter: null,
      cwe_cat: null,
      ecosystem: null,
      pop_downloads: null,
      pop_downloads_max: null,
      sort: null,
      order: null,
      page: null
    });
  }, [setParams]);

  // Check if filters are at default values
  const hasActiveFilters = useMemo(() => {
    return (
      filters.query !== '' ||
      filters.cvssMin !== 0 ||
      filters.cvssMax !== 10 ||
      filters.severity.length > 0 ||
      filters.epssLevel.length > 0 ||
      filters.cwes.length > 0 ||
      filters.hasExploit !== null ||
      filters.hasRepository !== null ||
      filters.hasCommitFix !== null ||
      filters.hasNuclei !== null ||
      filters.hasKev !== null ||
      filters.hasMissingTemplate !== null ||
      filters.languages.length > 0 ||
      filters.starsMin !== null ||
      filters.starsMax !== null ||
      filters.repoSizeMin !== null ||
      filters.repoSizeMax !== null ||
      filters.datePeriod !== 'all' ||
      filters.repository !== null ||
      filters.ecosystem !== null ||
      filters.popDownloadsMin !== null ||
      filters.popDownloadsMax !== null
    );
  }, [filters]);

  return {
    filters,
    sort,
    page,
    setFilters,
    setSort,
    setPage,
    resetFilters,
    hasActiveFilters
  };
}
