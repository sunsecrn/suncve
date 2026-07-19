'use client';

import { useEffect, useState, useCallback, useRef } from 'react';
import { useTranslations } from 'next-intl';
import { SQLiteProvider, useSQLite } from '@/lib/sqlite';
import { DB_MANIFEST_URL, DB_FALLBACK_URL } from '@/lib/db-config';
import { useCVESearch } from '@/lib/sqlite/use-cve-search';
import { useDebounce } from '@/hooks/use-debounce';
import { useSearchParams } from '@/features/search/hooks';
import { SearchBar } from '@/features/search/components/search-bar';
import { FiltersPanel } from '@/features/search/components/filters-panel';
import { ResultsTable } from '@/features/search/components/results-table';
import { CVEDetailDrawer } from '@/features/search/components/cve-detail-drawer';
import { DatabaseLoader } from '@/features/search/components/database-loader';
import { StatsCards } from '@/features/search/components/stats-cards';
import {
  type CVESearchResult,
  type SearchResultsPage
} from '@/features/search/types';

// Debounce delay for search (ms) - 1 second for better UX
const SEARCH_DEBOUNCE_MS = 1000;

function SearchPageContentInner() {
  const t = useTranslations('search');

  // Set page title
  useEffect(() => {
    document.title = 'CVE Search | SunCVE';
  }, []);

  const {
    isReady,
    isLoading,
    error,
    progress,
    loadDatabase,
    loadDatabaseWithManifest
  } = useSQLite();
  const {
    search,
    getFilterOptions,
    getCVEDetails,
    getFilteredStats,
    isSearching
  } = useCVESearch();

  // URL-synced state for filters, sort, and pagination
  const { filters, sort, page, setFilters, setSort, setPage } =
    useSearchParams();

  const [results, setResults] = useState<SearchResultsPage | null>(null);
  const [selectedCVE, setSelectedCVE] = useState<string | null>(null);
  const [cveDetails, setCveDetails] =
    useState<ReturnType<typeof getCVEDetails>>(null);
  const [filterOptions, setFilterOptions] = useState<
    ReturnType<typeof getFilterOptions>
  >({ cwes: [], languages: [] });
  const [stats, setStats] = useState<{
    totalCVEs: number;
    totalRepos: number;
    withExploit: number;
    withCommit: number;
    inKev: number;
  }>({
    totalCVEs: 0,
    totalRepos: 0,
    withExploit: 0,
    withCommit: 0,
    inKev: 0
  });

  // Debounce filters to avoid excessive queries while typing
  const debouncedFilters = useDebounce(filters, SEARCH_DEBOUNCE_MS);

  // Track if this is the initial load
  const isInitialLoad = useRef(true);

  // Load database on mount - try manifest first, fallback to direct URL
  useEffect(() => {
    if (!isReady && !isLoading && !error) {
      // Try to load with manifest (supports OPFS caching and compression)
      loadDatabaseWithManifest(DB_MANIFEST_URL).catch(() => {
        // Fallback to direct URL if manifest doesn't exist
        console.warn('Manifest not found, loading directly from URL');
        loadDatabase(DB_FALLBACK_URL);
      });
    }
  }, [isReady, isLoading, error, loadDatabase, loadDatabaseWithManifest]);

  // Load filter options and stats when DB is ready
  useEffect(() => {
    if (isReady) {
      // Use requestIdleCallback for non-critical data loading
      const loadNonCritical = () => {
        setFilterOptions(getFilterOptions());
      };

      if ('requestIdleCallback' in window) {
        requestIdleCallback(loadNonCritical);
      } else {
        setTimeout(loadNonCritical, 100);
      }
    }
  }, [isReady, getFilterOptions]);

  // Perform search and update stats when debounced filters/sort/page change
  const performSearch = useCallback(async () => {
    if (!isReady) return;

    const searchResults = await search(debouncedFilters, sort, page);
    setResults(searchResults);

    // Update stats based on current filters
    const filteredStats = getFilteredStats(debouncedFilters);
    setStats(filteredStats);

    isInitialLoad.current = false;
  }, [isReady, search, debouncedFilters, sort, page, getFilteredStats]);

  useEffect(() => {
    performSearch();
  }, [performSearch]);

  // Load CVE details when selected
  useEffect(() => {
    if (selectedCVE && isReady) {
      const details = getCVEDetails(selectedCVE);
      setCveDetails(details);
    } else {
      setCveDetails(null);
    }
  }, [selectedCVE, isReady, getCVEDetails]);

  const handleRowClick = useCallback((cve: CVESearchResult) => {
    setSelectedCVE(cve.cve_id);
  }, []);

  const handleCloseDrawer = useCallback(() => {
    setSelectedCVE(null);
  }, []);

  // Check if pending (filters changed but not yet applied)
  const isPending = filters !== debouncedFilters;

  // Show loader while database is loading
  if (!isReady) {
    return (
      <DatabaseLoader
        isLoading={isLoading}
        progress={progress}
        error={error}
        onRetry={() => loadDatabase(DB_FALLBACK_URL)}
      />
    );
  }

  return (
    <div className='flex min-h-0 flex-col p-4 pb-8 md:px-6'>
      {/* Header */}
      <div className='mb-4'>
        <h1 className='text-2xl font-bold tracking-tight'>{t('title')}</h1>
        <p className='text-muted-foreground'>{t('description')}</p>
      </div>

      <div className='flex flex-col space-y-4'>
        {/* Stats Cards - Same style as dashboard */}
        <StatsCards stats={stats} />

        {/* Search and Filters Section */}
        <div className='space-y-4'>
          <SearchBar
            filters={filters}
            onFiltersChange={setFilters}
            isSearching={isSearching || isPending}
          />

          <FiltersPanel
            filters={filters}
            filterOptions={filterOptions}
            onFiltersChange={setFilters}
            isSearching={isSearching || isPending}
          />
        </div>

        {/* Results Table */}
        <ResultsTable
          results={results}
          sort={sort}
          isLoading={isSearching || isPending}
          onSortChange={setSort}
          onPageChange={setPage}
          onRowClick={handleRowClick}
        />

        {/* CVE Detail Drawer */}
        <CVEDetailDrawer
          cve={cveDetails}
          isOpen={!!selectedCVE}
          onClose={handleCloseDrawer}
        />
      </div>
    </div>
  );
}

export default function SearchPageContent() {
  return (
    <SQLiteProvider>
      <SearchPageContentInner />
    </SQLiteProvider>
  );
}
