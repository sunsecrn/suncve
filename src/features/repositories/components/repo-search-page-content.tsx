'use client';

import { useEffect, useState, useCallback, useRef } from 'react';
import { useTranslations } from 'next-intl';
import { SQLiteProvider, useSQLite } from '@/lib/sqlite';
import { DB_MANIFEST_URL, DB_FALLBACK_URL } from '@/lib/db-config';
import { useRepositorySearch } from '@/lib/sqlite/use-repository-search';
import { useDebounce } from '@/hooks/use-debounce';
import { SearchBar } from '@/features/search/components/search-bar';
import { RepoFiltersPanel } from './repo-filters-panel';
import { RepoResultsTable } from './repo-results-table';
import { RepoDetailDrawer } from './repo-detail-drawer';
import { DatabaseLoader } from '@/features/search/components/database-loader';
import { RepoStatsCards } from './repo-stats-cards';
import { useContentReady } from '@/hooks/use-content-ready';
import {
  type RepositorySearchResult,
  type RepositorySearchResultsPage,
  type RepositorySearchFilters,
  type RepositorySortConfig,
  defaultRepositoryFilters,
  defaultFilters
} from '@/features/search/types';

// Debounce delay for search (ms) - 1 second for better UX
const SEARCH_DEBOUNCE_MS = 1000;

function RepositorySearchPageContentInner() {
  const t = useTranslations('repositories');

  // Set page title
  useEffect(() => {
    document.title = 'Repository Search | SunCVE';
  }, []);

  const {
    isReady,
    isLoading,
    error,
    progress,
    loadDatabase,
    loadDatabaseWithManifest
  } = useSQLite();

  // Reveal the layout footer only once the database is ready.
  const setContentReady = useContentReady((s) => s.setReady);
  useEffect(() => {
    setContentReady(isReady);
    return () => setContentReady(false);
  }, [isReady, setContentReady]);

  const {
    search,
    getFilterOptions,
    getRepositoryDetails,
    getFilteredStats,
    isSearching
  } = useRepositorySearch();

  // State for filters, sort, and pagination
  const [filters, setFilters] = useState<RepositorySearchFilters>(
    defaultRepositoryFilters
  );
  const [sort, setSort] = useState<RepositorySortConfig>({
    field: 'stars',
    order: 'desc'
  });
  const [page, setPage] = useState(1);

  const [results, setResults] = useState<RepositorySearchResultsPage | null>(
    null
  );
  const [selectedRepo, setSelectedRepo] = useState<string | null>(null);
  const [repoDetails, setRepoDetails] =
    useState<ReturnType<typeof getRepositoryDetails>>(null);
  const [filterOptions, setFilterOptions] = useState<
    ReturnType<typeof getFilterOptions>
  >({ languages: [] });
  const [stats, setStats] = useState<{
    totalRepos: number;
    withCVEs: number;
    withCommitFix: number;
  }>({ totalRepos: 0, withCVEs: 0, withCommitFix: 0 });

  // Keep the sort field meaningful per ecosystem: package ecosystems
  // (WordPress/npm/Packagist) are ranked by downloads, while stars is the sensible
  // default for plain GitHub repositories.
  useEffect(() => {
    const isPackageEcosystem =
      filters.ecosystem === 'wordpress' ||
      filters.ecosystem === 'npm' ||
      filters.ecosystem === 'packagist';
    if (isPackageEcosystem) {
      setSort((prev) =>
        prev.field === 'stars' ? { field: 'downloads', order: 'desc' } : prev
      );
    } else {
      setSort((prev) =>
        prev.field === 'downloads' || prev.field === 'active_installs'
          ? { field: 'stars', order: 'desc' }
          : prev
      );
    }
  }, [filters.ecosystem]);

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

  // Load repository details when selected
  useEffect(() => {
    if (selectedRepo && isReady) {
      const details = getRepositoryDetails(selectedRepo);
      setRepoDetails(details);
    } else {
      setRepoDetails(null);
    }
  }, [selectedRepo, isReady, getRepositoryDetails]);

  const handleRowClick = useCallback((repo: RepositorySearchResult) => {
    setSelectedRepo(repo.fullpath);
  }, []);

  const handleCloseDrawer = useCallback(() => {
    setSelectedRepo(null);
  }, []);

  // Handle filter changes - adapt SearchFilters to RepositorySearchFilters
  const handleFiltersChange = useCallback(
    (newFilters: RepositorySearchFilters) => {
      setFilters(newFilters);
      setPage(1); // Reset to first page when filters change
    },
    []
  );

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
    <div className='flex flex-1 flex-col p-4 pb-8 md:px-6'>
      {/* Header */}
      <div className='mb-4'>
        <h1 className='text-2xl font-bold tracking-tight'>{t('title')}</h1>
        <p className='text-muted-foreground'>{t('description')}</p>
      </div>

      <div className='flex flex-col space-y-4'>
        {/* Stats Cards */}
        <RepoStatsCards stats={stats} />

        {/* Search and Filters Section */}
        <div className='space-y-4'>
          <SearchBar
            filters={{
              ...defaultFilters,
              query: filters.query,
              languages: filters.languages,
              starsMin: filters.starsMin,
              starsMax: filters.starsMax,
              repoSizeMin: filters.sizeMin,
              repoSizeMax: filters.sizeMax
            }}
            onFiltersChange={(searchFilters) =>
              handleFiltersChange({
                ...filters,
                query: searchFilters.query
              })
            }
            isSearching={isSearching || isPending}
            placeholder={t('searchPlaceholder')}
          />

          <RepoFiltersPanel
            filters={filters}
            filterOptions={filterOptions}
            onFiltersChange={handleFiltersChange}
            isSearching={isSearching || isPending}
          />
        </div>

        {/* Results Table */}
        <RepoResultsTable
          results={results}
          sort={sort}
          isLoading={isSearching || isPending}
          onSortChange={setSort}
          onPageChange={setPage}
          onRowClick={handleRowClick}
        />

        {/* Repository Detail Drawer */}
        <RepoDetailDrawer
          repository={repoDetails}
          isOpen={!!selectedRepo}
          onClose={handleCloseDrawer}
        />
      </div>
    </div>
  );
}

export default function RepositorySearchPageContent() {
  return (
    <SQLiteProvider>
      <RepositorySearchPageContentInner />
    </SQLiteProvider>
  );
}
