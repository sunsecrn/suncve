'use client';

import dynamic from 'next/dynamic';
import PageContainer from '@/components/layout/page-container';
import React, { useEffect } from 'react';
import { WelcomeHeader } from '@/features/overview/components/welcome-header';
import { useContentReady } from '@/hooks/use-content-ready';
import { SQLiteProvider, useSQLite } from '@/lib/sqlite';
import { DB_MANIFEST_URL, DB_FALLBACK_URL } from '@/lib/db-config';
import { DatabaseLoader } from '@/features/search/components/database-loader';

const OverviewStatsCards = dynamic(
  () =>
    import('@/features/overview/components/overview-stats-cards').then(
      (mod) => mod.OverviewStatsCards
    ),
  { ssr: false }
);

function OverViewLayoutInner({
  sales,
  pie_stats,
  bar_stats,
  area_stats
}: {
  sales: React.ReactNode;
  pie_stats: React.ReactNode;
  bar_stats: React.ReactNode;
  area_stats: React.ReactNode;
}) {
  const {
    isReady,
    isLoading,
    error,
    progress,
    loadDatabase,
    loadDatabaseWithManifest
  } = useSQLite();

  const setContentReady = useContentReady((s) => s.setReady);

  // Reveal the layout footer only once the DB (and thus the charts) is ready.
  useEffect(() => {
    setContentReady(isReady);
    return () => setContentReady(false);
  }, [isReady, setContentReady]);

  // Set page title
  useEffect(() => {
    document.title = 'Dashboard | SunCVE';
  }, []);

  // Load database on mount
  useEffect(() => {
    if (!isReady && !isLoading && !error) {
      loadDatabaseWithManifest(DB_MANIFEST_URL).catch(() => {
        console.warn('Manifest not found, loading directly from URL');
        loadDatabase(DB_FALLBACK_URL);
      });
    }
  }, [isReady, isLoading, error, loadDatabase, loadDatabaseWithManifest]);

  // Show loader while database is loading
  if (!isReady) {
    return (
      <PageContainer>
        <DatabaseLoader
          isLoading={isLoading}
          progress={progress}
          error={error}
          onRetry={() => loadDatabase(DB_FALLBACK_URL)}
        />
      </PageContainer>
    );
  }

  return (
    <PageContainer>
      <div className='flex flex-1 flex-col space-y-2'>
        <WelcomeHeader />
        <OverviewStatsCards />
        <div
          data-tour='charts'
          className='grid grid-cols-1 gap-4 md:grid-cols-2 lg:grid-cols-7'
        >
          <div className='col-span-4'>{bar_stats}</div>
          <div className='col-span-4 md:col-span-3'>{sales}</div>
          <div className='col-span-4'>{area_stats}</div>
          <div className='col-span-4 md:col-span-3'>{pie_stats}</div>
        </div>
      </div>
    </PageContainer>
  );
}

export default function OverViewLayout({
  sales,
  pie_stats,
  bar_stats,
  area_stats
}: {
  sales: React.ReactNode;
  pie_stats: React.ReactNode;
  bar_stats: React.ReactNode;
  area_stats: React.ReactNode;
}) {
  return (
    <SQLiteProvider>
      <OverViewLayoutInner
        sales={sales}
        pie_stats={pie_stats}
        bar_stats={bar_stats}
        area_stats={area_stats}
      />
    </SQLiteProvider>
  );
}
