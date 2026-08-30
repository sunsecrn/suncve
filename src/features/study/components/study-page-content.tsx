'use client';

import { useCallback, useEffect, useRef, useState } from 'react';
import { useTranslations } from 'next-intl';
import { toast } from 'sonner';
import { IconDownload, IconUpload, IconNotebook } from '@tabler/icons-react';
import { SQLiteProvider, useSQLite } from '@/lib/sqlite';
import { DB_MANIFEST_URL, DB_FALLBACK_URL } from '@/lib/db-config';
import { useCVESearch } from '@/lib/sqlite/use-cve-search';
import { useContentReady } from '@/hooks/use-content-ready';
import { Button } from '@/components/ui/button';
import {
  Tabs,
  TabsList,
  TabsTrigger,
  TabsContent
} from '@/components/ui/tabs';
import { CVEDetailDrawer } from '@/features/search/components/cve-detail-drawer';
import { useStudyStore, useStudyHydrated } from '../store/use-study-store';
import { exportToFile, parseImportFile } from '../lib/backup';
import { FavoritesSection } from './favorites-section';
import { HistorySection } from './history-section';
import { LabelsSection } from './labels-section';

function StudyPageContentInner() {
  const t = useTranslations('studies');

  useEffect(() => {
    document.title = 'Meus Estudos | SunCVE';
  }, []);

  const {
    isReady,
    isLoading,
    error,
    loadDatabase,
    loadDatabaseWithManifest
  } = useSQLite();
  const { getCVEDetails } = useCVESearch();
  const hydrated = useStudyHydrated();
  const importData = useStudyStore((s) => s.importData);

  const [selectedCve, setSelectedCve] = useState<Record<
    string,
    unknown
  > | null>(null);
  const fileInputRef = useRef<HTMLInputElement>(null);

  // Carrega o DB em segundo plano (só é preciso ao abrir o detalhe de uma CVE).
  useEffect(() => {
    if (!isReady && !isLoading && !error) {
      loadDatabaseWithManifest(DB_MANIFEST_URL).catch(() => {
        loadDatabase(DB_FALLBACK_URL);
      });
    }
  }, [isReady, isLoading, error, loadDatabase, loadDatabaseWithManifest]);

  // Nosso conteúdo não depende do DB — libera o footer assim que monta.
  const setContentReady = useContentReady((s) => s.setReady);
  useEffect(() => {
    setContentReady(true);
    return () => setContentReady(false);
  }, [setContentReady]);

  const openCve = useCallback(
    (cveId: string) => {
      if (!isReady) {
        toast.info(t('dbLoading'));
        return;
      }
      const details = getCVEDetails(cveId);
      if (details) {
        setSelectedCve(details as Record<string, unknown>);
      } else {
        toast.error(t('cveNotFound', { id: cveId }));
      }
    },
    [isReady, getCVEDetails, t]
  );

  const handleImportFile = async (
    e: React.ChangeEvent<HTMLInputElement>
  ) => {
    const file = e.target.files?.[0];
    e.target.value = '';
    if (!file) return;
    try {
      const data = await parseImportFile(file);
      if (window.confirm(t('import.confirmReplace'))) {
        importData(data);
        toast.success(t('import.success'));
      }
    } catch {
      toast.error(t('import.error'));
    }
  };

  return (
    <div className='flex flex-1 flex-col p-4 pb-8 md:px-6'>
      {/* Header */}
      <div className='mb-4 flex flex-col gap-3 sm:flex-row sm:items-start sm:justify-between'>
        <div>
          <h1 className='flex items-center gap-2 text-2xl font-bold tracking-tight'>
            <IconNotebook className='text-primary h-6 w-6' />
            {t('title')}
          </h1>
          <p className='text-muted-foreground'>{t('description')}</p>
        </div>
        <div className='flex shrink-0 items-center gap-2'>
          <Button
            variant='outline'
            size='sm'
            className='gap-1.5'
            onClick={() => fileInputRef.current?.click()}
          >
            <IconUpload className='h-4 w-4' />
            {t('import.button')}
          </Button>
          <Button
            variant='outline'
            size='sm'
            className='gap-1.5'
            onClick={exportToFile}
          >
            <IconDownload className='h-4 w-4' />
            {t('export.button')}
          </Button>
          <input
            ref={fileInputRef}
            type='file'
            accept='application/json,.json'
            className='hidden'
            onChange={handleImportFile}
          />
        </div>
      </div>

      {!hydrated ? (
        <div className='flex min-h-[300px] items-center justify-center'>
          <div className='border-primary h-8 w-8 animate-spin rounded-full border-b-2' />
        </div>
      ) : (
        <Tabs defaultValue='favorites' className='w-full'>
          <TabsList>
            <TabsTrigger value='favorites'>{t('tabs.favorites')}</TabsTrigger>
            <TabsTrigger value='history'>{t('tabs.history')}</TabsTrigger>
            <TabsTrigger value='labels'>{t('tabs.labels')}</TabsTrigger>
          </TabsList>
          <TabsContent value='favorites' className='mt-4'>
            <FavoritesSection onOpenCve={openCve} />
          </TabsContent>
          <TabsContent value='history' className='mt-4'>
            <HistorySection onOpenCve={openCve} />
          </TabsContent>
          <TabsContent value='labels' className='mt-4'>
            <LabelsSection onOpenCve={openCve} />
          </TabsContent>
        </Tabs>
      )}

      <CVEDetailDrawer
        cve={selectedCve}
        isOpen={!!selectedCve}
        onClose={() => setSelectedCve(null)}
      />
    </div>
  );
}

export default function StudyPageContent() {
  return (
    <SQLiteProvider>
      <StudyPageContentInner />
    </SQLiteProvider>
  );
}
