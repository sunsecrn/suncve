'use client';

import { useEffect, useState, useCallback } from 'react';
import { Badge } from '@/components/ui/badge';
import {
  Card,
  CardHeader,
  CardContent,
  CardTitle,
  CardDescription
} from '@/components/ui/card';
import { useTranslations, useLocale } from 'next-intl';
import {
  useDashboardStats,
  type CriticalCVEWithPOC
} from '@/lib/sqlite/use-dashboard-stats';
import {
  IconBug,
  IconAlertTriangle,
  IconSkull,
  IconGitCommit,
  IconTargetArrow,
  IconShieldExclamation
} from '@tabler/icons-react';
import { CVEDetailDrawer } from '@/features/search/components/cve-detail-drawer';
import { EpssSignal } from '@/components/epss-signal';
import { useCVESearch } from '@/lib/sqlite/use-cve-search';

export function CriticalCVEs() {
  const t = useTranslations('charts');
  const locale = useLocale();
  const { getCriticalCVEsWithPOC, isReady } = useDashboardStats();
  const { getCVEDetails } = useCVESearch();
  const [cves, setCves] = useState<CriticalCVEWithPOC[]>([]);
  const [selectedCVE, setSelectedCVE] = useState<Record<
    string,
    unknown
  > | null>(null);
  const [isDrawerOpen, setIsDrawerOpen] = useState(false);

  const handleCVEClick = useCallback(
    async (cveId: string) => {
      const details = getCVEDetails(cveId);
      if (details) {
        setSelectedCVE(details as Record<string, unknown>);
        setIsDrawerOpen(true);
      }
    },
    [getCVEDetails]
  );

  const handleCloseDrawer = useCallback(() => {
    setIsDrawerOpen(false);
    setSelectedCVE(null);
  }, []);

  useEffect(() => {
    if (isReady) {
      const data = getCriticalCVEsWithPOC();
      setCves(data);
    }
  }, [isReady, getCriticalCVEsWithPOC]);

  const formatDate = (dateStr: string | null) => {
    if (!dateStr) return '-';
    const date = new Date(dateStr);
    return date.toLocaleDateString(locale, {
      day: '2-digit',
      month: 'short'
    });
  };

  const truncateText = (text: string | null, maxLength: number = 50) => {
    if (!text) return '-';
    return text.length > maxLength
      ? text.substring(0, maxLength) + '...'
      : text;
  };

  return (
    <Card className='h-full'>
      <CardHeader>
        <CardTitle className='flex items-center gap-2'>
          <IconAlertTriangle className='h-5 w-5 text-red-500' />
          {t('criticalCVEs')}
        </CardTitle>
        <CardDescription>{t('criticalCVEsDescription')}</CardDescription>
      </CardHeader>
      <CardContent>
        <div className='space-y-6'>
          {cves.length === 0 ? (
            <div className='text-muted-foreground py-8 text-center'>
              {t('noCriticalCVEs')}
            </div>
          ) : (
            cves.map((cve) => (
              <div
                key={cve.cve_id}
                className='hover:bg-muted/50 -mx-2 flex cursor-pointer items-start gap-3 rounded-lg px-2 py-2 transition-colors'
                onClick={() => handleCVEClick(cve.cve_id)}
              >
                <div className='flex h-9 w-9 items-center justify-center rounded-full bg-red-100 dark:bg-red-900/30'>
                  <IconBug className='h-4 w-4 text-red-600 dark:text-red-400' />
                </div>
                <div className='min-w-0 flex-1 space-y-1'>
                  <div className='flex flex-wrap items-center gap-2'>
                    <p className='font-mono text-sm leading-none font-medium'>
                      {cve.cve_id}
                    </p>
                    <Badge variant='destructive' className='text-xs'>
                      {cve.score?.toFixed(1) ?? '-'}
                    </Badge>
                    <EpssSignal
                      epss={cve.epss}
                      percentile={cve.epss_percentile}
                      locale={locale}
                      label={t('tagEpss')}
                      showValue
                    />
                    <div className='flex flex-nowrap gap-1'>
                      {cve.exists_exploit ? (
                        <Badge
                          variant='destructive'
                          className='px-1'
                          title={t('tagExploit')}
                        >
                          <IconSkull className='h-3 w-3' />
                        </Badge>
                      ) : null}
                      {cve.exists_commit ? (
                        <Badge
                          variant='secondary'
                          className='bg-green-500/20 px-1 text-green-700 dark:text-green-400'
                          title={t('tagCommit')}
                        >
                          <IconGitCommit className='h-3 w-3' />
                        </Badge>
                      ) : null}
                      {cve.exists_nuclei ? (
                        <Badge
                          variant='secondary'
                          className='bg-cyan-500/20 px-1 text-cyan-700 dark:text-cyan-400'
                          title={t('tagNuclei')}
                        >
                          <IconTargetArrow className='h-3 w-3' />
                        </Badge>
                      ) : null}
                      {cve.in_kev ? (
                        <Badge
                          variant='secondary'
                          className='bg-amber-500/20 px-1 text-amber-700 dark:text-amber-400'
                          title={t('tagKev')}
                        >
                          <IconShieldExclamation className='h-3 w-3' />
                        </Badge>
                      ) : null}
                      {cve.missing_nuclei_template ? (
                        <Badge
                          variant='outline'
                          className='border-dashed border-purple-500/50 px-1 text-purple-600 dark:text-purple-400'
                          title={t('tagMissing')}
                        >
                          <IconTargetArrow className='h-3 w-3 opacity-50' />
                        </Badge>
                      ) : null}
                    </div>
                  </div>
                  <p className='text-muted-foreground truncate text-xs'>
                    {truncateText(cve.title || cve.description, 60)}
                  </p>
                </div>
                <div className='text-muted-foreground text-xs whitespace-nowrap'>
                  {formatDate(cve.date_published)}
                </div>
              </div>
            ))
          )}
        </div>
      </CardContent>

      {/* CVE Detail Drawer */}
      <CVEDetailDrawer
        cve={selectedCVE}
        isOpen={isDrawerOpen}
        onClose={handleCloseDrawer}
      />
    </Card>
  );
}
