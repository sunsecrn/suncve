'use client';

import { useEffect, useState, useCallback } from 'react';
import { useRouter } from 'next/navigation';
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
  IconSkull,
  IconGitCommit,
  IconTargetArrow,
  IconShieldExclamation,
  IconArrowRight
} from '@tabler/icons-react';
import { CVEDetailDrawer } from '@/features/search/components/cve-detail-drawer';
import { EpssSignal } from '@/components/epss-signal';
import { useCVESearch } from '@/lib/sqlite/use-cve-search';

const LIMIT = 15;
const PER_COLUMN = 5;

// Reproduz exatamente o filtro da lista na busca: o bucket 'critical' é
// epss >= 0.7, e cvssMin vira IN (SELECT cve_id FROM cve_scores WHERE score >= 9).
// Sem sort na URL: o padrão da busca já é data de publicação decrescente,
// a mesma ordem da faixa.
const SEARCH_HREF = '/dashboard/search?epss=critical&cvssMin=9';

/**
 * Faixa do dashboard com a fila de "corrija primeiro": CVEs graves (CVSS 9.0+)
 * que o EPSS aponta como quase certas de serem exploradas (>= 70%), da mais
 * recente para a mais antiga. Mesmo desenho de linha do card "CVEs Críticas
 * com Exploit", em três colunas de cinco separadas por réguas.
 */
export function EpssCriticalCVEs() {
  const t = useTranslations('charts');
  const locale = useLocale();
  const router = useRouter();
  const { getCriticalHighEpssCVEs, isReady } = useDashboardStats();
  const { getCVEDetails } = useCVESearch();
  const [cves, setCves] = useState<CriticalCVEWithPOC[]>([]);
  const [selectedCVE, setSelectedCVE] = useState<Record<
    string,
    unknown
  > | null>(null);
  const [isDrawerOpen, setIsDrawerOpen] = useState(false);

  const handleCVEClick = useCallback(
    (cveId: string) => {
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
      setCves(getCriticalHighEpssCVEs(LIMIT));
    }
  }, [isReady, getCriticalHighEpssCVEs]);

  const formatDate = (dateStr: string | null) => {
    if (!dateStr) return '-';
    return new Date(dateStr).toLocaleDateString(locale, {
      day: '2-digit',
      month: 'short',
      year: 'numeric'
    });
  };

  // Colunas com a sequência preservada: 1-5, 6-10, 11-15.
  const columns: CriticalCVEWithPOC[][] = [];
  for (let i = 0; i < cves.length; i += PER_COLUMN) {
    columns.push(cves.slice(i, i + PER_COLUMN));
  }

  return (
    <Card className='h-full'>
      <CardHeader>
        <CardTitle className='flex items-center gap-2'>
          <EpssSignal epss={0.9} label={t('tagEpss')} />
          {t('epssCritical')}
        </CardTitle>
        <CardDescription>{t('epssCriticalDescription')}</CardDescription>
      </CardHeader>
      <CardContent>
        {cves.length === 0 ? (
          <div className='text-muted-foreground py-8 text-center'>
            {t('noEpssCritical')}
          </div>
        ) : (
          <>
            <div className='divide-border grid grid-cols-1 divide-y lg:grid-cols-3 lg:divide-x lg:divide-y-0'>
              {columns.map((column, columnIndex) => (
                <div
                  key={columnIndex}
                  className='space-y-4 py-4 first:pt-0 last:pb-0 lg:px-6 lg:py-0 lg:first:pl-0 lg:last:pr-0'
                >
                  {column.map((cve) => (
                    <div
                      key={cve.cve_id}
                      className='hover:bg-muted/50 -mx-2 flex cursor-pointer items-start gap-3 rounded-lg px-2 py-2 transition-colors'
                      onClick={() => handleCVEClick(cve.cve_id)}
                    >
                      <div className='flex h-9 w-9 shrink-0 items-center justify-center rounded-full bg-red-100 dark:bg-red-900/30'>
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
                          </div>
                        </div>
                        <p className='text-muted-foreground truncate text-xs'>
                          {cve.title || cve.description || '-'}
                        </p>
                      </div>
                      <div className='text-muted-foreground text-xs whitespace-nowrap'>
                        {formatDate(cve.date_published)}
                      </div>
                    </div>
                  ))}
                </div>
              ))}
            </div>
            <button
              type='button'
              onClick={() => router.push(SEARCH_HREF)}
              className='text-muted-foreground hover:text-foreground mt-4 flex items-center gap-1.5 text-sm transition-colors'
            >
              {t('viewAllInSearch')}
              <IconArrowRight className='h-4 w-4' />
            </button>
          </>
        )}
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
