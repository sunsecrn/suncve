'use client';

import { useEffect, useState } from 'react';
import { useRouter } from 'next/navigation';
import {
  Card,
  CardHeader,
  CardTitle,
  CardDescription,
  CardAction,
  CardContent,
  CardFooter
} from '@/components/ui/card';
import {
  IconShieldExclamation,
  IconAlertTriangle,
  IconBug,
  IconGitCommit,
  IconShieldChevron,
  IconTrendingUp
} from '@tabler/icons-react';
import { useTranslations, useLocale } from 'next-intl';
import {
  useDashboardStats,
  type DashboardStats,
  type EpssDistributionStats
} from '@/lib/sqlite/use-dashboard-stats';
import { EpssDistribution } from '@/components/epss-distribution';
import { Badge } from '@/components/ui/badge';
import { EPSS_LEVELS, type EpssFilterLevel } from '@/features/search/types';

const EMPTY_EPSS: EpssDistributionStats = {
  'very-low': 0,
  low: 0,
  moderate: 0,
  high: 0,
  critical: 0,
  unscored: 0
};

export function OverviewStatsCards() {
  const t = useTranslations('dashboard');
  const tEpss = useTranslations('epss');
  const locale = useLocale();
  const router = useRouter();
  const { getRecentStats, getEpssDistribution, isReady } = useDashboardStats();
  const [stats, setStats] = useState<DashboardStats>({
    newCVEs: 0,
    newCriticalCVEs: 0,
    newWithExploit: 0,
    newWithFix: 0,
    newInKev: 0
  });
  const [epss, setEpss] = useState<EpssDistributionStats>(EMPTY_EPSS);

  useEffect(() => {
    if (isReady) {
      setStats(getRecentStats());
      setEpss(getEpssDistribution());
    }
  }, [isReady, getRecentStats, getEpssDistribution]);

  const epssLevelLabels = Object.fromEntries(
    EPSS_LEVELS.map((level) => [level, tEpss(`levels.${level}`)])
  ) as Record<EpssFilterLevel, string>;

  // "Chance real" = 10% ou mais de probabilidade, ou seja moderate para cima.
  const epssRealChance = epss.moderate + epss.high + epss.critical;
  const epssScored =
    epss['very-low'] + epss.low + epss.moderate + epss.high + epss.critical;
  const epssPercent =
    epssScored > 0
      ? String(Math.round((epssRealChance / epssScored) * 100))
      : '0';
  const nf = new Intl.NumberFormat(locale);

  return (
    <div
      data-tour='stats-cards'
      className='*:data-[slot=card]:from-primary/5 *:data-[slot=card]:to-card dark:*:data-[slot=card]:bg-card grid grid-cols-1 gap-4 *:data-[slot=card]:bg-gradient-to-t *:data-[slot=card]:shadow-xs md:grid-cols-2 lg:grid-cols-3 xl:grid-cols-6'
    >
      <Card className='@container/card'>
        <CardHeader>
          <CardDescription>{t('newCVEs')}</CardDescription>
          <CardTitle className='text-2xl font-semibold tabular-nums @[250px]/card:text-3xl'>
            {nf.format(stats.newCVEs)}
          </CardTitle>
          <CardAction>
            <span className='flex items-center gap-1 text-xs font-medium text-blue-600'>
              <IconShieldExclamation className='h-4 w-4' />
              30d
            </span>
          </CardAction>
        </CardHeader>
        <CardFooter className='flex-col items-start gap-1.5 text-sm'>
          <div className='line-clamp-1 flex gap-2 font-medium'>
            {t('newCVEsFooter')}{' '}
            <IconShieldExclamation className='size-4 text-blue-500' />
          </div>
          <div className='text-muted-foreground'>{t('last30Days')}</div>
        </CardFooter>
      </Card>
      <Card className='@container/card'>
        <CardHeader>
          <CardDescription>{t('criticalCVEs')}</CardDescription>
          <CardTitle className='text-2xl font-semibold tabular-nums @[250px]/card:text-3xl'>
            {nf.format(stats.newCriticalCVEs)}
          </CardTitle>
          <CardAction>
            <span className='flex items-center gap-1 text-xs font-medium text-red-600'>
              <IconAlertTriangle className='h-4 w-4' />
              9.0+
            </span>
          </CardAction>
        </CardHeader>
        <CardFooter className='flex-col items-start gap-1.5 text-sm'>
          <div className='line-clamp-1 flex gap-2 font-medium'>
            {t('criticalCVEsFooter')}{' '}
            <IconAlertTriangle className='size-4 text-red-500' />
          </div>
          <div className='text-muted-foreground'>{t('cvssScore9Plus')}</div>
        </CardFooter>
      </Card>
      <Card className='@container/card'>
        <CardHeader>
          <CardDescription>{t('newExploits')}</CardDescription>
          <CardTitle className='text-2xl font-semibold tabular-nums @[250px]/card:text-3xl'>
            {nf.format(stats.newWithExploit)}
          </CardTitle>
          <CardAction>
            <span className='flex items-center gap-1 text-xs font-medium text-orange-600'>
              <IconBug className='h-4 w-4' />
              Exploit
            </span>
          </CardAction>
        </CardHeader>
        <CardFooter className='flex-col items-start gap-1.5 text-sm'>
          <div className='line-clamp-1 flex gap-2 font-medium'>
            {t('newExploitsFooter')}{' '}
            <IconBug className='size-4 text-orange-500' />
          </div>
          <div className='text-muted-foreground'>{t('exploitsAvailable')}</div>
        </CardFooter>
      </Card>
      <Card className='@container/card'>
        <CardHeader>
          <CardDescription>{t('newFixes')}</CardDescription>
          <CardTitle className='text-2xl font-semibold tabular-nums @[250px]/card:text-3xl'>
            {nf.format(stats.newWithFix)}
          </CardTitle>
          <CardAction>
            <span className='flex items-center gap-1 text-xs font-medium text-green-600'>
              <IconGitCommit className='h-4 w-4' />
              Fix
            </span>
          </CardAction>
        </CardHeader>
        <CardFooter className='flex-col items-start gap-1.5 text-sm'>
          <div className='line-clamp-1 flex gap-2 font-medium'>
            {t('newFixesFooter')}{' '}
            <IconGitCommit className='size-4 text-green-500' />
          </div>
          <div className='text-muted-foreground'>{t('patchesReleased')}</div>
        </CardFooter>
      </Card>
      <Card className='@container/card'>
        <CardHeader>
          <CardDescription>{t('newInKev')}</CardDescription>
          <CardTitle className='text-2xl font-semibold tabular-nums @[250px]/card:text-3xl'>
            {nf.format(stats.newInKev)}
          </CardTitle>
          <CardAction>
            <span className='flex items-center gap-1 text-xs font-medium text-amber-600'>
              <IconShieldChevron className='h-4 w-4' />
              KEV
            </span>
          </CardAction>
        </CardHeader>
        <CardFooter className='flex-col items-start gap-1.5 text-sm'>
          <div className='line-clamp-1 flex gap-2 font-medium'>
            {t('newInKevFooter')}{' '}
            <IconShieldChevron className='size-4 text-amber-500' />
          </div>
          <div className='text-muted-foreground'>{t('cisaCatalog')}</div>
        </CardFooter>
      </Card>
      <Card className='@container/card'>
        <CardHeader>
          <CardDescription>{tEpss('distribution')}</CardDescription>
          <CardTitle className='text-2xl font-semibold tabular-nums @[250px]/card:text-3xl'>
            {nf.format(epssRealChance)}
          </CardTitle>
          <CardAction>
            <Badge
              variant='outline'
              className='border-rose-500/50 text-xs text-rose-500'
            >
              {epssPercent}%
            </Badge>
          </CardAction>
        </CardHeader>
        <CardContent>
          <EpssDistribution
            counts={epss}
            locale={locale}
            levelLabels={epssLevelLabels}
            onSelect={(level) => router.push(`/dashboard/search?epss=${level}`)}
          />
        </CardContent>
        <CardFooter className='flex-col items-start gap-1.5 text-sm'>
          <div className='line-clamp-1 flex gap-2 font-medium text-rose-500'>
            <IconTrendingUp className='size-4' />
            {tEpss('realChance')}
          </div>
          <div className='text-muted-foreground'>
            {epssScored > 0
              ? tEpss('scoredOf', { total: nf.format(epssScored) })
              : tEpss('noScores')}
          </div>
        </CardFooter>
      </Card>
    </div>
  );
}
