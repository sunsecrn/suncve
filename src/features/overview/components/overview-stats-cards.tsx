'use client';

import { useEffect, useState } from 'react';
import {
  Card,
  CardHeader,
  CardTitle,
  CardDescription,
  CardAction,
  CardFooter
} from '@/components/ui/card';
import {
  IconShieldExclamation,
  IconAlertTriangle,
  IconBug,
  IconGitCommit,
  IconShieldChevron
} from '@tabler/icons-react';
import { useTranslations } from 'next-intl';
import {
  useDashboardStats,
  type DashboardStats
} from '@/lib/sqlite/use-dashboard-stats';
import { EpssSignal } from '@/components/epss-signal';

export function OverviewStatsCards() {
  const t = useTranslations('dashboard');
  const { getRecentStats, isReady } = useDashboardStats();
  const [stats, setStats] = useState<DashboardStats>({
    newCVEs: 0,
    newCriticalCVEs: 0,
    newWithExploit: 0,
    newWithFix: 0,
    newInKev: 0,
    newHighEpss: 0
  });

  useEffect(() => {
    if (isReady) {
      const data = getRecentStats();
      setStats(data);
    }
  }, [isReady, getRecentStats]);

  return (
    <div
      data-tour='stats-cards'
      className='*:data-[slot=card]:from-primary/5 *:data-[slot=card]:to-card dark:*:data-[slot=card]:bg-card grid grid-cols-1 gap-4 *:data-[slot=card]:bg-gradient-to-t *:data-[slot=card]:shadow-xs md:grid-cols-2 lg:grid-cols-6'
    >
      <Card className='@container/card'>
        <CardHeader>
          <CardDescription>{t('newCVEs')}</CardDescription>
          <CardTitle className='text-2xl font-semibold tabular-nums @[250px]/card:text-3xl'>
            {stats.newCVEs.toLocaleString()}
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
            {stats.newCriticalCVEs.toLocaleString()}
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
            {stats.newWithExploit.toLocaleString()}
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
            {stats.newWithFix.toLocaleString()}
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
            {stats.newInKev.toLocaleString()}
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
          <CardDescription>{t('newHighEpss')}</CardDescription>
          <CardTitle className='text-2xl font-semibold tabular-nums @[250px]/card:text-3xl'>
            {stats.newHighEpss.toLocaleString()}
          </CardTitle>
          <CardAction>
            <span className='flex items-center gap-1 text-xs font-medium text-rose-600'>
              <EpssSignal epss={0.5} label='EPSS' />
              EPSS
            </span>
          </CardAction>
        </CardHeader>
        <CardFooter className='flex-col items-start gap-1.5 text-sm'>
          <div className='line-clamp-1 flex items-center gap-2 font-medium'>
            {t('newHighEpssFooter')} <EpssSignal epss={0.9} label='EPSS' />
          </div>
          <div className='text-muted-foreground'>{t('epssThreshold')}</div>
        </CardFooter>
      </Card>
    </div>
  );
}
