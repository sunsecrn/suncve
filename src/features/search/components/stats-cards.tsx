'use client';

import { useTranslations } from 'next-intl';
import {
  IconBug,
  IconBrandGithub,
  IconSkull,
  IconGitCommit,
  IconTrendingUp,
  IconShieldExclamation
} from '@tabler/icons-react';
import {
  Card,
  CardHeader,
  CardTitle,
  CardDescription,
  CardAction,
  CardFooter
} from '@/components/ui/card';
import { Badge } from '@/components/ui/badge';

interface StatsCardsProps {
  stats: {
    totalCVEs: number;
    totalRepos: number;
    withExploit: number;
    withCommit: number;
    inKev: number;
  };
}

export function StatsCards({ stats }: StatsCardsProps) {
  const t = useTranslations('search.stats');

  // Calculate percentages
  const exploitPercent =
    stats.totalCVEs > 0
      ? ((stats.withExploit / stats.totalCVEs) * 100).toFixed(1)
      : '0';
  const commitPercent =
    stats.totalCVEs > 0
      ? ((stats.withCommit / stats.totalCVEs) * 100).toFixed(1)
      : '0';
  const kevPercent =
    stats.totalCVEs > 0
      ? ((stats.inKev / stats.totalCVEs) * 100).toFixed(1)
      : '0';

  return (
    <div
      className='*:data-[slot=card]:from-primary/5 *:data-[slot=card]:to-card dark:*:data-[slot=card]:bg-card grid grid-cols-2 gap-3 *:data-[slot=card]:bg-gradient-to-t *:data-[slot=card]:shadow-xs sm:gap-4 lg:grid-cols-5'
      data-tour='cve-stats'
    >
      <Card className='@container/card'>
        <CardHeader className='p-4 pb-2 sm:p-6 sm:pb-2'>
          <CardDescription className='text-xs sm:text-sm'>
            {t('totalCVEs')}
          </CardDescription>
          <CardTitle className='text-xl font-semibold tabular-nums sm:text-2xl @[250px]/card:text-3xl'>
            {stats.totalCVEs.toLocaleString()}
          </CardTitle>
          <CardAction>
            <div className='rounded-full bg-blue-500/10 p-1.5 sm:p-2'>
              <IconBug className='h-4 w-4 text-blue-500 sm:h-5 sm:w-5' />
            </div>
          </CardAction>
        </CardHeader>
        <CardFooter className='flex-col items-start gap-1 p-4 pt-0 text-xs sm:gap-1.5 sm:p-6 sm:pt-0 sm:text-sm'>
          <div className='line-clamp-1 flex gap-2 font-medium'>
            {t('vulnerabilities')}
          </div>
          <div className='text-muted-foreground hidden sm:block'>
            {t('inDatabase')}
          </div>
        </CardFooter>
      </Card>

      <Card className='@container/card'>
        <CardHeader className='p-4 pb-2 sm:p-6 sm:pb-2'>
          <CardDescription className='text-xs sm:text-sm'>
            {t('repositories')}
          </CardDescription>
          <CardTitle className='text-xl font-semibold tabular-nums sm:text-2xl @[250px]/card:text-3xl'>
            {stats.totalRepos.toLocaleString()}
          </CardTitle>
          <CardAction>
            <div className='rounded-full bg-purple-500/10 p-1.5 sm:p-2'>
              <IconBrandGithub className='h-4 w-4 text-purple-500 sm:h-5 sm:w-5' />
            </div>
          </CardAction>
        </CardHeader>
        <CardFooter className='flex-col items-start gap-1 p-4 pt-0 text-xs sm:gap-1.5 sm:p-6 sm:pt-0 sm:text-sm'>
          <div className='line-clamp-1 flex gap-2 font-medium'>
            {t('githubRepos')}
          </div>
          <div className='text-muted-foreground hidden sm:block'>
            {t('linkedToCVEs')}
          </div>
        </CardFooter>
      </Card>

      <Card className='@container/card'>
        <CardHeader className='p-4 pb-2 sm:p-6 sm:pb-2'>
          <CardDescription className='text-xs sm:text-sm'>
            {t('withExploit')}
          </CardDescription>
          <CardTitle className='text-xl font-semibold tabular-nums sm:text-2xl @[250px]/card:text-3xl'>
            {stats.withExploit.toLocaleString()}
          </CardTitle>
          <CardAction>
            <Badge
              variant='outline'
              className='border-red-500/50 text-xs text-red-500'
            >
              {exploitPercent}%
            </Badge>
          </CardAction>
        </CardHeader>
        <CardFooter className='flex-col items-start gap-1 p-4 pt-0 text-xs sm:gap-1.5 sm:p-6 sm:pt-0 sm:text-sm'>
          <div className='line-clamp-1 flex gap-2 font-medium text-red-500'>
            <IconSkull className='size-3 sm:size-4' />
            {t('exploitAvailable')}
          </div>
          <div className='text-muted-foreground hidden sm:block'>
            {t('publicExploits')}
          </div>
        </CardFooter>
      </Card>

      <Card className='@container/card'>
        <CardHeader className='p-4 pb-2 sm:p-6 sm:pb-2'>
          <CardDescription className='text-xs sm:text-sm'>
            {t('withCommitFix')}
          </CardDescription>
          <CardTitle className='text-xl font-semibold tabular-nums sm:text-2xl @[250px]/card:text-3xl'>
            {stats.withCommit.toLocaleString()}
          </CardTitle>
          <CardAction>
            <Badge
              variant='outline'
              className='border-green-500/50 text-xs text-green-500'
            >
              <IconTrendingUp className='mr-1 size-3' />
              {commitPercent}%
            </Badge>
          </CardAction>
        </CardHeader>
        <CardFooter className='flex-col items-start gap-1 p-4 pt-0 text-xs sm:gap-1.5 sm:p-6 sm:pt-0 sm:text-sm'>
          <div className='line-clamp-1 flex gap-2 font-medium text-green-500'>
            <IconGitCommit className='size-3 sm:size-4' />
            {t('fixAvailable')}
          </div>
          <div className='text-muted-foreground hidden sm:block'>
            {t('patchCommits')}
          </div>
        </CardFooter>
      </Card>

      <Card className='@container/card'>
        <CardHeader className='p-4 pb-2 sm:p-6 sm:pb-2'>
          <CardDescription className='text-xs sm:text-sm'>
            {t('inKev')}
          </CardDescription>
          <CardTitle className='text-xl font-semibold tabular-nums sm:text-2xl @[250px]/card:text-3xl'>
            {stats.inKev.toLocaleString()}
          </CardTitle>
          <CardAction>
            <Badge
              variant='outline'
              className='border-amber-500/50 text-xs text-amber-500'
            >
              {kevPercent}%
            </Badge>
          </CardAction>
        </CardHeader>
        <CardFooter className='flex-col items-start gap-1 p-4 pt-0 text-xs sm:gap-1.5 sm:p-6 sm:pt-0 sm:text-sm'>
          <div className='line-clamp-1 flex gap-2 font-medium text-amber-500'>
            <IconShieldExclamation className='size-3 sm:size-4' />
            {t('kevListed')}
          </div>
          <div className='text-muted-foreground hidden sm:block'>
            {t('kevCatalog')}
          </div>
        </CardFooter>
      </Card>
    </div>
  );
}
