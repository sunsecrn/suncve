'use client';

import { useTranslations } from 'next-intl';
import type { Icon as TablerIcon } from '@tabler/icons-react';
import {
  IconGitCommit,
  IconBug,
  IconSkull,
  IconStar,
  IconTag,
  IconSearch,
  IconBrandGithub,
  IconLayoutDashboard,
  IconShieldCheck,
  IconGitPullRequest,
  IconWorld,
  IconDatabase,
  IconExternalLink,
  IconHeart,
  IconCheck,
  IconTarget,
  IconTargetArrow,
  IconShieldExclamation,
  IconPackage,
  IconAdjustmentsHorizontal,
  IconHeartHandshake,
  IconUsers
} from '@tabler/icons-react';
import {
  Card,
  CardHeader,
  CardTitle,
  CardDescription,
  CardContent
} from '@/components/ui/card';
import { Badge } from '@/components/ui/badge';
import { Button } from '@/components/ui/button';
import { Contributors } from './contributors';

function SectionHeading({
  icon: Icon,
  badge,
  title,
  lead
}: {
  icon: TablerIcon;
  badge: string;
  title: string;
  lead?: string;
}) {
  return (
    <div className='space-y-2'>
      <Badge variant='outline' className='text-xs'>
        {badge}
      </Badge>
      <div className='flex items-center gap-2.5'>
        <div className='bg-primary/10 rounded-lg p-2'>
          <Icon className='text-primary size-5' />
        </div>
        <h2 className='text-xl font-bold tracking-tight sm:text-2xl'>
          {title}
        </h2>
      </div>
      {lead && <p className='text-muted-foreground max-w-3xl'>{lead}</p>}
    </div>
  );
}

export default function ReadmePageContent() {
  const t = useTranslations('readme');

  const purposeItems = [
    {
      icon: IconGitCommit,
      color: 'text-blue-500',
      bg: 'bg-blue-500/10',
      title: t('purpose.commitsTitle'),
      text: t('purpose.commitsText')
    },
    {
      icon: IconBug,
      color: 'text-purple-500',
      bg: 'bg-purple-500/10',
      title: t('purpose.diffsTitle'),
      text: t('purpose.diffsText')
    },
    {
      icon: IconSkull,
      color: 'text-red-500',
      bg: 'bg-red-500/10',
      title: t('purpose.exploitsTitle'),
      text: t('purpose.exploitsText')
    },
    {
      icon: IconStar,
      color: 'text-amber-500',
      bg: 'bg-amber-500/10',
      title: t('purpose.starsTitle'),
      text: t('purpose.starsText')
    }
  ];

  const offerItems = [
    {
      icon: IconSearch,
      color: 'text-blue-500',
      bg: 'bg-blue-500/10',
      title: t('offers.cveSearchTitle'),
      text: t('offers.cveSearchText')
    },
    {
      icon: IconBrandGithub,
      color: 'text-purple-500',
      bg: 'bg-purple-500/10',
      title: t('offers.repoSearchTitle'),
      text: t('offers.repoSearchText')
    },
    {
      icon: IconLayoutDashboard,
      color: 'text-cyan-500',
      bg: 'bg-cyan-500/10',
      title: t('offers.dashboardTitle'),
      text: t('offers.dashboardText')
    },
    {
      icon: IconShieldCheck,
      color: 'text-red-500',
      bg: 'bg-red-500/10',
      title: t('offers.exploitsTitle'),
      text: t('offers.exploitsText')
    },
    {
      icon: IconGitPullRequest,
      color: 'text-green-500',
      bg: 'bg-green-500/10',
      title: t('offers.commitsTitle'),
      text: t('offers.commitsText')
    },
    {
      icon: IconTargetArrow,
      color: 'text-cyan-500',
      bg: 'bg-cyan-500/10',
      title: t('offers.nucleiTitle'),
      text: t('offers.nucleiText')
    },
    {
      icon: IconShieldExclamation,
      color: 'text-amber-500',
      bg: 'bg-amber-500/10',
      title: t('offers.kevTitle'),
      text: t('offers.kevText')
    },
    {
      icon: IconWorld,
      color: 'text-rose-500',
      bg: 'bg-rose-500/10',
      title: t('offers.ecosystemsTitle'),
      text: t('offers.ecosystemsText')
    }
  ];

  const filterItems = [
    t('filters.cvss'),
    t('filters.severity'),
    t('filters.cwe'),
    t('filters.flags'),
    t('filters.detection'),
    t('filters.ecosystem'),
    t('filters.popularity'),
    t('filters.language'),
    t('filters.repoStars'),
    t('filters.repository'),
    t('filters.datePeriod')
  ];

  const sources = [
    {
      title: t('sources.cvelistv5Title'),
      text: t('sources.cvelistv5Text'),
      url: 'https://github.com/CVEProject/cvelistV5',
      color: 'text-blue-500',
      bg: 'bg-blue-500/10'
    },
    {
      title: t('sources.advisoryTitle'),
      text: t('sources.advisoryText'),
      url: 'https://github.com/github/advisory-database',
      color: 'text-purple-500',
      bg: 'bg-purple-500/10'
    },
    {
      title: t('sources.pocTitle'),
      text: t('sources.pocText'),
      url: 'https://github.com/nomi-sec/PoC-in-GitHub',
      color: 'text-red-500',
      bg: 'bg-red-500/10'
    },
    {
      title: t('sources.nucleiTitle'),
      text: t('sources.nucleiText'),
      url: 'https://github.com/projectdiscovery/nuclei-templates',
      color: 'text-cyan-500',
      bg: 'bg-cyan-500/10'
    },
    {
      title: t('sources.wordfenceTitle'),
      text: t('sources.wordfenceText'),
      url: 'https://github.com/topscoder/nuclei-wordfence-cve',
      color: 'text-orange-500',
      bg: 'bg-orange-500/10'
    },
    {
      title: t('sources.missingTitle'),
      text: t('sources.missingText'),
      url: 'https://github.com/edoardottt/missing-cve-nuclei-templates',
      color: 'text-purple-500',
      bg: 'bg-purple-500/10'
    },
    {
      title: t('sources.kevTitle'),
      text: t('sources.kevText'),
      url: 'https://www.cisa.gov/known-exploited-vulnerabilities-catalog',
      color: 'text-amber-500',
      bg: 'bg-amber-500/10'
    },
    {
      title: t('sources.wordpressTitle'),
      text: t('sources.wordpressText'),
      url: 'https://github.com/rix4uni/wordpress-plugins',
      color: 'text-cyan-500',
      bg: 'bg-cyan-500/10'
    },
    {
      title: t('sources.npmTitle'),
      text: t('sources.npmText'),
      url: 'https://github.com/nice-registry/download-counts',
      color: 'text-rose-500',
      bg: 'bg-rose-500/10'
    },
    {
      title: t('sources.packagistTitle'),
      text: t('sources.packagistText'),
      url: 'https://packagist.org',
      color: 'text-indigo-500',
      bg: 'bg-indigo-500/10'
    }
  ];

  return (
    <div className='flex min-h-0 flex-col p-4 pb-8 md:px-6'>
      {/* Page header */}
      <div className='mb-6'>
        <h1 className='text-2xl font-bold tracking-tight'>{t('title')}</h1>
        <p className='text-muted-foreground'>{t('description')}</p>
      </div>

      <div className='flex flex-col space-y-10'>
        {/* Purpose / Hero */}
        <section className='space-y-4'>
          <SectionHeading
            icon={IconTarget}
            badge={t('purpose.badge')}
            title={t('purpose.title')}
          />
          <Card className='from-primary/5 to-card bg-gradient-to-t'>
            <CardContent className='space-y-3 pt-0'>
              <p className='text-base leading-relaxed'>
                {t.rich('purpose.lead', {
                  b: (c) => (
                    <strong className='text-foreground font-semibold'>
                      {c}
                    </strong>
                  ),
                  hl: (c) => (
                    <span className='text-primary font-semibold'>{c}</span>
                  )
                })}
              </p>
              <p className='text-muted-foreground leading-relaxed'>
                {t.rich('purpose.challenge', {
                  b: (c) => (
                    <strong className='text-foreground font-semibold'>
                      {c}
                    </strong>
                  ),
                  hl: (c) => (
                    <span className='text-primary font-semibold'>{c}</span>
                  )
                })}
              </p>
            </CardContent>
          </Card>
          <div className='grid grid-cols-1 gap-3 sm:grid-cols-2 sm:gap-4 lg:grid-cols-4'>
            {purposeItems.map((item) => (
              <Card key={item.title} className='@container/card gap-3'>
                <CardHeader className='gap-2'>
                  <div className={`w-fit rounded-full p-2 ${item.bg}`}>
                    <item.icon className={`size-5 ${item.color}`} />
                  </div>
                  <CardTitle className='text-base'>{item.title}</CardTitle>
                </CardHeader>
                <CardContent>
                  <p className='text-muted-foreground text-sm leading-relaxed'>
                    {item.text}
                  </p>
                </CardContent>
              </Card>
            ))}
          </div>
        </section>

        {/* Contributors */}
        <section className='space-y-4'>
          <SectionHeading
            icon={IconUsers}
            badge={t('contributors.badge')}
            title={t('contributors.title')}
            lead={t('contributors.lead')}
          />
          <Contributors />
        </section>

        {/* What SunCVE offers */}
        <section className='space-y-4'>
          <SectionHeading
            icon={IconPackage}
            badge={t('offers.badge')}
            title={t('offers.title')}
            lead={t('offers.lead')}
          />
          <div className='grid grid-cols-1 gap-3 sm:grid-cols-2 sm:gap-4 lg:grid-cols-3'>
            {offerItems.map((item) => (
              <Card key={item.title} className='@container/card gap-3'>
                <CardHeader className='gap-2'>
                  <div className='flex items-center gap-3'>
                    <div className={`rounded-full p-2 ${item.bg}`}>
                      <item.icon className={`size-5 ${item.color}`} />
                    </div>
                    <CardTitle className='text-base'>{item.title}</CardTitle>
                  </div>
                </CardHeader>
                <CardContent>
                  <p className='text-muted-foreground text-sm leading-relaxed'>
                    {item.text}
                  </p>
                </CardContent>
              </Card>
            ))}
          </div>
        </section>

        {/* Filters */}
        <section className='space-y-4'>
          <SectionHeading
            icon={IconAdjustmentsHorizontal}
            badge={t('filters.badge')}
            title={t('filters.title')}
            lead={t('filters.lead')}
          />
          <Card>
            <CardContent className='pt-0'>
              <ul className='grid grid-cols-1 gap-x-6 gap-y-3 sm:grid-cols-2'>
                {filterItems.map((item) => (
                  <li key={item} className='flex items-start gap-2'>
                    <div className='mt-0.5 rounded-full bg-green-500/10 p-1'>
                      <IconCheck className='size-3.5 text-green-500' />
                    </div>
                    <span className='text-sm'>{item}</span>
                  </li>
                ))}
              </ul>
            </CardContent>
          </Card>
        </section>

        {/* Data sources */}
        <section className='space-y-4'>
          <SectionHeading
            icon={IconHeartHandshake}
            badge={t('sources.badge')}
            title={t('sources.title')}
            lead={t('sources.lead')}
          />
          <div className='grid grid-cols-1 gap-3 sm:grid-cols-2 sm:gap-4'>
            {sources.map((src) => (
              <Card key={src.title} className='@container/card gap-3'>
                <CardHeader className='gap-2'>
                  <div className='flex items-center gap-3'>
                    <div className={`rounded-full p-2 ${src.bg}`}>
                      <IconDatabase className={`size-5 ${src.color}`} />
                    </div>
                    <CardTitle className='text-base'>{src.title}</CardTitle>
                  </div>
                  <CardDescription>{src.text}</CardDescription>
                </CardHeader>
                <CardContent>
                  <Button variant='outline' asChild size='sm'>
                    <a href={src.url} target='_blank' rel='noopener noreferrer'>
                      <IconExternalLink className='mr-2 size-4' />
                      {t('sources.visit')}
                    </a>
                  </Button>
                </CardContent>
              </Card>
            ))}
          </div>
        </section>

        {/* Footer note */}
        <div className='text-muted-foreground flex items-center justify-center gap-2 pt-2 text-sm'>
          <IconHeart className='size-4 text-red-500' />
          <span>SunCVE</span>
          <IconTag className='size-4' />
        </div>
      </div>
    </div>
  );
}
