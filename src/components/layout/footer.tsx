'use client';

import Image from 'next/image';
import Link from 'next/link';
import { useTranslations } from 'next-intl';
import { IconBrandGithub, IconBrandInstagram } from '@tabler/icons-react';
import { withBasePath } from '@/lib/base-path';
import { useContentReady } from '@/hooks/use-content-ready';

const GITHUB_ORG = 'https://github.com/sunsecrn';
const GITHUB_REPO = 'https://github.com/sunsecrn/suncve';
const INSTAGRAM = 'https://www.instagram.com/sunsecrn';

interface FooterLink {
  label: string;
  href: string;
  external?: boolean;
}

export default function Footer() {
  const t = useTranslations('footer');
  const ready = useContentReady((s) => s.ready);
  const year = new Date().getFullYear();

  const navLinks: FooterLink[] = [
    { label: t('navDashboard'), href: '/dashboard/overview' },
    { label: t('navSearch'), href: '/dashboard/search' },
    { label: t('navRepos'), href: '/dashboard/repositories' },
    { label: t('navReadme'), href: '/dashboard/readme' }
  ];

  const resourceLinks: FooterLink[] = [
    { label: t('resCode'), href: GITHUB_REPO, external: true },
    {
      label: t('resApi'),
      href: `${GITHUB_REPO}/tree/main/local-api`,
      external: true
    },
    { label: t('resContributors'), href: '/dashboard/readme' },
    {
      label: t('resLicense'),
      href: `${GITHUB_REPO}/blob/main/LICENSE`,
      external: true
    }
  ];

  const sourceLinks: FooterLink[] = [
    {
      label: 'CVE List V5',
      href: 'https://github.com/CVEProject/cvelistV5',
      external: true
    },
    {
      label: 'GitHub Advisory',
      href: 'https://github.com/github/advisory-database',
      external: true
    },
    {
      label: 'Nuclei Templates',
      href: 'https://github.com/projectdiscovery/nuclei-templates',
      external: true
    },
    {
      label: 'CISA KEV',
      href: 'https://www.cisa.gov/known-exploited-vulnerabilities-catalog',
      external: true
    },
    {
      label: 'PoC-in-GitHub',
      href: 'https://github.com/nomi-sec/PoC-in-GitHub',
      external: true
    },
    {
      label: 'EPSS Scores',
      href: 'https://github.com/empiricalsec/epss_scores',
      external: true
    },
    { label: t('srcAllSources'), href: '/dashboard/readme' }
  ];

  const columns: { title: string; links: FooterLink[] }[] = [
    { title: t('nav'), links: navLinks },
    { title: t('resources'), links: resourceLinks },
    { title: t('sources'), links: sourceLinks }
  ];

  // Only show once the page content has loaded (avoids floating under a loader).
  if (!ready) return null;

  return (
    <footer className='bg-background mt-auto shrink-0 border-t'>
      <div className='mx-auto w-full max-w-7xl px-4 py-10 md:px-6'>
        <div className='grid grid-cols-1 gap-8 sm:grid-cols-2 lg:grid-cols-5'>
          {/* Brand */}
          <div className='space-y-4 lg:col-span-2'>
            <div className='flex items-center gap-2.5'>
              <div className='flex aspect-square size-8 shrink-0 items-center justify-center overflow-hidden rounded-lg'>
                <Image
                  src={withBasePath('/logo.png')}
                  alt='SunCVE'
                  width={32}
                  height={32}
                  className='size-8 object-contain'
                />
              </div>
              <span className='text-lg font-bold tracking-tight'>SunCVE</span>
            </div>
            <p className='text-muted-foreground max-w-xs text-sm leading-relaxed'>
              {t('tagline')}
            </p>
            <div className='flex items-center gap-2'>
              <a
                href={GITHUB_ORG}
                target='_blank'
                rel='noopener noreferrer'
                aria-label='GitHub'
                className='text-muted-foreground hover:text-foreground hover:border-foreground/30 rounded-md border p-2 transition-colors'
              >
                <IconBrandGithub className='size-4' />
              </a>
              <a
                href={INSTAGRAM}
                target='_blank'
                rel='noopener noreferrer'
                aria-label='Instagram'
                className='text-muted-foreground hover:text-foreground hover:border-foreground/30 rounded-md border p-2 transition-colors'
              >
                <IconBrandInstagram className='size-4' />
              </a>
            </div>
            <span className='text-muted-foreground inline-flex items-center gap-1.5 rounded-full border px-2.5 py-1 text-xs'>
              <span className='size-1.5 rounded-full bg-green-500' />
              {t('openSource')}
            </span>
          </div>

          {/* Link columns */}
          {columns.map((col) => (
            <div key={col.title} className='space-y-3'>
              <h3 className='text-sm font-semibold'>{col.title}</h3>
              <ul className='space-y-2.5'>
                {col.links.map((link) =>
                  link.external ? (
                    <li key={link.label}>
                      <a
                        href={link.href}
                        target='_blank'
                        rel='noopener noreferrer'
                        className='text-muted-foreground hover:text-foreground text-sm transition-colors'
                      >
                        {link.label}
                      </a>
                    </li>
                  ) : (
                    <li key={link.label}>
                      <Link
                        href={link.href}
                        className='text-muted-foreground hover:text-foreground text-sm transition-colors'
                      >
                        {link.label}
                      </Link>
                    </li>
                  )
                )}
              </ul>
            </div>
          ))}
        </div>

        {/* Bottom bar */}
        <div className='mt-10 flex flex-col items-center justify-between gap-2 border-t pt-6 sm:flex-row'>
          <p className='text-muted-foreground text-sm'>© {year} SunCVE</p>
          <p className='text-muted-foreground text-sm'>{t('madeBy')}</p>
        </div>
      </div>
    </footer>
  );
}
