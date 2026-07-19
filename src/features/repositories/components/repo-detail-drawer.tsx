'use client';

import { useState, useCallback, useEffect } from 'react';
import { useTranslations, useLocale } from 'next-intl';
import {
  IconExternalLink,
  IconPackage,
  IconStar,
  IconCode,
  IconCalendar,
  IconTag,
  IconCopy,
  IconCheck,
  IconBug,
  IconGitCommit,
  IconSkull,
  IconFolder,
  IconUsers,
  IconDownload,
  IconChevronLeft,
  IconChevronRight,
  IconSearch
} from '@tabler/icons-react';
import Link from 'next/link';
import { Badge } from '@/components/ui/badge';
import { Button } from '@/components/ui/button';
import { ScrollArea } from '@/components/ui/scroll-area';
import { Separator } from '@/components/ui/separator';
import {
  Sheet,
  SheetContent,
  SheetHeader,
  SheetTitle
} from '@/components/ui/sheet';
import {
  Accordion,
  AccordionContent,
  AccordionItem,
  AccordionTrigger
} from '@/components/ui/accordion';
import {
  Card,
  CardContent,
  CardDescription,
  CardHeader,
  CardTitle
} from '@/components/ui/card';
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow
} from '@/components/ui/table';
import {
  getSeverityFromScore,
  getSeverityColor,
  type CVESearchResult
} from '@/features/search/types';
import { CVEDetailDrawer } from '@/features/search/components/cve-detail-drawer';
import { useCVESearch } from '@/lib/sqlite/use-cve-search';
import { useRepositorySearch } from '@/lib/sqlite/use-repository-search';
import { getEcosystemMeta } from '@/lib/ecosystem';
import { cn } from '@/lib/utils';
import { formatDateLocalized } from '@/lib/format';
import {
  useStudyStore,
  useStudyHydrated
} from '@/features/study/store/use-study-store';
import { buildRepoSnapshot } from '@/features/study/lib/snapshot';

const CVE_PAGE_SIZE = 20;

interface RepoDetailDrawerProps {
  repository: Record<string, unknown> | null;
  isOpen: boolean;
  onClose: () => void;
}

export function RepoDetailDrawer({
  repository,
  isOpen,
  onClose
}: RepoDetailDrawerProps) {
  const t = useTranslations('repositories.detail');
  const tStudy = useTranslations('studies.actions');
  const locale = useLocale();
  const [copied, setCopied] = useState(false);
  const [selectedCveId, setSelectedCveId] = useState<string | null>(null);
  const [selectedCve, setSelectedCve] = useState<Record<
    string,
    unknown
  > | null>(null);
  const { getCVEDetails, isReady: cveSearchReady } = useCVESearch();
  const { getRepositoryCVEs, isReady: repoSearchReady } = useRepositorySearch();

  // CVE pagination state
  const [cvePage, setCvePage] = useState(1);
  const [cves, setCves] = useState<CVESearchResult[]>([]);
  const [cveTotalPages, setCveTotalPages] = useState(0);
  const [cveTotal, setCveTotal] = useState(0);

  // Extract repository fields (outside of conditional to avoid hooks order issues)
  const fullpath = repository?.fullpath as string | undefined;
  const cveCount = (repository?.cve_count as number) ?? 0;

  // Favoritar repositório (estado local no navegador via store de estudos).
  const studyHydrated = useStudyHydrated();
  const isRepoFav = useStudyStore((s) =>
    fullpath ? s.favoriteRepos.includes(fullpath) : false
  );
  const toggleFavoriteRepo = useStudyStore((s) => s.toggleFavoriteRepo);

  // Load CVEs when drawer opens or page changes
  useEffect(() => {
    if (!isOpen || !repoSearchReady || !fullpath) {
      return;
    }

    const result = getRepositoryCVEs(fullpath, cvePage, CVE_PAGE_SIZE);
    setCves(result.cves);
    setCveTotalPages(result.totalPages);
    setCveTotal(result.total);
  }, [isOpen, repoSearchReady, fullpath, cvePage, getRepositoryCVEs]);

  // Reset page when drawer opens with a different repository
  useEffect(() => {
    if (isOpen) {
      setCvePage(1);
    }
  }, [isOpen, fullpath]);

  const handleCveClick = useCallback(
    (cveId: string) => {
      if (!cveSearchReady) return;
      const cveDetails = getCVEDetails(cveId);
      if (cveDetails) {
        setSelectedCve(cveDetails);
        setSelectedCveId(cveId);
      }
    },
    [cveSearchReady, getCVEDetails]
  );

  const handleCloseCveDrawer = useCallback(() => {
    setSelectedCveId(null);
    setSelectedCve(null);
  }, []);

  if (!repository) return null;

  // Extract and type repository fields (now guaranteed to exist)
  const repoFullpath = repository.fullpath as string;
  const name = repository.name as string | null;
  const stars = (repository.stars as number) ?? 0;
  const size = repository.size as number | null;
  const languageMain = repository.languageMain as string | null;
  const commitsFixCount = (repository.commits_fix_count as number) ?? 0;
  const createdRepository = repository.created_repository as string | null;
  const updatedRepository = repository.updated_repository as string | null;
  const ecosystem = (repository.ecosystem as string | null) ?? 'github';
  const isWordpress = ecosystem === 'wordpress';
  const isPackage = ecosystem === 'npm' || ecosystem === 'packagist';
  const activeInstalls = repository.active_installs as number | null;
  const downloads = repository.downloads as number | null;
  const packageUrl = repository.package_url as string | null;
  const externalUrl = isWordpress
    ? `https://${repoFullpath}` // wordpress.org/plugins/<slug>
    : `https://github.com/${repoFullpath}`;

  const repoFavActive = studyHydrated && isRepoFav;
  const repoSnapshot = buildRepoSnapshot(repository);

  const displayName = name || repoFullpath.split('/').pop() || '';
  const truncatedName =
    displayName.length > 100 ? `${displayName.slice(0, 100)}…` : displayName;

  const languages = parseJSON<Record<string, number>>(
    repository.languages as string
  );
  const tags = parseJSON<string[]>(repository.tags as string) ?? [];

  const handleCopy = async () => {
    await navigator.clipboard.writeText(repoFullpath);
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  };

  const formatCount = (value: number | null): string => {
    if (value == null) return '—';
    if (value >= 1000000) return `${(value / 1000000).toFixed(1)}M`;
    if (value >= 1000) return `${(value / 1000).toFixed(1)}k`;
    return value.toLocaleString();
  };

  const formatSize = (sizeKB: number | null): string => {
    if (!sizeKB) return '—';
    if (sizeKB >= 1024 * 1024) {
      return `${(sizeKB / (1024 * 1024)).toFixed(1)} GB`;
    }
    if (sizeKB >= 1024) {
      return `${(sizeKB / 1024).toFixed(1)} MB`;
    }
    return `${sizeKB} KB`;
  };

  return (
    <Sheet open={isOpen} onOpenChange={(open) => !open && onClose()}>
      <SheetContent className='w-full overflow-hidden p-0 sm:max-w-[90vw] md:max-w-3xl lg:max-w-4xl'>
        <ScrollArea className='h-full'>
          <div className='space-y-6 p-6'>
            {/* Header */}
            <SheetHeader className='space-y-4'>
              <div className='flex items-start justify-between gap-4'>
                <div className='min-w-0 flex-1'>
                  <SheetTitle className='flex min-w-0 items-center gap-2 text-xl'>
                    {(() => {
                      const meta = getEcosystemMeta(ecosystem);
                      return (
                        <meta.Icon
                          className={cn('h-6 w-6 shrink-0', meta.textClass)}
                        />
                      );
                    })()}
                    <span className='min-w-0 truncate' title={displayName}>
                      {truncatedName}
                    </span>
                    {ecosystem !== 'github' && (
                      <Badge
                        variant='outline'
                        className={cn(
                          'shrink-0',
                          getEcosystemMeta(ecosystem).borderClass
                        )}
                      >
                        {getEcosystemMeta(ecosystem).label}
                      </Badge>
                    )}
                  </SheetTitle>
                  <div className='mt-2 flex items-center gap-2'>
                    <code className='bg-muted text-muted-foreground truncate rounded px-2 py-1 text-sm'>
                      {repoFullpath}
                    </code>
                    <Button
                      variant='ghost'
                      size='icon'
                      className='h-8 w-8 shrink-0'
                      onClick={handleCopy}
                    >
                      {copied ? (
                        <IconCheck className='h-4 w-4 text-green-500' />
                      ) : (
                        <IconCopy className='h-4 w-4' />
                      )}
                    </Button>
                  </div>
                </div>
                <div className='flex shrink-0 items-center gap-2'>
                  <Button
                    variant={repoFavActive ? 'secondary' : 'outline'}
                    size='sm'
                    className='gap-1.5'
                    onClick={() => toggleFavoriteRepo(repoSnapshot)}
                  >
                    <IconStar
                      className={cn(
                        'h-4 w-4',
                        repoFavActive && 'fill-amber-400 text-amber-500'
                      )}
                    />
                    {repoFavActive ? tStudy('favorited') : tStudy('favorite')}
                  </Button>
                  <Button variant='outline' size='sm' asChild>
                    <a
                      href={externalUrl}
                      target='_blank'
                      rel='noopener noreferrer'
                    >
                      <IconExternalLink className='mr-1 h-4 w-4' />
                      {isWordpress ? 'WordPress.org' : 'GitHub'}
                    </a>
                  </Button>
                </div>
              </div>
            </SheetHeader>

            {/* Quick Stats */}
            <div className='grid grid-cols-2 gap-3 sm:grid-cols-4'>
              {isWordpress ? (
                <Card>
                  <CardContent className='flex items-center gap-2 p-3'>
                    <IconUsers className='h-4 w-4 shrink-0 text-[#21759b]' />
                    <div className='min-w-0'>
                      <p className='truncate text-lg font-bold sm:text-2xl'>
                        {formatCount(activeInstalls)}
                      </p>
                      <p className='text-muted-foreground text-xs'>
                        {t('activeInstalls')}
                      </p>
                    </div>
                  </CardContent>
                </Card>
              ) : (
                <Card>
                  <CardContent className='flex items-center gap-2 p-3'>
                    <IconStar className='h-4 w-4 shrink-0 text-yellow-500' />
                    <div className='min-w-0'>
                      <p className='truncate text-lg font-bold sm:text-2xl'>
                        {stars.toLocaleString()}
                      </p>
                      <p className='text-muted-foreground text-xs'>
                        {t('stars')}
                      </p>
                    </div>
                  </CardContent>
                </Card>
              )}
              <Card>
                <CardContent className='flex items-center gap-2 p-3'>
                  <IconBug className='h-4 w-4 shrink-0 text-red-500' />
                  <div className='min-w-0'>
                    <p className='truncate text-lg font-bold sm:text-2xl'>
                      {cveCount}
                    </p>
                    <p className='text-muted-foreground text-xs'>{t('cves')}</p>
                  </div>
                </CardContent>
              </Card>
              <Card>
                <CardContent className='flex items-center gap-2 p-3'>
                  <IconGitCommit className='h-4 w-4 shrink-0 text-green-500' />
                  <div className='min-w-0'>
                    <p className='truncate text-lg font-bold sm:text-2xl'>
                      {commitsFixCount}
                    </p>
                    <p className='text-muted-foreground text-xs'>
                      {t('fixes')}
                    </p>
                  </div>
                </CardContent>
              </Card>
              {isWordpress || isPackage ? (
                <Card>
                  <CardContent className='flex items-center gap-2 p-3'>
                    <IconDownload className='h-4 w-4 shrink-0 text-blue-500' />
                    <div className='min-w-0'>
                      <p className='truncate text-lg font-bold sm:text-2xl'>
                        {formatCount(downloads)}
                      </p>
                      <p className='text-muted-foreground text-xs'>
                        {t('downloads')}
                      </p>
                    </div>
                  </CardContent>
                </Card>
              ) : (
                <Card>
                  <CardContent className='flex items-center gap-2 p-3'>
                    <IconFolder className='h-4 w-4 shrink-0 text-blue-500' />
                    <div className='min-w-0'>
                      <p className='truncate text-lg font-bold sm:text-2xl'>
                        {formatSize(size)}
                      </p>
                      <p className='text-muted-foreground text-xs'>
                        {t('size')}
                      </p>
                    </div>
                  </CardContent>
                </Card>
              )}
            </div>

            <Separator />

            {/* Accordion Sections */}
            <Accordion
              type='multiple'
              defaultValue={['info', 'cves']}
              className='w-full'
            >
              {/* Repository Info */}
              <AccordionItem value='info'>
                <AccordionTrigger className='text-base font-semibold'>
                  <div className='flex items-center gap-2'>
                    <IconCode className='h-5 w-5' />
                    {t('repoInfo')}
                  </div>
                </AccordionTrigger>
                <AccordionContent>
                  <div className='space-y-4'>
                    {/* Package registry URL (npm / Packagist) */}
                    {packageUrl && (
                      <div>
                        <p className='text-muted-foreground mb-2 text-sm'>
                          {t('package')}
                        </p>
                        <a
                          href={packageUrl}
                          target='_blank'
                          rel='noopener noreferrer'
                          className='text-primary inline-flex items-center gap-1 text-sm hover:underline'
                        >
                          <IconPackage className='h-4 w-4 shrink-0' />
                          <span className='truncate'>{packageUrl}</span>
                          <IconExternalLink className='h-3 w-3 shrink-0' />
                        </a>
                      </div>
                    )}

                    {/* Main Language */}
                    {languageMain && (
                      <div>
                        <p className='text-muted-foreground mb-2 text-sm'>
                          {t('mainLanguage')}
                        </p>
                        <Badge variant='secondary' className='gap-1'>
                          <IconCode className='h-3 w-3' />
                          {languageMain}
                        </Badge>
                      </div>
                    )}

                    {/* Languages */}
                    {languages && Object.keys(languages).length > 0 && (
                      <div>
                        <p className='text-muted-foreground mb-2 text-sm'>
                          {t('languages')}
                        </p>
                        <div className='flex flex-wrap gap-2'>
                          {Object.entries(languages)
                            .sort(([, a], [, b]) => b - a)
                            .slice(0, 10)
                            .map(([lang, percent]) => (
                              <Badge key={lang} variant='outline'>
                                {lang}:{' '}
                                {typeof percent === 'number'
                                  ? `${percent.toFixed(1)}%`
                                  : percent}
                              </Badge>
                            ))}
                        </div>
                      </div>
                    )}

                    {/* Tags */}
                    {tags.length > 0 && (
                      <div>
                        <p className='text-muted-foreground mb-2 text-sm'>
                          {t('tags')}
                        </p>
                        <div className='flex flex-wrap gap-2'>
                          {tags.slice(0, 20).map((tag) => (
                            <Badge key={tag} variant='secondary'>
                              <IconTag className='mr-1 h-3 w-3' />
                              {tag}
                            </Badge>
                          ))}
                        </div>
                      </div>
                    )}

                    {/* Dates */}
                    <div className='grid gap-4 sm:grid-cols-2'>
                      {createdRepository && (
                        <div>
                          <p className='text-muted-foreground mb-1 text-sm'>
                            {t('created')}
                          </p>
                          <div className='flex items-center gap-2'>
                            <IconCalendar className='text-muted-foreground h-4 w-4' />
                            <span>
                              {formatDateLocalized(createdRepository, locale)}
                            </span>
                          </div>
                        </div>
                      )}
                      {updatedRepository && (
                        <div>
                          <p className='text-muted-foreground mb-1 text-sm'>
                            {t('updated')}
                          </p>
                          <div className='flex items-center gap-2'>
                            <IconCalendar className='text-muted-foreground h-4 w-4' />
                            <span>
                              {formatDateLocalized(updatedRepository, locale)}
                            </span>
                          </div>
                        </div>
                      )}
                    </div>
                  </div>
                </AccordionContent>
              </AccordionItem>

              {/* CVEs */}
              {cveCount > 0 && (
                <AccordionItem value='cves'>
                  <AccordionTrigger className='text-base font-semibold'>
                    <div className='flex items-center gap-2'>
                      <IconBug className='h-5 w-5 text-red-500' />
                      {t('relatedCVEs')}
                      <Badge variant='destructive' className='ml-2'>
                        {cveTotal || cveCount}
                      </Badge>
                    </div>
                  </AccordionTrigger>
                  <Link
                    href={`/dashboard/search?repo_filter=${encodeURIComponent(repoFullpath)}`}
                    className='text-muted-foreground hover:text-primary mb-2 inline-flex items-center gap-1 text-sm transition-colors'
                  >
                    <IconSearch className='h-4 w-4' />
                    {t('advancedFilters')}
                    <IconExternalLink className='h-3 w-3' />
                  </Link>
                  <AccordionContent>
                    <div className='space-y-4'>
                      <div className='overflow-x-auto rounded-lg border'>
                        <Table className='min-w-[500px]'>
                          <TableHeader>
                            <TableRow>
                              <TableHead className='min-w-[200px]'>
                                {t('cveId')}
                              </TableHead>
                              <TableHead className='w-[80px]'>
                                {t('score')}
                              </TableHead>
                              <TableHead className='w-[80px]'>
                                {t('flags')}
                              </TableHead>
                              <TableHead className='w-[100px]'>
                                {t('published')}
                              </TableHead>
                            </TableRow>
                          </TableHeader>
                          <TableBody>
                            {cves.map((cve) => {
                              const severity = getSeverityFromScore(
                                cve.max_score ?? 0
                              );
                              return (
                                <TableRow
                                  key={cve.cve_id}
                                  className='hover:bg-muted/50 cursor-pointer transition-colors'
                                  onClick={() => handleCveClick(cve.cve_id)}
                                >
                                  <TableCell className='max-w-0 overflow-hidden'>
                                    <span className='text-primary font-mono text-sm font-medium hover:underline'>
                                      {cve.cve_id}
                                    </span>
                                    {cve.title && (
                                      <p
                                        className='text-muted-foreground mt-1 truncate text-xs'
                                        title={cve.title}
                                      >
                                        {cve.title.substring(0, 100)}
                                      </p>
                                    )}
                                  </TableCell>
                                  <TableCell>
                                    {cve.max_score !== null ? (
                                      <Badge
                                        className={cn(
                                          'font-mono',
                                          getSeverityColor(severity)
                                        )}
                                      >
                                        {cve.max_score.toFixed(1)}
                                      </Badge>
                                    ) : (
                                      <span className='text-muted-foreground'>
                                        —
                                      </span>
                                    )}
                                  </TableCell>
                                  <TableCell>
                                    <div className='flex gap-1'>
                                      {cve.exists_exploit && (
                                        <Badge
                                          variant='destructive'
                                          className='gap-1'
                                        >
                                          <IconSkull className='h-3 w-3' />
                                        </Badge>
                                      )}
                                      {cve.exists_commit && (
                                        <Badge
                                          variant='secondary'
                                          className='gap-1 bg-green-500/20 text-green-700 dark:text-green-400'
                                        >
                                          <IconGitCommit className='h-3 w-3' />
                                        </Badge>
                                      )}
                                    </div>
                                  </TableCell>
                                  <TableCell className='text-muted-foreground text-sm'>
                                    {formatDateLocalized(
                                      cve.date_published,
                                      locale
                                    )}
                                  </TableCell>
                                </TableRow>
                              );
                            })}
                          </TableBody>
                        </Table>
                      </div>

                      {/* Pagination Controls */}
                      {cveTotalPages > 1 && (
                        <div className='flex items-center justify-between'>
                          <p className='text-muted-foreground text-sm'>
                            {t('page')} {cvePage} {t('of')} {cveTotalPages} (
                            {cveTotal} CVEs)
                          </p>
                          <div className='flex items-center gap-2'>
                            <Button
                              variant='outline'
                              size='sm'
                              onClick={() =>
                                setCvePage((p) => Math.max(1, p - 1))
                              }
                              disabled={cvePage <= 1}
                            >
                              <IconChevronLeft className='h-4 w-4' />
                              {t('previous')}
                            </Button>
                            <Button
                              variant='outline'
                              size='sm'
                              onClick={() =>
                                setCvePage((p) =>
                                  Math.min(cveTotalPages, p + 1)
                                )
                              }
                              disabled={cvePage >= cveTotalPages}
                            >
                              {t('next')}
                              <IconChevronRight className='h-4 w-4' />
                            </Button>
                          </div>
                        </div>
                      )}
                    </div>
                  </AccordionContent>
                </AccordionItem>
              )}
            </Accordion>
          </div>
        </ScrollArea>
      </SheetContent>

      {/* CVE Detail Drawer */}
      <CVEDetailDrawer
        cve={selectedCve}
        isOpen={selectedCveId !== null}
        onClose={handleCloseCveDrawer}
      />
    </Sheet>
  );
}

// Helper function
function parseJSON<T>(json: string | null | undefined): T | null {
  if (!json) return null;
  try {
    return JSON.parse(json) as T;
  } catch {
    return null;
  }
}
