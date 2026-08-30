'use client';

import { useTranslations, useLocale } from 'next-intl';
import {
  IconChevronUp,
  IconChevronDown,
  IconSelector,
  IconSkull,
  IconGitCommit,
  IconBrandGithub,
  IconStar,
  IconTargetArrow,
  IconShieldExclamation
} from '@tabler/icons-react';
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow
} from '@/components/ui/table';
import { Badge } from '@/components/ui/badge';
import { Button } from '@/components/ui/button';
import { Skeleton } from '@/components/ui/skeleton';
import {
  Pagination,
  PaginationContent,
  PaginationEllipsis,
  PaginationItem,
  PaginationLink,
  PaginationNext,
  PaginationPrevious
} from '@/components/ui/pagination';
import type {
  CVESearchResult,
  SearchResultsPage,
  SortConfig,
  SortField,
  Severity
} from '@/features/search/types';
import { EpssSignal } from '@/components/epss-signal';
import { cn } from '@/lib/utils';
import { formatDateLocalized } from '@/lib/format';

interface ResultsTableProps {
  results: SearchResultsPage | null;
  sort: SortConfig;
  isLoading: boolean;
  onSortChange: (sort: SortConfig) => void;
  onPageChange: (page: number) => void;
  onRowClick: (cve: CVESearchResult) => void;
}

export function ResultsTable({
  results,
  sort,
  isLoading,
  onSortChange,
  onPageChange,
  onRowClick
}: ResultsTableProps) {
  const t = useTranslations('search.table');
  const locale = useLocale();

  const handleSort = (field: SortField) => {
    // Special handling for score/epss: 3 states (desc -> asc -> reset).
    // Nos dois casos o interessante é o topo, então começam em desc.
    if (field === 'score' || field === 'epss') {
      if (sort.field === field) {
        if (sort.order === 'desc') {
          // Current: desc, next: asc
          onSortChange({ field, order: 'asc' });
        } else {
          // Current: asc, next: reset to default
          onSortChange({ field: 'date_published', order: 'desc' });
        }
      } else {
        // Not sorting by this field yet, start with desc
        onSortChange({ field, order: 'desc' });
      }
    } else {
      // Other fields: 2 states (toggle between asc/desc)
      if (sort.field === field) {
        onSortChange({ field, order: sort.order === 'asc' ? 'desc' : 'asc' });
      } else {
        onSortChange({ field, order: 'desc' });
      }
    }
  };

  const SortIcon = ({ field }: { field: SortField }) => {
    if (sort.field !== field) {
      return <IconSelector className='ml-1 h-4 w-4 opacity-50' />;
    }
    return sort.order === 'asc' ? (
      <IconChevronUp className='ml-1 h-4 w-4' />
    ) : (
      <IconChevronDown className='ml-1 h-4 w-4' />
    );
  };

  if (isLoading && !results) {
    return <TableSkeleton />;
  }

  if (!results || results.results.length === 0) {
    return (
      <div className='bg-card flex flex-col items-center justify-center rounded-xl border-2 p-16 text-center shadow-sm'>
        <div className='bg-muted mb-4 rounded-full p-4'>
          <IconSelector className='text-muted-foreground h-8 w-8' />
        </div>
        <p className='text-foreground text-xl font-semibold'>
          {t('noResults')}
        </p>
        <p className='text-muted-foreground mt-2 text-sm'>
          {t('tryDifferentFilters')}
        </p>
      </div>
    );
  }

  return (
    <div className='space-y-4' data-tour='cve-results'>
      <div className='bg-muted/30 flex items-center justify-between rounded-xl px-4 py-3'>
        <p className='text-muted-foreground text-sm font-medium'>
          {t('showing', {
            from: ((results.page - 1) * results.pageSize + 1).toLocaleString(),
            to: Math.min(
              results.page * results.pageSize,
              results.total
            ).toLocaleString(),
            total: results.total.toLocaleString()
          })}
        </p>
      </div>

      <div className='w-full'>
        <div className='bg-card rounded-xl border-2 shadow-sm'>
          <div
            className='overflow-x-auto'
            style={{
              WebkitOverflowScrolling: 'touch',
              overscrollBehaviorX: 'contain'
            }}
          >
            <Table className='w-full table-fixed'>
              <TableHeader>
                <TableRow>
                  <TableHead className='w-[140px]'>
                    <Button
                      variant='ghost'
                      className='h-8 p-0 font-semibold hover:bg-transparent'
                      onClick={() => handleSort('cve_id')}
                    >
                      {t('cveId')}
                      <SortIcon field='cve_id' />
                    </Button>
                  </TableHead>
                  <TableHead className='min-w-[80px]'>{t('title')}</TableHead>
                  <TableHead className='w-[100px]'>
                    <Button
                      variant='ghost'
                      className='h-8 p-0 font-semibold hover:bg-transparent'
                      onClick={() => handleSort('score')}
                    >
                      {t('score')}
                      <SortIcon field='score' />
                    </Button>
                  </TableHead>
                  <TableHead className='w-[95px]'>
                    <Button
                      variant='ghost'
                      className='h-8 p-0 font-semibold hover:bg-transparent'
                      onClick={() => handleSort('epss')}
                    >
                      {t('epss')}
                      <SortIcon field='epss' />
                    </Button>
                  </TableHead>
                  <TableHead className='w-[100px]'>{t('flags')}</TableHead>
                  <TableHead className='w-[120px]'>{t('affected')}</TableHead>
                  <TableHead className='w-[150px]'>{t('repository')}</TableHead>
                  <TableHead className='w-[120px]'>
                    <Button
                      variant='ghost'
                      className='h-8 p-0 font-semibold hover:bg-transparent'
                      onClick={() => handleSort('date_published')}
                    >
                      {t('published')}
                      <SortIcon field='date_published' />
                    </Button>
                  </TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {results.results.map((cve, index) => (
                  <TableRow
                    key={cve.cve_id}
                    className='hover:bg-muted/50 cursor-pointer'
                    onClick={() => onRowClick(cve)}
                    data-tour={index === 0 ? 'cve-first-row' : undefined}
                  >
                    <TableCell className='font-mono text-sm font-medium'>
                      {cve.cve_id}
                    </TableCell>
                    <TableCell className='overflow-hidden'>
                      <div
                        className='truncate text-sm'
                        title={
                          cve.title || cve.description?.substring(0, 200) || ''
                        }
                      >
                        {cve.title || cve.description?.substring(0, 100) || '—'}
                      </div>
                    </TableCell>
                    <TableCell>
                      {cve.max_score !== null ? (
                        <SeverityBadge
                          score={cve.max_score}
                          severity={cve.severity}
                        />
                      ) : (
                        <span className='text-muted-foreground'>—</span>
                      )}
                    </TableCell>
                    <TableCell>
                      <EpssSignal
                        epss={cve.epss}
                        percentile={cve.epss_percentile}
                        locale={locale}
                        label={t('epss')}
                        showValue
                      />
                    </TableCell>
                    <TableCell>
                      <div className='flex flex-nowrap gap-1'>
                        {cve.exists_exploit && (
                          <Badge variant='destructive' className='px-1.5'>
                            <IconSkull className='h-3 w-3' />
                          </Badge>
                        )}
                        {cve.exists_commit && (
                          <Badge
                            variant='secondary'
                            className='bg-green-500/20 px-1.5 text-green-700 dark:text-green-400'
                          >
                            <IconGitCommit className='h-3 w-3' />
                          </Badge>
                        )}
                        {cve.exists_nuclei && (
                          <Badge
                            variant='secondary'
                            className='bg-cyan-500/20 px-1.5 text-cyan-700 dark:text-cyan-400'
                          >
                            <IconTargetArrow className='h-3 w-3' />
                          </Badge>
                        )}
                        {cve.in_kev && (
                          <Badge
                            variant='secondary'
                            className='bg-amber-500/20 px-1.5 text-amber-700 dark:text-amber-400'
                          >
                            <IconShieldExclamation className='h-3 w-3' />
                          </Badge>
                        )}
                        {cve.missing_nuclei_template && (
                          <Badge
                            variant='outline'
                            className='border-dashed border-purple-500/50 px-1.5 text-purple-600 dark:text-purple-400'
                          >
                            <IconTargetArrow className='h-3 w-3 opacity-50' />
                          </Badge>
                        )}
                      </div>
                    </TableCell>
                    <TableCell className='overflow-hidden'>
                      <div className='truncate text-sm'>
                        {cve.vendor_list ? (
                          <span>{cve.vendor_list}</span>
                        ) : (
                          <span className='text-muted-foreground'>—</span>
                        )}
                      </div>
                    </TableCell>
                    <TableCell className='overflow-hidden'>
                      {cve.repo_fullpath ? (
                        <div className='flex items-center gap-2 overflow-hidden'>
                          <IconBrandGithub className='text-muted-foreground h-4 w-4 shrink-0' />
                          <span className='truncate text-sm'>
                            {cve.repo_fullpath.split('/').pop()}
                          </span>
                          {cve.repo_stars !== null && (
                            <div className='text-muted-foreground flex shrink-0 items-center gap-0.5 text-xs'>
                              <IconStar className='h-3 w-3' />
                              {formatStars(cve.repo_stars)}
                            </div>
                          )}
                        </div>
                      ) : (
                        <span className='text-muted-foreground'>—</span>
                      )}
                    </TableCell>
                    <TableCell className='text-muted-foreground text-sm'>
                      {formatDateLocalized(cve.date_published, locale)}
                    </TableCell>
                  </TableRow>
                ))}
              </TableBody>
            </Table>
          </div>
        </div>
      </div>

      {results.totalPages > 1 && (
        <Pagination>
          <PaginationContent>
            <PaginationItem>
              <PaginationPrevious
                href='#'
                onClick={(e) => {
                  e.preventDefault();
                  if (results.page > 1) onPageChange(results.page - 1);
                }}
                className={cn(
                  results.page === 1 && 'pointer-events-none opacity-50'
                )}
              />
            </PaginationItem>

            {generatePaginationItems(results.page, results.totalPages).map(
              (item, i) => (
                <PaginationItem key={i}>
                  {item === 'ellipsis' ? (
                    <PaginationEllipsis />
                  ) : (
                    <PaginationLink
                      href='#'
                      isActive={item === results.page}
                      onClick={(e) => {
                        e.preventDefault();
                        onPageChange(item);
                      }}
                    >
                      {item}
                    </PaginationLink>
                  )}
                </PaginationItem>
              )
            )}

            <PaginationItem>
              <PaginationNext
                href='#'
                onClick={(e) => {
                  e.preventDefault();
                  if (results.page < results.totalPages)
                    onPageChange(results.page + 1);
                }}
                className={cn(
                  results.page === results.totalPages &&
                    'pointer-events-none opacity-50'
                )}
              />
            </PaginationItem>
          </PaginationContent>
        </Pagination>
      )}
    </div>
  );
}

function SeverityBadge({
  score,
  severity
}: {
  score: number;
  severity: Severity;
}) {
  const colors: Record<Severity, string> = {
    critical: 'bg-red-500 text-white',
    high: 'bg-orange-500 text-white',
    medium: 'bg-yellow-500 text-black',
    low: 'bg-blue-500 text-white',
    none: 'bg-gray-500 text-white'
  };

  return (
    <Badge className={cn('font-mono', colors[severity])}>
      {score.toFixed(1)}
    </Badge>
  );
}

function TableSkeleton() {
  return (
    <div className='space-y-4'>
      <div className='bg-muted/30 flex items-center justify-between rounded-xl px-4 py-3'>
        <Skeleton className='h-4 w-48' />
      </div>
      <div className='w-full'>
        <div className='bg-card rounded-xl border-2 shadow-sm'>
          <div
            className='overflow-x-auto'
            style={{
              WebkitOverflowScrolling: 'touch',
              overscrollBehaviorX: 'contain'
            }}
          >
            <Table className='w-full table-fixed'>
              <TableHeader>
                <TableRow>
                  <TableHead className='w-[140px]'>CVE ID</TableHead>
                  <TableHead className='w-[80px]'>Title</TableHead>
                  <TableHead className='w-[80px]'>Score</TableHead>
                  <TableHead className='w-[95px]'>EPSS</TableHead>
                  <TableHead className='w-[100px]'>Flags</TableHead>
                  <TableHead className='w-[120px]'>Affected</TableHead>
                  <TableHead className='w-[150px]'>Repository</TableHead>
                  <TableHead className='w-[100px]'>Published</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {Array.from({ length: 10 }).map((_, i) => (
                  <TableRow key={i}>
                    <TableCell>
                      <Skeleton className='h-5 w-28 rounded' />
                    </TableCell>
                    <TableCell>
                      <Skeleton className='h-5 w-full rounded' />
                    </TableCell>
                    <TableCell>
                      <Skeleton className='h-7 w-14 rounded-full' />
                    </TableCell>
                    <TableCell>
                      <Skeleton className='h-5 w-16 rounded' />
                    </TableCell>
                    <TableCell>
                      <Skeleton className='h-7 w-16 rounded' />
                    </TableCell>
                    <TableCell>
                      <Skeleton className='h-5 w-24 rounded' />
                    </TableCell>
                    <TableCell>
                      <Skeleton className='h-5 w-32 rounded' />
                    </TableCell>
                    <TableCell>
                      <Skeleton className='h-5 w-20 rounded' />
                    </TableCell>
                  </TableRow>
                ))}
              </TableBody>
            </Table>
          </div>
        </div>
      </div>
    </div>
  );
}

function formatStars(stars: number): string {
  if (stars >= 1000) {
    return `${(stars / 1000).toFixed(1)}k`;
  }
  return stars.toString();
}

function generatePaginationItems(
  currentPage: number,
  totalPages: number
): (number | 'ellipsis')[] {
  const items: (number | 'ellipsis')[] = [];
  const maxVisible = 7;

  if (totalPages <= maxVisible) {
    return Array.from({ length: totalPages }, (_, i) => i + 1);
  }

  items.push(1);

  if (currentPage > 3) {
    items.push('ellipsis');
  }

  const start = Math.max(2, currentPage - 1);
  const end = Math.min(totalPages - 1, currentPage + 1);

  for (let i = start; i <= end; i++) {
    items.push(i);
  }

  if (currentPage < totalPages - 2) {
    items.push('ellipsis');
  }

  items.push(totalPages);

  return items;
}
