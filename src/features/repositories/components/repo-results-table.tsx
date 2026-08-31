'use client';

import { useTranslations, useLocale } from 'next-intl';
import {
  IconChevronUp,
  IconChevronDown,
  IconSelector,
  IconBrandGithub,
  IconBrandWordpress,
  IconStar,
  IconBug,
  IconGitCommit,
  IconCode,
  IconDownload
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
  RepositorySearchResult,
  RepositorySearchResultsPage,
  RepositorySortConfig,
  RepositorySortField
} from '@/features/search/types';
import { getEcosystemMeta } from '@/lib/ecosystem';
import { cn } from '@/lib/utils';
import { formatDateLocalized } from '@/lib/format';

interface RepoResultsTableProps {
  results: RepositorySearchResultsPage | null;
  sort: RepositorySortConfig;
  isLoading: boolean;
  onSortChange: (sort: RepositorySortConfig) => void;
  onPageChange: (page: number) => void;
  onRowClick: (repo: RepositorySearchResult) => void;
}

export function RepoResultsTable({
  results,
  sort,
  isLoading,
  onSortChange,
  onPageChange,
  onRowClick
}: RepoResultsTableProps) {
  const t = useTranslations('repositories.table');
  const locale = useLocale();

  const handleSort = (field: RepositorySortField) => {
    if (sort.field === field) {
      onSortChange({ field, order: sort.order === 'asc' ? 'desc' : 'asc' });
    } else {
      onSortChange({ field, order: 'desc' });
    }
  };

  const SortIcon = ({ field }: { field: RepositorySortField }) => {
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
          <IconBrandGithub className='text-muted-foreground h-8 w-8' />
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
    <div className='space-y-4'>
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
            <Table className='min-w-[1000px]'>
              <TableHeader>
                <TableRow>
                  <TableHead className='min-w-[250px]'>
                    <Button
                      variant='ghost'
                      className='h-8 p-0 font-semibold hover:bg-transparent'
                      onClick={() => handleSort('fullpath')}
                    >
                      {t('repository')}
                      <SortIcon field='fullpath' />
                    </Button>
                  </TableHead>
                  <TableHead className='w-[120px]'>{t('ecosystem')}</TableHead>
                  <TableHead className='w-[110px]'>
                    <Button
                      variant='ghost'
                      className='h-8 p-0 font-semibold hover:bg-transparent'
                      onClick={() => handleSort('stars')}
                    >
                      {t('stars')}
                      <SortIcon field='stars' />
                    </Button>
                  </TableHead>
                  <TableHead className='w-[120px]'>
                    <Button
                      variant='ghost'
                      className='h-8 p-0 font-semibold hover:bg-transparent'
                      onClick={() => handleSort('downloads')}
                    >
                      {t('downloads')}
                      <SortIcon field='downloads' />
                    </Button>
                  </TableHead>
                  <TableHead className='w-[120px]'>{t('language')}</TableHead>
                  <TableHead className='w-[100px]'>
                    <Button
                      variant='ghost'
                      className='h-8 p-0 font-semibold hover:bg-transparent'
                      onClick={() => handleSort('cve_count')}
                    >
                      {t('cves')}
                      <SortIcon field='cve_count' />
                    </Button>
                  </TableHead>
                  <TableHead className='w-[100px]'>
                    <Button
                      variant='ghost'
                      className='h-8 p-0 font-semibold hover:bg-transparent'
                      onClick={() => handleSort('commits_fix_count')}
                    >
                      {t('fixes')}
                      <SortIcon field='commits_fix_count' />
                    </Button>
                  </TableHead>
                  <TableHead className='w-[100px]'>{t('size')}</TableHead>
                  <TableHead className='w-[120px]'>
                    <Button
                      variant='ghost'
                      className='h-8 p-0 font-semibold hover:bg-transparent'
                      onClick={() => handleSort('updated_repository')}
                    >
                      {t('updated')}
                      <SortIcon field='updated_repository' />
                    </Button>
                  </TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {results.results.map((repo, index) => (
                  <TableRow
                    key={repo.fullpath}
                    className='hover:bg-muted/50 cursor-pointer'
                    onClick={() => onRowClick(repo)}
                  >
                    <TableCell>
                      <div className='flex items-center gap-2'>
                        {repo.ecosystem === 'wordpress' ? (
                          <IconBrandWordpress className='h-5 w-5 shrink-0 text-[#21759b]' />
                        ) : (
                          <IconBrandGithub className='text-muted-foreground h-5 w-5 shrink-0' />
                        )}
                        <div className='min-w-0'>
                          <span
                            className='block truncate font-medium'
                            title={repo.name ?? repo.fullpath}
                          >
                            {repo.name || repo.fullpath.split('/').pop()}
                          </span>
                          <div className='text-muted-foreground truncate text-xs'>
                            {repo.fullpath}
                          </div>
                        </div>
                      </div>
                    </TableCell>
                    <TableCell>
                      {(() => {
                        const meta = getEcosystemMeta(repo.ecosystem);
                        return (
                          <Badge
                            variant='outline'
                            className={cn('gap-1', meta.borderClass)}
                          >
                            <meta.Icon
                              className={cn('h-3 w-3', meta.textClass)}
                            />
                            {meta.label}
                          </Badge>
                        );
                      })()}
                    </TableCell>
                    <TableCell>
                      {repo.stars != null ? (
                        <div className='flex items-center gap-1'>
                          <IconStar className='h-4 w-4 text-yellow-500' />
                          <span className='font-medium'>
                            {formatStars(repo.stars)}
                          </span>
                        </div>
                      ) : (
                        <span className='text-muted-foreground'>—</span>
                      )}
                    </TableCell>
                    <TableCell>
                      {repo.downloads != null ? (
                        <div className='flex items-center gap-1'>
                          <IconDownload className='text-muted-foreground h-4 w-4' />
                          <span className='font-medium'>
                            {formatCount(repo.downloads)}
                          </span>
                        </div>
                      ) : (
                        <span className='text-muted-foreground'>—</span>
                      )}
                    </TableCell>
                    <TableCell>
                      {repo.languageMain ? (
                        <Badge variant='secondary' className='gap-1'>
                          <IconCode className='h-3 w-3' />
                          {repo.languageMain}
                        </Badge>
                      ) : (
                        <span className='text-muted-foreground'>—</span>
                      )}
                    </TableCell>
                    <TableCell>
                      {repo.cve_count > 0 ? (
                        <Badge
                          variant='outline'
                          className='gap-1 border-red-500/50 text-red-500'
                        >
                          <IconBug className='h-3 w-3' />
                          {repo.cve_count}
                        </Badge>
                      ) : (
                        <span className='text-muted-foreground'>0</span>
                      )}
                    </TableCell>
                    <TableCell>
                      {repo.commits_fix_count && repo.commits_fix_count > 0 ? (
                        <Badge
                          variant='outline'
                          className='gap-1 border-green-500/50 text-green-500'
                        >
                          <IconGitCommit className='h-3 w-3' />
                          {repo.commits_fix_count}
                        </Badge>
                      ) : (
                        <span className='text-muted-foreground'>0</span>
                      )}
                    </TableCell>
                    <TableCell className='text-muted-foreground text-sm'>
                      {repo.size ? formatSize(repo.size) : '—'}
                    </TableCell>
                    <TableCell className='text-muted-foreground text-sm'>
                      {formatDateLocalized(repo.updated_repository, locale)}
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
            <Table className='min-w-[1000px]'>
              <TableHeader>
                <TableRow>
                  <TableHead className='min-w-[250px]'>Repository</TableHead>
                  <TableHead className='w-[120px]'>Ecosystem</TableHead>
                  <TableHead className='w-[110px]'>Stars</TableHead>
                  <TableHead className='w-[120px]'>Downloads</TableHead>
                  <TableHead className='w-[120px]'>Language</TableHead>
                  <TableHead className='w-[100px]'>CVEs</TableHead>
                  <TableHead className='w-[100px]'>Fixes</TableHead>
                  <TableHead className='w-[100px]'>Size</TableHead>
                  <TableHead className='w-[120px]'>Updated</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {Array.from({ length: 10 }).map((_, i) => (
                  <TableRow key={i}>
                    <TableCell>
                      <Skeleton className='h-10 w-full rounded' />
                    </TableCell>
                    <TableCell>
                      <Skeleton className='h-6 w-20 rounded-full' />
                    </TableCell>
                    <TableCell>
                      <Skeleton className='h-5 w-16 rounded' />
                    </TableCell>
                    <TableCell>
                      <Skeleton className='h-5 w-16 rounded' />
                    </TableCell>
                    <TableCell>
                      <Skeleton className='h-6 w-20 rounded-full' />
                    </TableCell>
                    <TableCell>
                      <Skeleton className='h-6 w-12 rounded-full' />
                    </TableCell>
                    <TableCell>
                      <Skeleton className='h-6 w-12 rounded-full' />
                    </TableCell>
                    <TableCell>
                      <Skeleton className='h-5 w-16 rounded' />
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
  if (stars >= 1000000) {
    return `${(stars / 1000000).toFixed(1)}M`;
  }
  if (stars >= 1000) {
    return `${(stars / 1000).toFixed(1)}k`;
  }
  return stars.toString();
}

function formatCount(value: number): string {
  if (value >= 1000000) {
    return `${(value / 1000000).toFixed(1)}M`;
  }
  if (value >= 1000) {
    return `${(value / 1000).toFixed(1)}k`;
  }
  return value.toLocaleString();
}

function formatSize(sizeKB: number): string {
  if (sizeKB >= 1024 * 1024) {
    return `${(sizeKB / (1024 * 1024)).toFixed(1)} GB`;
  }
  if (sizeKB >= 1024) {
    return `${(sizeKB / 1024).toFixed(1)} MB`;
  }
  return `${sizeKB} KB`;
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
