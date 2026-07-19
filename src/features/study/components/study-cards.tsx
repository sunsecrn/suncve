'use client';

import type { ReactNode } from 'react';
import { IconStar, IconX, IconExternalLink } from '@tabler/icons-react';
import { Badge } from '@/components/ui/badge';
import { Button } from '@/components/ui/button';
import { Card } from '@/components/ui/card';
import { getSeverityColor } from '@/features/search/types';
import { getEcosystemMeta } from '@/lib/ecosystem';
import { cn } from '@/lib/utils';
import type { CveSnapshot, RepoSnapshot } from '../types';

interface CveMiniCardProps {
  snapshot: CveSnapshot;
  onOpen: (cveId: string) => void;
  onRemove?: () => void;
  removeLabel?: string;
  footer?: ReactNode;
}

export function CveMiniCard({
  snapshot,
  onOpen,
  onRemove,
  removeLabel,
  footer
}: CveMiniCardProps) {
  return (
    <Card
      role='button'
      tabIndex={0}
      onClick={() => onOpen(snapshot.cve_id)}
      onKeyDown={(e) => {
        if (e.key === 'Enter' || e.key === ' ') {
          e.preventDefault();
          onOpen(snapshot.cve_id);
        }
      }}
      className='hover:border-primary/50 cursor-pointer gap-0 p-3 transition-colors'
    >
      <div className='flex items-start justify-between gap-2'>
        <div className='min-w-0 flex-1'>
          <div className='flex flex-wrap items-center gap-2'>
            <span className='font-mono text-sm font-semibold'>
              {snapshot.cve_id}
            </span>
            {snapshot.cvss != null && (
              <Badge
                className={cn(
                  'px-2 py-0 font-mono text-xs',
                  getSeverityColor(snapshot.severity)
                )}
              >
                {snapshot.cvss.toFixed(1)}
              </Badge>
            )}
          </div>
          {snapshot.title && (
            <p className='text-muted-foreground mt-1 line-clamp-2 text-xs'>
              {snapshot.title}
            </p>
          )}
          {footer}
        </div>
        {onRemove && (
          <Button
            variant='ghost'
            size='icon'
            className='h-7 w-7 shrink-0'
            aria-label={removeLabel}
            title={removeLabel}
            onClick={(e) => {
              e.stopPropagation();
              onRemove();
            }}
          >
            <IconX className='h-4 w-4' />
          </Button>
        )}
      </div>
    </Card>
  );
}

function repoExternalUrl(snapshot: RepoSnapshot): string {
  if (snapshot.ecosystem === 'wordpress') return `https://${snapshot.fullpath}`;
  if (snapshot.ecosystem === 'npm') {
    return `https://www.npmjs.com/package/${snapshot.name ?? snapshot.fullpath}`;
  }
  if (snapshot.ecosystem === 'packagist') {
    return `https://packagist.org/packages/${snapshot.fullpath}`;
  }
  return `https://github.com/${snapshot.fullpath}`;
}

interface RepoMiniCardProps {
  snapshot: RepoSnapshot;
  onRemove?: () => void;
  removeLabel?: string;
}

export function RepoMiniCard({
  snapshot,
  onRemove,
  removeLabel
}: RepoMiniCardProps) {
  const eco = getEcosystemMeta(snapshot.ecosystem);
  const EcoIcon = eco.Icon;
  return (
    <Card className='gap-0 p-3'>
      <div className='flex items-start justify-between gap-2'>
        <div className='min-w-0 flex-1'>
          <div className='flex items-center gap-2'>
            <EcoIcon className={cn('h-4 w-4 shrink-0', eco.textClass)} />
            <span className='truncate font-mono text-sm'>
              {snapshot.fullpath}
            </span>
          </div>
          <div className='text-muted-foreground mt-2 flex flex-wrap items-center gap-3 text-xs'>
            <Badge variant='outline' className={cn('gap-1', eco.borderClass)}>
              <EcoIcon className='h-3 w-3' />
              {eco.label}
            </Badge>
            {snapshot.stars != null && (
              <span className='flex items-center gap-1'>
                <IconStar className='h-3.5 w-3.5 text-yellow-500' />
                <span className='tabular-nums'>
                  {snapshot.stars.toLocaleString()}
                </span>
              </span>
            )}
          </div>
        </div>
        <div className='flex shrink-0 items-center gap-1'>
          <a
            href={repoExternalUrl(snapshot)}
            target='_blank'
            rel='noopener noreferrer'
            className='text-muted-foreground hover:text-primary p-1 transition-colors'
            aria-label='external link'
          >
            <IconExternalLink className='h-4 w-4' />
          </a>
          {onRemove && (
            <Button
              variant='ghost'
              size='icon'
              className='h-7 w-7'
              aria-label={removeLabel}
              title={removeLabel}
              onClick={onRemove}
            >
              <IconX className='h-4 w-4' />
            </Button>
          )}
        </div>
      </div>
    </Card>
  );
}

/** Snapshot mínimo para itens cujo snapshot completo não existe mais no cache. */
export function fallbackCveSnapshot(cveId: string): CveSnapshot {
  return {
    cve_id: cveId,
    title: null,
    cvss: null,
    severity: 'none',
    date_published: null
  };
}
