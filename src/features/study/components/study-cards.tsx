'use client';

import type { ReactNode } from 'react';
import { useLocale } from 'next-intl';
import {
  IconStar,
  IconX,
  IconExternalLink,
  IconCalendar
} from '@tabler/icons-react';
import { Badge } from '@/components/ui/badge';
import { Button } from '@/components/ui/button';
import { Card } from '@/components/ui/card';
import { getSeverityColor } from '@/features/search/types';
import { getEcosystemMeta } from '@/lib/ecosystem';
import { formatDateLocalized } from '@/lib/format';
import { cn } from '@/lib/utils';
import { useStudyStore } from '../store/use-study-store';
import { getLabelColorMeta, type CveSnapshot, type RepoSnapshot } from '../types';

const EMPTY: string[] = [];

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
  const locale = useLocale();
  const labelIds = useStudyStore((s) => s.cveLabels[snapshot.cve_id]) ?? EMPTY;
  const labels = useStudyStore((s) => s.labels);
  const chips = labelIds
    .map((id) => labels.find((l) => l.id === id))
    .filter((l): l is NonNullable<typeof l> => Boolean(l));

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
      className='hover:border-primary/50 hover:bg-muted/40 cursor-pointer gap-0 p-4 transition-colors'
    >
      <div className='flex items-start justify-between gap-3'>
        <div className='min-w-0 flex-1 space-y-2'>
          <div className='flex flex-wrap items-center gap-2'>
            <span className='font-mono text-base font-semibold break-all'>
              {snapshot.cve_id}
            </span>
            {snapshot.cvss != null && (
              <Badge
                className={cn(
                  'px-2 py-0.5 font-mono text-xs',
                  getSeverityColor(snapshot.severity)
                )}
              >
                {snapshot.cvss.toFixed(1)} · {snapshot.severity.toUpperCase()}
              </Badge>
            )}
          </div>

          {snapshot.title && (
            <p className='text-foreground/90 line-clamp-2 text-sm leading-snug'>
              {snapshot.title}
            </p>
          )}

          {snapshot.date_published && (
            <p className='text-muted-foreground flex items-center gap-1.5 text-xs'>
              <IconCalendar className='h-3.5 w-3.5' />
              <span className='tabular-nums'>
                {formatDateLocalized(snapshot.date_published, locale)}
              </span>
            </p>
          )}

          {chips.length > 0 && (
            <div className='flex flex-wrap gap-1.5 pt-0.5'>
              {chips.map((label) => (
                <span
                  key={label.id}
                  className={cn(
                    'inline-flex items-center rounded-full border px-2 py-0.5 text-[11px] font-medium',
                    getLabelColorMeta(label.color).badge
                  )}
                >
                  {label.name}
                </span>
              ))}
            </div>
          )}

          {footer}
        </div>

        {onRemove && (
          <Button
            variant='ghost'
            size='icon'
            className='h-8 w-8 shrink-0'
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
    // encodeURI (e nao encodeURIComponent) para preservar a barra de pacotes
    // com escopo (@org/pkg); o nome vem de dado externo, entao nunca vai cru.
    return `https://www.npmjs.com/package/${encodeURI(snapshot.name ?? snapshot.fullpath)}`;
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
    <Card className='gap-0 p-4'>
      <div className='flex items-start justify-between gap-3'>
        <div className='min-w-0 flex-1 space-y-2'>
          <div className='flex items-center gap-2'>
            <EcoIcon className={cn('h-4 w-4 shrink-0', eco.textClass)} />
            <span className='truncate font-mono text-sm font-medium'>
              {snapshot.fullpath}
            </span>
          </div>
          <div className='text-muted-foreground flex flex-wrap items-center gap-3 text-xs'>
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
            onClick={(e) => e.stopPropagation()}
          >
            <IconExternalLink className='h-4 w-4' />
          </a>
          {onRemove && (
            <Button
              variant='ghost'
              size='icon'
              className='h-8 w-8'
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
