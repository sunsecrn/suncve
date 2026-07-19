'use client';

import { useTranslations } from 'next-intl';
import { IconStar } from '@tabler/icons-react';
import { Button } from '@/components/ui/button';
import { cn } from '@/lib/utils';
import { useStudyStore, useStudyHydrated } from '../store/use-study-store';
import { CveLabelsPopover } from './cve-labels-popover';
import type { CveSnapshot } from '../types';

/** Barra de ações (favoritar + labels) montada no header do drawer da CVE. */
export function StudyActions({ snapshot }: { snapshot: CveSnapshot }) {
  const t = useTranslations('studies.actions');
  const hydrated = useStudyHydrated();
  const isFav = useStudyStore((s) => s.favoriteCves.includes(snapshot.cve_id));
  const toggleFav = useStudyStore((s) => s.toggleFavoriteCve);
  const active = hydrated && isFav;

  return (
    <div className='flex flex-wrap items-center gap-2'>
      <Button
        variant={active ? 'secondary' : 'outline'}
        size='sm'
        className='h-7 gap-1.5'
        onClick={() => toggleFav(snapshot)}
      >
        <IconStar
          className={cn('h-4 w-4', active && 'fill-amber-400 text-amber-500')}
        />
        {active ? t('favorited') : t('favorite')}
      </Button>
      <CveLabelsPopover snapshot={snapshot} />
    </div>
  );
}
