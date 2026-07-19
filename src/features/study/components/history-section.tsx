'use client';

import { useTranslations, useLocale } from 'next-intl';
import { IconHistory, IconTrash } from '@tabler/icons-react';
import { Button } from '@/components/ui/button';
import { useStudyStore } from '../store/use-study-store';
import { CveMiniCard, fallbackCveSnapshot } from './study-cards';
import { EmptyState } from './empty-state';

export function HistorySection({
  onOpenCve
}: {
  onOpenCve: (cveId: string) => void;
}) {
  const t = useTranslations('studies.history');
  const locale = useLocale();
  const history = useStudyStore((s) => s.history);
  const snapshots = useStudyStore((s) => s.snapshots);
  const clearHistory = useStudyStore((s) => s.clearHistory);
  const removeHistoryEntry = useStudyStore((s) => s.removeHistoryEntry);

  if (history.length === 0) {
    return <EmptyState icon={IconHistory} title={t('empty')} />;
  }

  const formatTs = (ts: number) =>
    new Intl.DateTimeFormat(locale, {
      dateStyle: 'short',
      timeStyle: 'short'
    }).format(new Date(ts));

  return (
    <div className='space-y-3'>
      <div className='flex justify-end'>
        <Button
          variant='outline'
          size='sm'
          className='gap-1.5'
          onClick={clearHistory}
        >
          <IconTrash className='h-4 w-4' />
          {t('clear')}
        </Button>
      </div>
      <div className='grid gap-3 sm:grid-cols-2'>
        {history.map((entry) => {
          const snap = snapshots[entry.cveId] ?? fallbackCveSnapshot(entry.cveId);
          return (
            <CveMiniCard
              key={entry.cveId}
              snapshot={snap}
              onOpen={onOpenCve}
              onRemove={() => removeHistoryEntry(entry.cveId)}
              removeLabel={t('remove')}
              footer={
                <p className='text-muted-foreground mt-2 text-[11px] tabular-nums'>
                  {t('accessedAt', { when: formatTs(entry.ts) })}
                </p>
              }
            />
          );
        })}
      </div>
    </div>
  );
}
