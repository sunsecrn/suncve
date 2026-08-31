'use client';

import { useTranslations } from 'next-intl';
import { IconStar } from '@tabler/icons-react';
import { useStudyStore } from '../store/use-study-store';
import {
  CveMiniCard,
  RepoMiniCard,
  fallbackCveSnapshot
} from './study-cards';
import { EmptyState } from './empty-state';

export function FavoritesSection({
  onOpenCve,
  onOpenRepo
}: {
  onOpenCve: (cveId: string) => void;
  onOpenRepo: (fullpath: string) => void;
}) {
  const t = useTranslations('studies.favorites');
  const favoriteCves = useStudyStore((s) => s.favoriteCves);
  const favoriteRepos = useStudyStore((s) => s.favoriteRepos);
  const snapshots = useStudyStore((s) => s.snapshots);
  const repoSnapshots = useStudyStore((s) => s.repoSnapshots);
  const toggleCve = useStudyStore((s) => s.toggleFavoriteCve);
  const toggleRepo = useStudyStore((s) => s.toggleFavoriteRepo);

  if (favoriteCves.length === 0 && favoriteRepos.length === 0) {
    return (
      <EmptyState
        icon={IconStar}
        title={t('empty')}
        hint={t('emptyHint')}
      />
    );
  }

  return (
    <div className='space-y-8'>
      {favoriteCves.length > 0 && (
        <section className='space-y-3'>
          <h3 className='text-muted-foreground text-sm font-semibold tracking-wide uppercase'>
            {t('cves')} ({favoriteCves.length})
          </h3>
          <div className='grid gap-3 sm:grid-cols-2'>
            {favoriteCves.map((id) => {
              const snap = snapshots[id] ?? fallbackCveSnapshot(id);
              return (
                <CveMiniCard
                  key={id}
                  snapshot={snap}
                  onOpen={onOpenCve}
                  onRemove={() => toggleCve(snap)}
                  removeLabel={t('remove')}
                />
              );
            })}
          </div>
        </section>
      )}

      {favoriteRepos.length > 0 && (
        <section className='space-y-3'>
          <h3 className='text-muted-foreground text-sm font-semibold tracking-wide uppercase'>
            {t('repos')} ({favoriteRepos.length})
          </h3>
          <div className='grid gap-3 sm:grid-cols-2'>
            {favoriteRepos.map((fp) => {
              const snap = repoSnapshots[fp];
              if (!snap) return null;
              return (
                <RepoMiniCard
                  key={fp}
                  snapshot={snap}
                  onOpen={onOpenRepo}
                  onRemove={() => toggleRepo(snap)}
                  removeLabel={t('remove')}
                />
              );
            })}
          </div>
        </section>
      )}
    </div>
  );
}
