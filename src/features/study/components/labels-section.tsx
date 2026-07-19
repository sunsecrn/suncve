'use client';

import { useMemo, useState } from 'react';
import { useTranslations } from 'next-intl';
import {
  IconTag,
  IconPlus,
  IconTrash,
  IconPencil,
  IconCheck,
  IconX
} from '@tabler/icons-react';
import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';
import { cn } from '@/lib/utils';
import { useStudyStore } from '../store/use-study-store';
import {
  LABEL_COLORS,
  LABEL_COLOR_META,
  getLabelColorMeta,
  type LabelColor
} from '../types';
import { CveMiniCard, fallbackCveSnapshot } from './study-cards';
import { EmptyState } from './empty-state';

export function LabelsSection({
  onOpenCve
}: {
  onOpenCve: (cveId: string) => void;
}) {
  const t = useTranslations('studies.labels');
  const labels = useStudyStore((s) => s.labels);
  const cveLabels = useStudyStore((s) => s.cveLabels);
  const snapshots = useStudyStore((s) => s.snapshots);
  const createLabel = useStudyStore((s) => s.createLabel);
  const renameLabel = useStudyStore((s) => s.renameLabel);
  const deleteLabel = useStudyStore((s) => s.deleteLabel);
  const toggleCveLabel = useStudyStore((s) => s.toggleCveLabel);

  const [selectedId, setSelectedId] = useState<string | null>(null);
  const [newName, setNewName] = useState('');
  const [newColor, setNewColor] = useState<LabelColor>('blue');
  const [renaming, setRenaming] = useState<string | null>(null);
  const [renameValue, setRenameValue] = useState('');

  const counts = useMemo(() => {
    const c: Record<string, number> = {};
    for (const ids of Object.values(cveLabels)) {
      for (const id of ids) c[id] = (c[id] ?? 0) + 1;
    }
    return c;
  }, [cveLabels]);

  const selected = labels.find((l) => l.id === selectedId) ?? null;

  const cveIdsInSelected = useMemo(() => {
    if (!selectedId) return [];
    return Object.entries(cveLabels)
      .filter(([, ids]) => ids.includes(selectedId))
      .map(([cveId]) => cveId);
  }, [cveLabels, selectedId]);

  const handleCreate = () => {
    const name = newName.trim();
    if (!name) return;
    const label = createLabel(name, newColor);
    setNewName('');
    setSelectedId(label.id);
  };

  const startRename = (id: string, currentName: string) => {
    setRenaming(id);
    setRenameValue(currentName);
  };

  const commitRename = () => {
    if (renaming) renameLabel(renaming, renameValue);
    setRenaming(null);
  };

  const handleDelete = (id: string) => {
    if (window.confirm(t('deleteConfirm'))) {
      deleteLabel(id);
      if (selectedId === id) setSelectedId(null);
    }
  };

  return (
    <div className='grid gap-6 md:grid-cols-[300px_1fr]'>
      {/* Rail esquerdo: criar + listas */}
      <div className='space-y-4'>
        {/* Criar nova lista */}
        <div className='bg-card space-y-3 rounded-xl border p-4'>
          <p className='text-muted-foreground text-xs font-semibold tracking-wide uppercase'>
            {t('create')}
          </p>
          <Input
            value={newName}
            onChange={(e) => setNewName(e.target.value)}
            placeholder={t('namePlaceholder')}
            className='h-9'
            onKeyDown={(e) => {
              if (e.key === 'Enter') {
                e.preventDefault();
                handleCreate();
              }
            }}
          />
          <div className='flex flex-wrap items-center gap-2'>
            {LABEL_COLORS.map((color) => (
              <button
                key={color}
                type='button'
                aria-label={color}
                onClick={() => setNewColor(color)}
                className={cn(
                  'h-5 w-5 rounded-full transition-all',
                  LABEL_COLOR_META[color].dot,
                  newColor === color
                    ? 'ring-foreground ring-2 ring-offset-2'
                    : 'opacity-60 hover:opacity-100'
                )}
              />
            ))}
          </div>
          <Button
            size='sm'
            className='w-full gap-1.5'
            onClick={handleCreate}
            disabled={!newName.trim()}
          >
            <IconPlus className='h-4 w-4' />
            {t('add')}
          </Button>
        </div>

        {/* Lista de labels */}
        <div className='space-y-1'>
          {labels.length === 0 ? (
            <p className='text-muted-foreground px-1 py-2 text-xs'>
              {t('empty')}
            </p>
          ) : (
            labels.map((label) => {
              const meta = getLabelColorMeta(label.color);
              const isSelected = selectedId === label.id;
              const isRenaming = renaming === label.id;
              return (
                <div
                  key={label.id}
                  className={cn(
                    'group flex items-center gap-2 rounded-lg border border-transparent px-2.5 py-2 transition-colors',
                    isSelected
                      ? 'bg-muted border-border'
                      : 'hover:bg-muted/60'
                  )}
                >
                  {isRenaming ? (
                    <>
                      <span
                        className={cn('h-3 w-3 shrink-0 rounded-full', meta.dot)}
                      />
                      <Input
                        autoFocus
                        value={renameValue}
                        onChange={(e) => setRenameValue(e.target.value)}
                        onKeyDown={(e) => {
                          if (e.key === 'Enter') commitRename();
                          if (e.key === 'Escape') setRenaming(null);
                        }}
                        className='h-6 flex-1 px-1 text-sm'
                      />
                      <button
                        type='button'
                        onClick={commitRename}
                        className='text-primary shrink-0'
                        aria-label={t('rename')}
                      >
                        <IconCheck className='h-4 w-4' />
                      </button>
                      <button
                        type='button'
                        onClick={() => setRenaming(null)}
                        className='text-muted-foreground shrink-0'
                        aria-label='cancel'
                      >
                        <IconX className='h-4 w-4' />
                      </button>
                    </>
                  ) : (
                    <>
                      <button
                        type='button'
                        onClick={() => setSelectedId(label.id)}
                        className='flex min-w-0 flex-1 items-center gap-2.5 text-left text-sm'
                      >
                        <span
                          className={cn(
                            'h-3 w-3 shrink-0 rounded-full',
                            meta.dot
                          )}
                        />
                        <span className='truncate font-medium'>
                          {label.name}
                        </span>
                        <span className='bg-muted-foreground/15 text-muted-foreground ml-auto rounded-full px-2 py-0.5 text-xs tabular-nums'>
                          {counts[label.id] ?? 0}
                        </span>
                      </button>
                      <button
                        type='button'
                        onClick={() => startRename(label.id, label.name)}
                        className='text-muted-foreground hover:text-foreground shrink-0 opacity-0 transition-opacity group-hover:opacity-100'
                        aria-label={t('rename')}
                      >
                        <IconPencil className='h-3.5 w-3.5' />
                      </button>
                      <button
                        type='button'
                        onClick={() => handleDelete(label.id)}
                        className='text-muted-foreground hover:text-destructive shrink-0 opacity-0 transition-opacity group-hover:opacity-100'
                        aria-label={t('delete')}
                      >
                        <IconTrash className='h-3.5 w-3.5' />
                      </button>
                    </>
                  )}
                </div>
              );
            })
          )}
        </div>
      </div>

      {/* Painel direito: CVEs da lista selecionada */}
      <div className='min-w-0'>
        {!selected ? (
          <EmptyState icon={IconTag} title={t('selectHint')} />
        ) : (
          <div className='space-y-4'>
            <div className='flex items-center gap-2.5 border-b pb-3'>
              <span
                className={cn(
                  'h-4 w-4 shrink-0 rounded-full',
                  getLabelColorMeta(selected.color).dot
                )}
              />
              <h3 className='truncate text-lg font-semibold'>
                {selected.name}
              </h3>
              <span className='bg-muted text-muted-foreground rounded-full px-2.5 py-0.5 text-xs tabular-nums'>
                {cveIdsInSelected.length}
              </span>
            </div>

            {cveIdsInSelected.length === 0 ? (
              <EmptyState icon={IconTag} title={t('emptyList')} />
            ) : (
              <div className='grid gap-3 sm:grid-cols-2'>
                {cveIdsInSelected.map((cveId) => {
                  const snap = snapshots[cveId] ?? fallbackCveSnapshot(cveId);
                  return (
                    <CveMiniCard
                      key={cveId}
                      snapshot={snap}
                      onOpen={onOpenCve}
                      onRemove={() => toggleCveLabel(cveId, selected.id, snap)}
                      removeLabel={t('removeFromList')}
                    />
                  );
                })}
              </div>
            )}
          </div>
        )}
      </div>
    </div>
  );
}
