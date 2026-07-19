'use client';

// Store único do módulo "Meus Estudos". Zustand + persist gravando no IndexedDB.
// É um hook usável em qualquer componente client — não precisa de Provider novo.

import { useEffect, useState } from 'react';
import { create } from 'zustand';
import { persist, createJSONStorage } from 'zustand/middleware';
import {
  HISTORY_LIMIT,
  type CveSnapshot,
  type Label,
  type LabelColor,
  type RepoSnapshot,
  type StudyData
} from '../types';
import { idbStorage } from './study-storage';

interface StudyState extends StudyData {
  toggleFavoriteCve: (snap: CveSnapshot) => void;
  toggleFavoriteRepo: (snap: RepoSnapshot) => void;
  setNote: (cveId: string, markdown: string) => void;
  createLabel: (name: string, color: LabelColor) => Label;
  renameLabel: (id: string, name: string) => void;
  recolorLabel: (id: string, color: LabelColor) => void;
  deleteLabel: (id: string) => void;
  toggleCveLabel: (cveId: string, labelId: string, snap: CveSnapshot) => void;
  recordHistory: (snap: CveSnapshot) => void;
  removeHistoryEntry: (cveId: string) => void;
  clearHistory: () => void;
  importData: (data: StudyData) => void;
}

const initialData: StudyData = {
  snapshots: {},
  repoSnapshots: {},
  favoriteCves: [],
  favoriteRepos: [],
  notes: {},
  labels: [],
  cveLabels: {},
  history: []
};

function genId(): string {
  if (typeof crypto !== 'undefined' && 'randomUUID' in crypto) {
    return crypto.randomUUID();
  }
  return `${Date.now().toString(36)}-${Math.random().toString(36).slice(2, 10)}`;
}

export const useStudyStore = create<StudyState>()(
  persist(
    (set) => ({
      ...initialData,

      toggleFavoriteCve: (snap) =>
        set((state) => {
          const exists = state.favoriteCves.includes(snap.cve_id);
          return {
            snapshots: { ...state.snapshots, [snap.cve_id]: snap },
            favoriteCves: exists
              ? state.favoriteCves.filter((id) => id !== snap.cve_id)
              : [snap.cve_id, ...state.favoriteCves]
          };
        }),

      toggleFavoriteRepo: (snap) =>
        set((state) => {
          const exists = state.favoriteRepos.includes(snap.fullpath);
          return {
            repoSnapshots: { ...state.repoSnapshots, [snap.fullpath]: snap },
            favoriteRepos: exists
              ? state.favoriteRepos.filter((fp) => fp !== snap.fullpath)
              : [snap.fullpath, ...state.favoriteRepos]
          };
        }),

      setNote: (cveId, markdown) =>
        set((state) => {
          const notes = { ...state.notes };
          if (markdown.trim() === '') {
            delete notes[cveId];
          } else {
            notes[cveId] = markdown;
          }
          return { notes };
        }),

      createLabel: (name, color) => {
        const label: Label = {
          id: genId(),
          name: name.trim() || 'Label',
          color,
          createdAt: Date.now()
        };
        set((state) => ({ labels: [...state.labels, label] }));
        return label;
      },

      renameLabel: (id, name) =>
        set((state) => ({
          labels: state.labels.map((l) =>
            l.id === id ? { ...l, name: name.trim() || l.name } : l
          )
        })),

      recolorLabel: (id, color) =>
        set((state) => ({
          labels: state.labels.map((l) => (l.id === id ? { ...l, color } : l))
        })),

      deleteLabel: (id) =>
        set((state) => {
          const cveLabels: Record<string, string[]> = {};
          for (const [cveId, ids] of Object.entries(state.cveLabels)) {
            const filtered = ids.filter((labelId) => labelId !== id);
            if (filtered.length) cveLabels[cveId] = filtered;
          }
          return {
            labels: state.labels.filter((l) => l.id !== id),
            cveLabels
          };
        }),

      toggleCveLabel: (cveId, labelId, snap) =>
        set((state) => {
          const current = state.cveLabels[cveId] ?? [];
          const next = current.includes(labelId)
            ? current.filter((l) => l !== labelId)
            : [...current, labelId];
          const cveLabels = { ...state.cveLabels };
          if (next.length) {
            cveLabels[cveId] = next;
          } else {
            delete cveLabels[cveId];
          }
          return {
            snapshots: { ...state.snapshots, [cveId]: snap },
            cveLabels
          };
        }),

      recordHistory: (snap) =>
        set((state) => {
          const history = [
            { cveId: snap.cve_id, ts: Date.now() },
            ...state.history.filter((h) => h.cveId !== snap.cve_id)
          ].slice(0, HISTORY_LIMIT);
          return {
            snapshots: { ...state.snapshots, [snap.cve_id]: snap },
            history
          };
        }),

      removeHistoryEntry: (cveId) =>
        set((state) => ({
          history: state.history.filter((h) => h.cveId !== cveId)
        })),

      clearHistory: () => set({ history: [] }),

      importData: (data) =>
        set(() => ({
          snapshots: data.snapshots,
          repoSnapshots: data.repoSnapshots,
          favoriteCves: data.favoriteCves,
          favoriteRepos: data.favoriteRepos,
          notes: data.notes,
          labels: data.labels,
          cveLabels: data.cveLabels,
          history: data.history
        }))
    }),
    {
      name: 'suncve-study',
      version: 1,
      storage: createJSONStorage(() => idbStorage),
      partialize: (s): StudyData => ({
        snapshots: s.snapshots,
        repoSnapshots: s.repoSnapshots,
        favoriteCves: s.favoriteCves,
        favoriteRepos: s.favoriteRepos,
        notes: s.notes,
        labels: s.labels,
        cveLabels: s.cveLabels,
        history: s.history
      })
    }
  )
);

/**
 * Como o persist sobre IndexedDB reidrata de forma assíncrona, use este hook
 * para evitar flash no estado inicial (ex.: estrela de favorito).
 */
export function useStudyHydrated(): boolean {
  const [hydrated, setHydrated] = useState<boolean>(() =>
    useStudyStore.persist.hasHydrated()
  );

  useEffect(() => {
    const unsub = useStudyStore.persist.onFinishHydration(() =>
      setHydrated(true)
    );
    setHydrated(useStudyStore.persist.hasHydrated());
    return () => unsub();
  }, []);

  return hydrated;
}
