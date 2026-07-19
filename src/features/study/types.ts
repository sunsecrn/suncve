// Tipos do módulo "Meus Estudos": favoritos, anotações, histórico e labels/listas.
// Todo o dado do usuário vive apenas no navegador (IndexedDB) — nunca no SQLite,
// que é somente-leitura e substituído por inteiro a cada atualização.

import type { Severity } from '@/features/search/types';

/** Mini-snapshot denormalizado de uma CVE, capturado no momento da ação. */
export interface CveSnapshot {
  cve_id: string;
  title: string | null;
  cvss: number | null;
  severity: Severity;
  date_published: string | null;
}

/** Mini-snapshot denormalizado de um repositório. */
export interface RepoSnapshot {
  fullpath: string;
  name: string | null;
  stars: number | null;
  ecosystem: string | null;
}

export type LabelColor =
  | 'red'
  | 'orange'
  | 'amber'
  | 'green'
  | 'teal'
  | 'blue'
  | 'violet'
  | 'pink'
  | 'slate';

export interface Label {
  id: string;
  name: string;
  color: LabelColor;
  createdAt: number;
}

/** Entrada de histórico — referencia o snapshot pela chave `cveId`. */
export interface HistoryEntry {
  cveId: string;
  ts: number;
}

/** Fatia persistida do store (o que vai pro IndexedDB e pro export). */
export interface StudyData {
  snapshots: Record<string, CveSnapshot>; // cve_id -> snapshot
  repoSnapshots: Record<string, RepoSnapshot>; // fullpath -> snapshot
  favoriteCves: string[]; // ids, mais recente primeiro
  favoriteRepos: string[]; // fullpaths, mais recente primeiro
  notes: Record<string, string>; // cve_id -> markdown
  labels: Label[];
  cveLabels: Record<string, string[]>; // cve_id -> labelId[]
  history: HistoryEntry[]; // mais recente primeiro, cap HISTORY_LIMIT
  seeded: boolean; // se as labels padrão já foram semeadas uma vez
}

/** Labels de estudo criadas automaticamente na primeira vez (uma vez só). */
export const DEFAULT_LABELS: {
  namePtBR: string;
  nameEn: string;
  color: LabelColor;
}[] = [
  { namePtBR: 'Estudar mais tarde', nameEn: 'Study later', color: 'blue' },
  { namePtBR: 'Aprendendo', nameEn: 'Learning', color: 'amber' },
  { namePtBR: 'Importante', nameEn: 'Important', color: 'red' },
  { namePtBR: 'Dominado', nameEn: 'Mastered', color: 'green' }
];

/** Formato do arquivo de export/import. */
export interface StudyExport {
  app: 'suncve';
  kind: 'study-export';
  version: number;
  exportedAt: string;
  data: StudyData;
}

export const STUDY_EXPORT_VERSION = 1;
export const HISTORY_LIMIT = 30;

/** Paleta fixa de labels. Classes literais para o Tailwind detectar no build. */
export const LABEL_COLORS: LabelColor[] = [
  'red',
  'orange',
  'amber',
  'green',
  'teal',
  'blue',
  'violet',
  'pink',
  'slate'
];

export const LABEL_COLOR_META: Record<
  LabelColor,
  { dot: string; badge: string }
> = {
  red: {
    dot: 'bg-red-500',
    badge: 'border-red-500/40 bg-red-500/15 text-red-600 dark:text-red-400'
  },
  orange: {
    dot: 'bg-orange-500',
    badge:
      'border-orange-500/40 bg-orange-500/15 text-orange-600 dark:text-orange-400'
  },
  amber: {
    dot: 'bg-amber-500',
    badge:
      'border-amber-500/40 bg-amber-500/15 text-amber-600 dark:text-amber-400'
  },
  green: {
    dot: 'bg-green-500',
    badge:
      'border-green-500/40 bg-green-500/15 text-green-600 dark:text-green-400'
  },
  teal: {
    dot: 'bg-teal-500',
    badge: 'border-teal-500/40 bg-teal-500/15 text-teal-600 dark:text-teal-400'
  },
  blue: {
    dot: 'bg-blue-500',
    badge: 'border-blue-500/40 bg-blue-500/15 text-blue-600 dark:text-blue-400'
  },
  violet: {
    dot: 'bg-violet-500',
    badge:
      'border-violet-500/40 bg-violet-500/15 text-violet-600 dark:text-violet-400'
  },
  pink: {
    dot: 'bg-pink-500',
    badge: 'border-pink-500/40 bg-pink-500/15 text-pink-600 dark:text-pink-400'
  },
  slate: {
    dot: 'bg-slate-500',
    badge:
      'border-slate-500/40 bg-slate-500/15 text-slate-600 dark:text-slate-400'
  }
};

export function getLabelColorMeta(color: string) {
  return LABEL_COLOR_META[color as LabelColor] ?? LABEL_COLOR_META.slate;
}
