// Export/import do módulo "Meus Estudos" em arquivo JSON. Rede de segurança contra
// perda de dados (o app é client-side puro; nada sincroniza entre dispositivos).

import {
  STUDY_EXPORT_VERSION,
  type CveSnapshot,
  type HistoryEntry,
  type Label,
  type RepoSnapshot,
  type StudyData,
  type StudyExport
} from '../types';
import { useStudyStore } from '../store/use-study-store';

function currentData(): StudyData {
  const s = useStudyStore.getState();
  return {
    snapshots: s.snapshots,
    repoSnapshots: s.repoSnapshots,
    favoriteCves: s.favoriteCves,
    favoriteRepos: s.favoriteRepos,
    notes: s.notes,
    labels: s.labels,
    cveLabels: s.cveLabels,
    history: s.history,
    seeded: s.seeded
  };
}

export function buildExport(): StudyExport {
  return {
    app: 'suncve',
    kind: 'study-export',
    version: STUDY_EXPORT_VERSION,
    exportedAt: new Date().toISOString(),
    data: currentData()
  };
}

export function exportToFile(): void {
  const payload = buildExport();
  const blob = new Blob([JSON.stringify(payload, null, 2)], {
    type: 'application/json'
  });
  const url = URL.createObjectURL(blob);
  const anchor = document.createElement('a');
  anchor.href = url;
  anchor.download = `suncve-estudos-${new Date().toISOString().slice(0, 10)}.json`;
  document.body.appendChild(anchor);
  anchor.click();
  anchor.remove();
  URL.revokeObjectURL(url);
}

/* ------------------------------ validação ------------------------------ */

function isObject(v: unknown): v is Record<string, unknown> {
  return typeof v === 'object' && v !== null && !Array.isArray(v);
}

function coerceStringArray(v: unknown): string[] {
  return Array.isArray(v) ? v.filter((x): x is string => typeof x === 'string') : [];
}

function coerceStringRecord(v: unknown): Record<string, string> {
  const out: Record<string, string> = {};
  if (isObject(v)) {
    for (const [k, val] of Object.entries(v)) {
      if (typeof val === 'string') out[k] = val;
    }
  }
  return out;
}

function coerceSnapshots(v: unknown): Record<string, CveSnapshot> {
  const out: Record<string, CveSnapshot> = {};
  if (isObject(v)) {
    for (const [k, val] of Object.entries(v)) {
      if (isObject(val) && typeof val.cve_id === 'string') {
        out[k] = {
          cve_id: val.cve_id,
          title: (val.title as string) ?? null,
          cvss: typeof val.cvss === 'number' ? val.cvss : null,
          severity: (val.severity as CveSnapshot['severity']) ?? 'none',
          date_published: (val.date_published as string) ?? null
        };
      }
    }
  }
  return out;
}

function coerceRepoSnapshots(v: unknown): Record<string, RepoSnapshot> {
  const out: Record<string, RepoSnapshot> = {};
  if (isObject(v)) {
    for (const [k, val] of Object.entries(v)) {
      if (isObject(val) && typeof val.fullpath === 'string') {
        out[k] = {
          fullpath: val.fullpath,
          name: (val.name as string) ?? null,
          stars: typeof val.stars === 'number' ? val.stars : null,
          ecosystem: (val.ecosystem as string) ?? null
        };
      }
    }
  }
  return out;
}

function coerceLabels(v: unknown): Label[] {
  if (!Array.isArray(v)) return [];
  return v
    .filter(
      (l): l is Record<string, unknown> =>
        isObject(l) && typeof l.id === 'string' && typeof l.name === 'string'
    )
    .map((l) => ({
      id: l.id as string,
      name: l.name as string,
      color: (l.color as Label['color']) ?? 'slate',
      createdAt: typeof l.createdAt === 'number' ? l.createdAt : Date.now()
    }));
}

function coerceCveLabels(v: unknown): Record<string, string[]> {
  const out: Record<string, string[]> = {};
  if (isObject(v)) {
    for (const [k, val] of Object.entries(v)) {
      const arr = coerceStringArray(val);
      if (arr.length) out[k] = arr;
    }
  }
  return out;
}

function coerceHistory(v: unknown): HistoryEntry[] {
  if (!Array.isArray(v)) return [];
  return v
    .filter(
      (h): h is Record<string, unknown> =>
        isObject(h) && typeof h.cveId === 'string'
    )
    .map((h) => ({
      cveId: h.cveId as string,
      ts: typeof h.ts === 'number' ? h.ts : Date.now()
    }));
}

function normalizeStudyData(raw: unknown): StudyData {
  const d = isObject(raw) ? raw : {};
  return {
    snapshots: coerceSnapshots(d.snapshots),
    repoSnapshots: coerceRepoSnapshots(d.repoSnapshots),
    favoriteCves: coerceStringArray(d.favoriteCves),
    favoriteRepos: coerceStringArray(d.favoriteRepos),
    notes: coerceStringRecord(d.notes),
    labels: coerceLabels(d.labels),
    cveLabels: coerceCveLabels(d.cveLabels),
    history: coerceHistory(d.history),
    // Datasets importados são de usuários já estabelecidos: não re-semear defaults.
    seeded: d.seeded === undefined ? true : Boolean(d.seeded)
  };
}

/** Lê e valida um arquivo de export. Lança em JSON inválido / formato desconhecido. */
export async function parseImportFile(file: File): Promise<StudyData> {
  const text = await file.text();
  const json: unknown = JSON.parse(text); // pode lançar SyntaxError
  if (!isObject(json) || json.kind !== 'study-export' || !('data' in json)) {
    throw new Error('Arquivo de export inválido');
  }
  return normalizeStudyData(json.data);
}
