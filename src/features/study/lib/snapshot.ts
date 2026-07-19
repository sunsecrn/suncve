// Constrói mini-snapshots denormalizados a partir dos registros crus vindos do SQLite.
// Usado no drawer da CVE/repo para favoritar, marcar labels e registrar histórico sem
// depender do SQLite estar carregado na aba "Meus Estudos".

import { getSeverityFromScore } from '@/features/search/types';
import type { CveSnapshot, RepoSnapshot } from '../types';

export function buildCveSnapshot(cve: Record<string, unknown>): CveSnapshot {
  const scores =
    (cve.scores as Array<{ version: string; score: number }>) ?? [];
  const cvss = scores.length > 0 ? Math.max(...scores.map((s) => s.score)) : null;
  return {
    cve_id: String(cve.cve_id),
    title: (cve.title as string) ?? null,
    cvss,
    severity: cvss !== null ? getSeverityFromScore(cvss) : 'none',
    date_published: (cve.date_published as string) ?? null
  };
}

export function buildRepoSnapshot(
  repo: Record<string, unknown>
): RepoSnapshot {
  return {
    fullpath: String(repo.fullpath),
    name: (repo.name as string) ?? null,
    stars: (repo.stars as number) ?? null,
    ecosystem: (repo.ecosystem as string) ?? null
  };
}
