// Ported verbatim from src/features/search/types.ts so the EPSS buckets match
// the web UI exactly.
//
// EPSS is the probability [0-1] that a CVE will be exploited in the next 30
// days. The thresholds are on the raw probability, not the percentile, so a
// full signal means real risk rather than merely "above the median".

export type EpssLevel =
  | 'none'
  | 'very-low'
  | 'low'
  | 'moderate'
  | 'high'
  | 'critical';

export type EpssFilterLevel = Exclude<EpssLevel, 'none'>;

export function getEpssLevel(epss: number | null | undefined): EpssLevel {
  if (epss === null || epss === undefined) return 'none';
  if (epss >= 0.7) return 'critical';
  if (epss >= 0.36) return 'high';
  if (epss >= 0.1) return 'moderate';
  if (epss >= 0.01) return 'low';
  return 'very-low';
}

export const EPSS_LEVEL_RANGE: Record<
  EpssFilterLevel,
  { min: number; max: number | null }
> = {
  'very-low': { min: 0, max: 0.01 },
  low: { min: 0.01, max: 0.1 },
  moderate: { min: 0.1, max: 0.36 },
  high: { min: 0.36, max: 0.7 },
  critical: { min: 0.7, max: null }
};

export const EPSS_LEVELS: EpssFilterLevel[] = [
  'very-low',
  'low',
  'moderate',
  'high',
  'critical'
];
