'use client';

import { useState, useCallback } from 'react';
import { useSQLite } from './sqlite-context';

// Types for dashboard data
export interface DashboardStats {
  // Recent activity (last 30 days)
  newCVEs: number;
  newCriticalCVEs: number;
  newWithExploit: number;
  newWithFix: number;
  newInKev: number;
  newHighEpss: number;
}

export interface SeverityDistribution {
  critical: number;
  high: number;
  medium: number;
  low: number;
  unknown: number;
}

export interface CriticalCVEWithPOC {
  cve_id: string;
  title: string | null;
  description: string | null;
  score: number;
  date_published: string;
  // Source flags (SQLite booleans, 0 | 1) — for tags shown next to the CVSS
  exists_exploit: number;
  exists_commit: number;
  exists_nuclei: number;
  in_kev: number;
  missing_nuclei_template: number;
  epss: number | null;
  epss_percentile: number | null;
}

export interface CVEsByPeriod {
  period: string;
  label: string;
  total: number;
  withExploit: number;
}

export interface CWETrendData {
  period: string;
  label: string;
  [key: string]: string | number; // Dynamic CWE keys
}

export interface TopCWE {
  cwe_id: string;
  count: number;
}

export type SeverityPeriod = '7d' | '30d' | '120d';
export type ChartPeriod = '30d' | '1y' | '5y';

export function useDashboardStats() {
  const { executeQuery, isReady } = useSQLite();
  const [isLoading, setIsLoading] = useState(false);

  // Get recent activity stats (last 30 days)
  const getRecentStats = useCallback((): DashboardStats => {
    if (!isReady) {
      return {
        newCVEs: 0,
        newCriticalCVEs: 0,
        newWithExploit: 0,
        newWithFix: 0,
        newInKev: 0,
        newHighEpss: 0
      };
    }

    const now = new Date();
    const thirtyDaysAgo = new Date(now.getTime() - 30 * 24 * 60 * 60 * 1000);
    const dateStr = thirtyDaysAgo.toISOString().split('T')[0];

    const result = executeQuery<{
      newCVEs: number;
      newWithExploit: number;
      newWithFix: number;
      newCriticalCVEs: number;
      newInKev: number;
      newHighEpss: number;
    }>(
      `
      SELECT 
        (SELECT COUNT(*) FROM cves WHERE date_published >= ?) as newCVEs,
        (SELECT COUNT(*) FROM cves WHERE date_published >= ? AND exists_exploit = 1) as newWithExploit,
        (SELECT COUNT(*) FROM cves WHERE date_published >= ? AND exists_commit = 1) as newWithFix,
        (SELECT COUNT(*) FROM cves c 
         WHERE c.date_published >= ? 
         AND EXISTS (SELECT 1 FROM cve_scores cs WHERE cs.cve_id = c.cve_id AND cs.score >= 9.0)
        ) as newCriticalCVEs,
        (SELECT COUNT(*) FROM cves WHERE date_published >= ? AND in_kev = 1) as newInKev,
        (SELECT COUNT(*) FROM cves WHERE date_published >= ? AND epss >= 0.1) as newHighEpss
    `,
      [dateStr, dateStr, dateStr, dateStr, dateStr, dateStr]
    );

    return {
      newCVEs: result[0]?.newCVEs ?? 0,
      newCriticalCVEs: result[0]?.newCriticalCVEs ?? 0,
      newWithExploit: result[0]?.newWithExploit ?? 0,
      newWithFix: result[0]?.newWithFix ?? 0,
      newInKev: result[0]?.newInKev ?? 0,
      newHighEpss: result[0]?.newHighEpss ?? 0
    };
  }, [isReady, executeQuery]);

  // Get severity distribution with configurable period (includes unknown)
  const getSeverityDistribution = useCallback(
    (period: SeverityPeriod = '30d'): SeverityDistribution => {
      if (!isReady) {
        return { critical: 0, high: 0, medium: 0, low: 0, unknown: 0 };
      }

      const days = period === '7d' ? 7 : period === '30d' ? 30 : 120;
      const now = new Date();
      const pastDate = new Date(now.getTime() - days * 24 * 60 * 60 * 1000);
      const dateStr = pastDate.toISOString().split('T')[0];

      const result = executeQuery<{
        critical: number;
        high: number;
        medium: number;
        low: number;
        unknown: number;
      }>(
        `
      WITH recent_cves AS (
        SELECT cve_id FROM cves WHERE date_published >= ?
      ),
      cve_with_scores AS (
        SELECT 
          rc.cve_id,
          (SELECT MAX(score) FROM cve_scores cs WHERE cs.cve_id = rc.cve_id) as max_score
        FROM recent_cves rc
      )
      SELECT 
        SUM(CASE WHEN max_score >= 9.0 THEN 1 ELSE 0 END) as critical,
        SUM(CASE WHEN max_score >= 7.0 AND max_score < 9.0 THEN 1 ELSE 0 END) as high,
        SUM(CASE WHEN max_score >= 4.0 AND max_score < 7.0 THEN 1 ELSE 0 END) as medium,
        SUM(CASE WHEN max_score > 0 AND max_score < 4.0 THEN 1 ELSE 0 END) as low,
        SUM(CASE WHEN max_score IS NULL OR max_score = 0 THEN 1 ELSE 0 END) as unknown
      FROM cve_with_scores
    `,
        [dateStr]
      );

      return {
        critical: result[0]?.critical ?? 0,
        high: result[0]?.high ?? 0,
        medium: result[0]?.medium ?? 0,
        low: result[0]?.low ?? 0,
        unknown: result[0]?.unknown ?? 0
      };
    },
    [isReady, executeQuery]
  );

  // Get top 5 critical CVEs with exploit
  const getCriticalCVEsWithPOC = useCallback((): CriticalCVEWithPOC[] => {
    if (!isReady) {
      return [];
    }

    const result = executeQuery<{
      cve_id: string;
      title: string | null;
      description: string | null;
      score: number;
      date_published: string;
      exists_exploit: number;
      exists_commit: number;
      exists_nuclei: number;
      in_kev: number;
      missing_nuclei_template: number;
      epss: number | null;
      epss_percentile: number | null;
    }>(`
      SELECT
        c.cve_id,
        c.title,
        c.description,
        (SELECT MAX(score) FROM cve_scores WHERE cve_id = c.cve_id) as score,
        c.date_published,
        c.exists_exploit,
        c.exists_commit,
        c.exists_nuclei,
        c.in_kev,
        c.missing_nuclei_template,
        c.epss,
        c.epss_percentile
      FROM cves c
      WHERE c.exists_exploit = 1
        AND EXISTS (SELECT 1 FROM cve_scores cs WHERE cs.cve_id = c.cve_id AND cs.score >= 9.0)
      ORDER BY c.date_published DESC
      LIMIT 5
    `);

    return result;
  }, [isReady, executeQuery]);

  // Get CVEs by period with appropriate granularity
  // 30d = week by week, 1y = month by month, 5y = year by year
  const getCVEsByPeriod = useCallback(
    (period: ChartPeriod = '30d'): CVEsByPeriod[] => {
      if (!isReady) {
        return [];
      }

      let query: string;
      let sqlPeriod: string;

      if (period === '30d') {
        // Day by day for last 30 days
        sqlPeriod = '-30 days';
        query = `
        SELECT 
          date(date_published) as period,
          strftime('%d/%m', date_published) as label,
          COUNT(*) as total,
          SUM(CASE WHEN exists_exploit = 1 THEN 1 ELSE 0 END) as withExploit
        FROM cves
        WHERE date_published >= date('now', '${sqlPeriod}')
          AND date_published IS NOT NULL
        GROUP BY date(date_published)
        ORDER BY period ASC
      `;
      } else if (period === '1y') {
        // Month by month for last year
        sqlPeriod = '-12 months';
        query = `
        SELECT 
          strftime('%Y-%m', date_published) as period,
          strftime('%m', date_published) as label,
          COUNT(*) as total,
          SUM(CASE WHEN exists_exploit = 1 THEN 1 ELSE 0 END) as withExploit
        FROM cves
        WHERE date_published >= date('now', '${sqlPeriod}')
          AND date_published IS NOT NULL
        GROUP BY strftime('%Y-%m', date_published)
        ORDER BY period ASC
      `;
      } else {
        // Year by year for last 5 years
        sqlPeriod = '-5 years';
        query = `
        SELECT 
          strftime('%Y', date_published) as period,
          strftime('%Y', date_published) as label,
          COUNT(*) as total,
          SUM(CASE WHEN exists_exploit = 1 THEN 1 ELSE 0 END) as withExploit
        FROM cves
        WHERE date_published >= date('now', '${sqlPeriod}')
          AND date_published IS NOT NULL
        GROUP BY strftime('%Y', date_published)
        ORDER BY period ASC
      `;
      }

      const result = executeQuery<{
        period: string;
        label: string;
        total: number;
        withExploit: number;
      }>(query);

      return result;
    },
    [isReady, executeQuery]
  );

  // Get CWE trend over time with appropriate granularity
  // 30d = week by week, 1y = month by month, 5y = year by year
  const getCWETrend = useCallback(
    (
      period: ChartPeriod = '30d',
      topN: number = 5
    ): { data: CWETrendData[]; cwes: string[] } => {
      if (!isReady) {
        return { data: [], cwes: [] };
      }

      // First, get top N CWEs for the period
      let sqlPeriod: string;
      let groupBy: string;
      let periodFormat: string;
      let labelFormat: string;

      if (period === '30d') {
        sqlPeriod = '-30 days';
        groupBy = 'date(c.date_published)';
        periodFormat = 'date(c.date_published)';
        labelFormat = "strftime('%d/%m', c.date_published)";
      } else if (period === '1y') {
        sqlPeriod = '-12 months';
        groupBy = "strftime('%Y-%m', c.date_published)";
        periodFormat = "strftime('%Y-%m', c.date_published)";
        labelFormat = "strftime('%m', c.date_published)";
      } else {
        sqlPeriod = '-5 years';
        groupBy = "strftime('%Y', c.date_published)";
        periodFormat = "strftime('%Y', c.date_published)";
        labelFormat = "strftime('%Y', c.date_published)";
      }

      // Get top CWEs for the period
      const topCWEs = executeQuery<{ cwe_id: string }>(
        `
      SELECT cw.cwe_id
      FROM cve_cwes cw
      JOIN cves c ON cw.cve_id = c.cve_id
      WHERE c.date_published >= date('now', '${sqlPeriod}')
      GROUP BY cw.cwe_id
      ORDER BY COUNT(*) DESC
      LIMIT ?
    `,
        [topN]
      );

      const cwes = topCWEs.map((r) => r.cwe_id);
      if (cwes.length === 0) {
        return { data: [], cwes: [] };
      }

      // Get trend data for each period
      const trendData = executeQuery<{
        period: string;
        label: string;
        cwe_id: string;
        count: number;
      }>(
        `
      SELECT 
        ${periodFormat} as period,
        ${labelFormat} as label,
        cw.cwe_id,
        COUNT(*) as count
      FROM cve_cwes cw
      JOIN cves c ON cw.cve_id = c.cve_id
      WHERE c.date_published >= date('now', '${sqlPeriod}')
        AND c.date_published IS NOT NULL
        AND cw.cwe_id IN (${cwes.map(() => '?').join(',')})
      GROUP BY ${groupBy}, cw.cwe_id
      ORDER BY period ASC
    `,
        cwes
      );

      // Transform to grouped format
      const groupedData = new Map<string, CWETrendData>();

      trendData.forEach((row) => {
        if (!groupedData.has(row.period)) {
          const entry: CWETrendData = { period: row.period, label: row.label };
          cwes.forEach((cwe) => {
            entry[cwe] = 0;
          });
          groupedData.set(row.period, entry);
        }
        const entry = groupedData.get(row.period)!;
        entry[row.cwe_id] = row.count;
      });

      return {
        data: Array.from(groupedData.values()),
        cwes
      };
    },
    [isReady, executeQuery]
  );

  // Get top CWEs (most common vulnerability types)
  const getTopCWEs = useCallback(
    (limit: number = 5, period: ChartPeriod = '30d'): TopCWE[] => {
      if (!isReady) {
        return [];
      }

      const sqlPeriod =
        period === '30d'
          ? '-30 days'
          : period === '1y'
            ? '-12 months'
            : '-5 years';

      const result = executeQuery<{
        cwe_id: string;
        count: number;
      }>(
        `
      SELECT 
        cw.cwe_id,
        COUNT(*) as count
      FROM cve_cwes cw
      JOIN cves c ON cw.cve_id = c.cve_id
      WHERE c.date_published >= date('now', '${sqlPeriod}')
      GROUP BY cw.cwe_id
      ORDER BY count DESC
      LIMIT ?
    `,
        [limit]
      );

      return result;
    },
    [isReady, executeQuery]
  );

  return {
    getRecentStats,
    getSeverityDistribution,
    getCriticalCVEsWithPOC,
    getCVEsByPeriod,
    getCWETrend,
    getTopCWEs,
    isLoading,
    isReady
  };
}
