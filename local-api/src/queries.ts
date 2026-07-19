// Data-access layer. The SQL here is a faithful server-side port of the three
// React hooks the web app uses:
//   - src/lib/sqlite/use-cve-search.ts
//   - src/lib/sqlite/use-repository-search.ts
//   - src/lib/sqlite/use-dashboard-stats.ts
// Same params -> same SQL, so results match the UI. Additions: the tri-state
// `hasNuclei` filter and the parsed `nuclei` array in CVE detail.

import type { Db } from './db.js';
import { getSeverityFromScore } from './severity.js';
import { getCWEsFromCategory } from './cwe-data.js';
import type {
  SearchFilters,
  SortConfig,
  CVESearchResult,
  SearchResultsPage,
  RepositorySearchFilters,
  RepositorySortConfig,
  RepositorySearchResult,
  RepositorySearchResultsPage,
  NucleiTemplate
} from './types.js';

type Params = (string | number)[];

function daysAgoISO(days: number): string {
  const past = new Date(Date.now() - days * 24 * 60 * 60 * 1000);
  return past.toISOString().split('T')[0];
}

function parseJsonArray(value: unknown): unknown[] {
  if (typeof value !== 'string' || value.trim() === '') return [];
  try {
    const parsed = JSON.parse(value);
    return Array.isArray(parsed) ? parsed : [];
  } catch {
    return [];
  }
}

export class SunCveQueries {
  private readonly hasNucleiCol: boolean;

  constructor(private readonly db: Db) {
    this.hasNucleiCol = db.hasColumn('cves', 'exists_nuclei');
  }

  private repoCol(name: string, expr = 'r'): string {
    // Older snapshots may lack ecosystem/active_installs/downloads/package_url.
    return this.db.hasColumn('repositories', name)
      ? `${expr}.${name}`
      : `NULL AS ${name}`;
  }

  // ---- CVE search -------------------------------------------------------

  private buildCveWhere(filters: SearchFilters): {
    where: string;
    params: Params;
  } {
    const conditions: string[] = [];
    const params: Params = [];

    if (filters.query.trim()) {
      const term = `%${filters.query.trim()}%`;
      conditions.push(
        `(c.cve_id LIKE ? ESCAPE '\\' OR c.title LIKE ? ESCAPE '\\' OR c.description LIKE ? ESCAPE '\\')`
      );
      params.push(term, term, term);
    }

    if (filters.cvssMin > 0 || filters.cvssMax < 10) {
      conditions.push(
        `c.cve_id IN (SELECT cve_id FROM cve_scores WHERE score >= ? AND score <= ?)`
      );
      params.push(filters.cvssMin, filters.cvssMax);
    }

    if (filters.severity.length > 0) {
      const ranges: string[] = [];
      for (const sev of filters.severity) {
        switch (sev) {
          case 'critical':
            ranges.push('score >= 9.0');
            break;
          case 'high':
            ranges.push('(score >= 7.0 AND score < 9.0)');
            break;
          case 'medium':
            ranges.push('(score >= 4.0 AND score < 7.0)');
            break;
          case 'low':
            ranges.push('(score > 0 AND score < 4.0)');
            break;
          case 'none':
            ranges.push('score = 0');
            break;
        }
      }
      if (ranges.length > 0) {
        conditions.push(
          `c.cve_id IN (SELECT cve_id FROM cve_scores WHERE ${ranges.join(' OR ')})`
        );
      }
    }

    if (filters.cwes.length > 0) {
      const ph = filters.cwes.map(() => '?').join(',');
      conditions.push(
        `c.cve_id IN (SELECT cve_id FROM cve_cwes WHERE cwe_id IN (${ph}))`
      );
      params.push(...filters.cwes);
    }

    if (filters.hasExploit !== null) {
      conditions.push('c.exists_exploit = ?');
      params.push(filters.hasExploit ? 1 : 0);
    }

    if (filters.hasRepository !== null) {
      conditions.push(
        filters.hasRepository
          ? `c.cve_id IN (SELECT DISTINCT cve_id FROM cve_repositories)`
          : `c.cve_id NOT IN (SELECT DISTINCT cve_id FROM cve_repositories)`
      );
    }

    if (filters.hasCommitFix !== null) {
      conditions.push('c.exists_commit = ?');
      params.push(filters.hasCommitFix ? 1 : 0);
    }

    // Nuclei filter (new). Degrade gracefully if the column is absent.
    // exists_nuclei is only set to 1 during enrichment; CVEs without a template
    // keep it NULL (no DEFAULT, not written on insert), so the "no" case must
    // treat NULL as "no template".
    if (filters.hasNuclei !== null) {
      if (this.hasNucleiCol) {
        conditions.push(
          filters.hasNuclei
            ? 'c.exists_nuclei = 1'
            : '(c.exists_nuclei = 0 OR c.exists_nuclei IS NULL)'
        );
      } else {
        conditions.push(filters.hasNuclei ? '1 = 0' : '1 = 1');
      }
    }

    if (filters.ecosystem && this.db.hasColumn('repositories', 'ecosystem')) {
      const ecoCondition =
        filters.ecosystem === 'github'
          ? `(r.ecosystem = 'github' OR r.ecosystem IS NULL)`
          : 'r.ecosystem = ?';
      if (filters.ecosystem !== 'github') params.push(filters.ecosystem);
      conditions.push(`c.cve_id IN (
        SELECT cr.cve_id FROM cve_repositories cr
        JOIN repositories r ON cr.repository_fullpath = r.fullpath
        WHERE ${ecoCondition})`);
    }

    if (
      (filters.popDownloadsMin !== null || filters.popDownloadsMax !== null) &&
      this.db.hasColumn('repositories', 'downloads')
    ) {
      let dl = '';
      if (
        filters.popDownloadsMin !== null &&
        filters.popDownloadsMax !== null
      ) {
        dl = 'r.downloads >= ? AND r.downloads <= ?';
        params.push(filters.popDownloadsMin, filters.popDownloadsMax);
      } else if (filters.popDownloadsMin !== null) {
        dl = 'r.downloads >= ?';
        params.push(filters.popDownloadsMin);
      } else {
        dl = 'r.downloads <= ?';
        params.push(filters.popDownloadsMax!);
      }
      conditions.push(`c.cve_id IN (
        SELECT cr.cve_id FROM cve_repositories cr
        JOIN repositories r ON cr.repository_fullpath = r.fullpath
        WHERE ${dl})`);
    }

    if (filters.languages.length > 0) {
      const ph = filters.languages.map(() => '?').join(',');
      conditions.push(`c.cve_id IN (
        SELECT cr.cve_id FROM cve_repositories cr
        JOIN repositories r ON cr.repository_fullpath = r.fullpath
        WHERE r.languageMain IN (${ph}))`);
      params.push(...filters.languages);
    }

    if (filters.starsMin !== null || filters.starsMax !== null) {
      let cond = '';
      if (filters.starsMin !== null && filters.starsMax !== null) {
        cond = 'r.stars >= ? AND r.stars <= ?';
        params.push(filters.starsMin, filters.starsMax);
      } else if (filters.starsMin !== null) {
        cond = 'r.stars >= ?';
        params.push(filters.starsMin);
      } else {
        cond = 'r.stars <= ?';
        params.push(filters.starsMax!);
      }
      conditions.push(`c.cve_id IN (
        SELECT cr.cve_id FROM cve_repositories cr
        JOIN repositories r ON cr.repository_fullpath = r.fullpath
        WHERE ${cond})`);
    }

    if (filters.repoSizeMin !== null || filters.repoSizeMax !== null) {
      let cond = '';
      if (filters.repoSizeMin !== null && filters.repoSizeMax !== null) {
        cond = 'r.size >= ? AND r.size <= ?';
        params.push(filters.repoSizeMin, filters.repoSizeMax);
      } else if (filters.repoSizeMin !== null) {
        cond = 'r.size >= ?';
        params.push(filters.repoSizeMin);
      } else {
        cond = 'r.size <= ?';
        params.push(filters.repoSizeMax!);
      }
      conditions.push(`c.cve_id IN (
        SELECT cr.cve_id FROM cve_repositories cr
        JOIN repositories r ON cr.repository_fullpath = r.fullpath
        WHERE ${cond})`);
    }

    if (filters.datePeriod && filters.datePeriod !== 'all') {
      if (filters.datePeriod === 'custom' && filters.customDate) {
        const cd = filters.customDate;
        if (cd.length === 4) {
          conditions.push(`strftime('%Y', c.date_published) = ?`);
          params.push(cd);
        } else if (cd.length === 7) {
          conditions.push(`strftime('%Y-%m', c.date_published) = ?`);
          params.push(cd);
        } else {
          conditions.push(`date(c.date_published) = ?`);
          params.push(cd);
        }
      } else if (filters.datePeriod === 'today') {
        conditions.push(`date(c.date_published) = ?`);
        params.push(new Date().toISOString().split('T')[0]);
      } else {
        const map: Record<string, number> = {
          '7d': 7,
          '30d': 30,
          '120d': 120,
          '1y': 365,
          '5y': 365 * 5
        };
        conditions.push(`c.date_published >= ?`);
        params.push(daysAgoISO(map[filters.datePeriod] ?? 0));
      }
    }

    if (filters.repository) {
      conditions.push(
        `c.cve_id IN (SELECT cve_id FROM cve_repositories WHERE repository_fullpath = ?)`
      );
      params.push(filters.repository);
    }

    if (filters.cweCategory) {
      const cat = getCWEsFromCategory(filters.cweCategory);
      if (cat.length > 0) {
        const ph = cat.map(() => '?').join(',');
        conditions.push(
          `c.cve_id IN (SELECT cve_id FROM cve_cwes WHERE cwe_id IN (${ph}))`
        );
        params.push(...cat);
      }
    }

    const where =
      conditions.length > 0 ? `WHERE ${conditions.join(' AND ')}` : '';
    return { where, params };
  }

  searchCVEs(
    filters: SearchFilters,
    sort: SortConfig,
    page = 1,
    pageSize = 50
  ): SearchResultsPage {
    const { where, params } = this.buildCveWhere(filters);
    const offset = (page - 1) * pageSize;

    let orderBy = 'c.date_published DESC';
    switch (sort.field) {
      case 'cve_id':
        orderBy = `c.cve_id ${sort.order.toUpperCase()}`;
        break;
      case 'date_published':
        orderBy = `c.date_published ${sort.order.toUpperCase()} NULLS LAST`;
        break;
      case 'date_updated':
        orderBy = `c.date_updated ${sort.order.toUpperCase()} NULLS LAST`;
        break;
      case 'score':
        orderBy = `s.max_score ${sort.order.toUpperCase()} NULLS LAST`;
        break;
      case 'stars':
        orderBy = `ra.repo_stars ${sort.order.toUpperCase()} NULLS LAST`;
        break;
    }

    const nucleiSelect = this.hasNucleiCol
      ? 'c.exists_nuclei'
      : '0 AS exists_nuclei';

    const sql = `
      WITH
      score_agg AS (
        SELECT cve_id, MAX(score) as max_score FROM cve_scores GROUP BY cve_id
      ),
      cwe_agg AS (
        SELECT cve_id, GROUP_CONCAT(cwe_id, ', ') as cwe_list
        FROM (SELECT DISTINCT cve_id, cwe_id FROM cve_cwes)
        GROUP BY cve_id
      ),
      affected_agg AS (
        SELECT cve_id,
          GROUP_CONCAT(DISTINCT vendor) as vendor_list,
          GROUP_CONCAT(DISTINCT product) as product_list
        FROM cve_affected GROUP BY cve_id
      ),
      repo_agg AS (
        SELECT
          cr.cve_id,
          COUNT(*) as repo_count,
          MAX(r.stars) as repo_stars,
          (SELECT r2.fullpath FROM cve_repositories cr2
             JOIN repositories r2 ON cr2.repository_fullpath = r2.fullpath
             WHERE cr2.cve_id = cr.cve_id ORDER BY r2.stars DESC LIMIT 1) as repo_fullpath,
          (SELECT r2.languageMain FROM cve_repositories cr2
             JOIN repositories r2 ON cr2.repository_fullpath = r2.fullpath
             WHERE cr2.cve_id = cr.cve_id ORDER BY r2.stars DESC LIMIT 1) as repo_language
        FROM cve_repositories cr
        JOIN repositories r ON cr.repository_fullpath = r.fullpath
        GROUP BY cr.cve_id
      ),
      filtered_cves AS (SELECT c.cve_id FROM cves c ${where}),
      total_count AS (SELECT COUNT(*) as total FROM filtered_cves)
      SELECT
        c.cve_id, c.title, c.description, c.date_published, c.date_updated,
        c.exists_exploit, c.exists_commit, ${nucleiSelect},
        COALESCE(s.max_score, 0) as max_score,
        cw.cwe_list, a.vendor_list, a.product_list,
        COALESCE(ra.repo_count, 0) as repo_count,
        ra.repo_fullpath, ra.repo_stars, ra.repo_language,
        tc.total
      FROM cves c
      INNER JOIN filtered_cves fc ON fc.cve_id = c.cve_id
      CROSS JOIN total_count tc
      LEFT JOIN score_agg s ON s.cve_id = c.cve_id
      LEFT JOIN cwe_agg cw ON cw.cve_id = c.cve_id
      LEFT JOIN affected_agg a ON a.cve_id = c.cve_id
      LEFT JOIN repo_agg ra ON ra.cve_id = c.cve_id
      ORDER BY ${orderBy}
      LIMIT ? OFFSET ?
    `;

    const rows = this.db.all<Record<string, unknown>>(sql, [
      ...params,
      pageSize,
      offset
    ]);
    const total = rows.length > 0 ? Number(rows[0].total ?? 0) : 0;

    const results: CVESearchResult[] = rows.map((row) => {
      const max = Number(row.max_score ?? 0);
      return {
        cve_id: row.cve_id as string,
        title: (row.title as string) ?? null,
        description: (row.description as string) ?? null,
        date_published: (row.date_published as string) ?? null,
        date_updated: (row.date_updated as string) ?? null,
        exists_exploit: Boolean(row.exists_exploit),
        exists_commit: Boolean(row.exists_commit),
        exists_nuclei: Boolean(row.exists_nuclei),
        max_score: max,
        severity: getSeverityFromScore(max),
        cwe_list: (row.cwe_list as string) ?? null,
        vendor_list: (row.vendor_list as string) ?? null,
        product_list: (row.product_list as string) ?? null,
        repo_count: Number(row.repo_count ?? 0),
        repo_fullpath: (row.repo_fullpath as string) ?? null,
        repo_stars: row.repo_stars == null ? null : Number(row.repo_stars),
        repo_language: (row.repo_language as string) ?? null
      };
    });

    return {
      results,
      total,
      page,
      pageSize,
      totalPages: Math.ceil(total / pageSize)
    };
  }

  getCVEDetails(cveId: string) {
    const rows = this.db.all<Record<string, unknown>>(
      `SELECT c.*,
        (SELECT GROUP_CONCAT(cwe_id) FROM cve_cwes WHERE cve_id = c.cve_id) as cwes_json,
        (SELECT MAX(score) FROM cve_scores WHERE cve_id = c.cve_id) as max_score
       FROM cves c WHERE c.cve_id = ?`,
      [cveId]
    );
    if (rows.length === 0) return null;
    const cve = rows[0];

    const scores = this.db.all(
      `SELECT * FROM cve_scores WHERE cve_id = ? ORDER BY version DESC`,
      [cveId]
    );
    const affected = this.db.all(
      `SELECT DISTINCT vendor, product FROM cve_affected WHERE cve_id = ? LIMIT 100`,
      [cveId]
    );

    const repoSelect = [
      'r.fullpath',
      'r.stars',
      'r.languageMain',
      'r.size',
      'r.name',
      this.repoCol('ecosystem'),
      this.repoCol('active_installs'),
      this.repoCol('downloads'),
      this.repoCol('package_url')
    ].join(', ');
    const repositories = this.db.all(
      `SELECT ${repoSelect}
       FROM cve_repositories cr
       JOIN repositories r ON cr.repository_fullpath = r.fullpath
       WHERE cr.cve_id = ? ORDER BY r.stars DESC LIMIT 50`,
      [cveId]
    );

    const cwesStr = cve.cwes_json as string | null;
    const cwes = cwesStr ? cwesStr.split(',') : [];
    const max = Number(cve.max_score ?? 0);

    const nuclei = parseJsonArray(cve.list_nuclei) as NucleiTemplate[];

    return {
      cve_id: cve.cve_id,
      state: cve.state ?? null,
      date_published: cve.date_published ?? null,
      date_updated: cve.date_updated ?? null,
      date_reserved: cve.date_reserved ?? null,
      title: cve.title ?? null,
      description: cve.description ?? null,
      exists_exploit: Boolean(cve.exists_exploit),
      exists_commit: Boolean(cve.exists_commit),
      exists_nuclei: Boolean(cve.exists_nuclei),
      max_score: max,
      severity: getSeverityFromScore(max),
      cwes,
      scores,
      affected,
      repositories,
      references: parseJsonArray(cve.list_references),
      exploits: parseJsonArray(cve.list_exploit),
      commits: parseJsonArray(cve.list_commit),
      nuclei
    };
  }

  getFilterOptions() {
    const cwes = this.db.all<{ cwe_id: string; count: number }>(
      `SELECT cwe_id, COUNT(*) as count FROM cve_cwes
       GROUP BY cwe_id ORDER BY count DESC LIMIT 100`
    );
    const languages = this.db.all<{ languageMain: string; count: number }>(
      `SELECT languageMain, COUNT(*) as count FROM repositories
       WHERE languageMain IS NOT NULL AND languageMain != ''
       GROUP BY languageMain ORDER BY count DESC LIMIT 50`
    );
    return { cwes, languages };
  }

  getStats() {
    const s = this.db.get<{
      totalCVEs: number;
      withExploit: number;
      withCommit: number;
      totalRepos: number;
      inKev: number;
    }>(
      `SELECT
        (SELECT COUNT(*) FROM cves) as totalCVEs,
        (SELECT COUNT(*) FROM cves WHERE exists_exploit = 1) as withExploit,
        (SELECT COUNT(*) FROM cves WHERE exists_commit = 1) as withCommit,
        (SELECT COUNT(*) FROM cves WHERE in_kev = 1) as inKev,
        (SELECT COUNT(*) FROM repositories) as totalRepos`
    );
    return {
      totalCVEs: s?.totalCVEs ?? 0,
      totalRepos: s?.totalRepos ?? 0,
      withExploit: s?.withExploit ?? 0,
      withCommit: s?.withCommit ?? 0,
      inKev: s?.inKev ?? 0
    };
  }

  getFilteredStats(filters: SearchFilters) {
    const { where, params } = this.buildCveWhere(filters);
    const s = this.db.get<{
      totalCVEs: number;
      withExploit: number;
      withCommit: number;
      totalRepos: number;
      inKev: number;
    }>(
      `WITH filtered_cves AS (
        SELECT c.cve_id, c.exists_exploit, c.exists_commit, c.in_kev FROM cves c ${where}
      )
      SELECT
        COUNT(*) as totalCVEs,
        SUM(CASE WHEN exists_exploit = 1 THEN 1 ELSE 0 END) as withExploit,
        SUM(CASE WHEN exists_commit = 1 THEN 1 ELSE 0 END) as withCommit,
        SUM(CASE WHEN in_kev = 1 THEN 1 ELSE 0 END) as inKev,
        (SELECT COUNT(DISTINCT r.fullpath)
           FROM filtered_cves fc
           JOIN cve_repositories cr ON cr.cve_id = fc.cve_id
           JOIN repositories r ON cr.repository_fullpath = r.fullpath) as totalRepos
      FROM filtered_cves`,
      params
    );
    return {
      totalCVEs: s?.totalCVEs ?? 0,
      totalRepos: s?.totalRepos ?? 0,
      withExploit: s?.withExploit ?? 0,
      withCommit: s?.withCommit ?? 0,
      inKev: s?.inKev ?? 0
    };
  }

  // ---- Repository search ------------------------------------------------

  private buildRepoWhere(filters: RepositorySearchFilters): {
    where: string;
    params: Params;
  } {
    const conditions: string[] = [];
    const params: Params = [];

    if (filters.query.trim()) {
      const term = `%${filters.query.trim()}%`;
      conditions.push(
        `(r.fullpath LIKE ? ESCAPE '\\' OR r.name LIKE ? ESCAPE '\\')`
      );
      params.push(term, term);
    }

    if (filters.languages.length > 0) {
      const ph = filters.languages.map(() => '?').join(',');
      conditions.push(`r.languageMain IN (${ph})`);
      params.push(...filters.languages);
    }

    if (filters.starsMin !== null) {
      conditions.push('r.stars >= ?');
      params.push(filters.starsMin);
    }
    if (filters.starsMax !== null) {
      conditions.push('r.stars <= ?');
      params.push(filters.starsMax);
    }
    if (filters.sizeMin !== null) {
      conditions.push('r.size >= ?');
      params.push(filters.sizeMin);
    }
    if (filters.sizeMax !== null) {
      conditions.push('r.size <= ?');
      params.push(filters.sizeMax);
    }

    if (filters.hasCVEs !== null) {
      conditions.push(
        filters.hasCVEs
          ? `r.fullpath IN (SELECT DISTINCT repository_fullpath FROM cve_repositories)`
          : `r.fullpath NOT IN (SELECT DISTINCT repository_fullpath FROM cve_repositories)`
      );
    }

    if (filters.hasCommitFix !== null) {
      conditions.push(
        filters.hasCommitFix
          ? 'r.commits_fix_count > 0'
          : '(r.commits_fix_count IS NULL OR r.commits_fix_count = 0)'
      );
    }

    if (filters.ecosystem && this.db.hasColumn('repositories', 'ecosystem')) {
      if (filters.ecosystem === 'github') {
        conditions.push(`(r.ecosystem = 'github' OR r.ecosystem IS NULL)`);
      } else {
        conditions.push('r.ecosystem = ?');
        params.push(filters.ecosystem);
      }
    }

    const installCond =
      filters.activeInstallsMin !== null &&
      this.db.hasColumn('repositories', 'active_installs')
        ? 'r.active_installs >= ?'
        : null;
    const downloadCond =
      filters.downloadsMin !== null &&
      this.db.hasColumn('repositories', 'downloads')
        ? 'r.downloads >= ?'
        : null;
    if (installCond && downloadCond) {
      conditions.push(`(${installCond} OR ${downloadCond})`);
      params.push(filters.activeInstallsMin!, filters.downloadsMin!);
    } else if (installCond) {
      conditions.push(installCond);
      params.push(filters.activeInstallsMin!);
    } else if (downloadCond) {
      conditions.push(downloadCond);
      params.push(filters.downloadsMin!);
    }

    const where =
      conditions.length > 0 ? `WHERE ${conditions.join(' AND ')}` : '';
    return { where, params };
  }

  searchRepositories(
    filters: RepositorySearchFilters,
    sort: RepositorySortConfig,
    page = 1,
    pageSize = 50
  ): RepositorySearchResultsPage {
    const { where, params } = this.buildRepoWhere(filters);
    const offset = (page - 1) * pageSize;

    let orderBy = 'r.stars DESC NULLS LAST';
    switch (sort.field) {
      case 'fullpath':
        orderBy = `r.fullpath ${sort.order.toUpperCase()}`;
        break;
      case 'name':
        orderBy = `r.name ${sort.order.toUpperCase()} NULLS LAST`;
        break;
      case 'stars':
        orderBy = `r.stars ${sort.order.toUpperCase()} NULLS LAST`;
        break;
      case 'size':
        orderBy = `r.size ${sort.order.toUpperCase()} NULLS LAST`;
        break;
      case 'cve_count':
        orderBy = `cve_count ${sort.order.toUpperCase()}`;
        break;
      case 'commits_fix_count':
        orderBy = `r.commits_fix_count ${sort.order.toUpperCase()} NULLS LAST`;
        break;
      case 'created_repository':
        orderBy = `r.created_repository ${sort.order.toUpperCase()} NULLS LAST`;
        break;
      case 'updated_repository':
        orderBy = `r.updated_repository ${sort.order.toUpperCase()} NULLS LAST`;
        break;
      case 'active_installs':
        orderBy = this.db.hasColumn('repositories', 'active_installs')
          ? `r.active_installs ${sort.order.toUpperCase()} NULLS LAST`
          : orderBy;
        break;
      case 'downloads':
        orderBy = this.db.hasColumn('repositories', 'downloads')
          ? `r.downloads ${sort.order.toUpperCase()} NULLS LAST`
          : orderBy;
        break;
    }

    const sql = `
      WITH
      cve_counts AS (
        SELECT repository_fullpath, COUNT(*) as cve_count
        FROM cve_repositories GROUP BY repository_fullpath
      ),
      filtered_repos AS (SELECT r.fullpath FROM repositories r ${where}),
      total_count AS (SELECT COUNT(*) as total FROM filtered_repos)
      SELECT
        r.fullpath, r.name, r.stars, r.size, r.languageMain,
        COALESCE(cc.cve_count, 0) as cve_count,
        r.commits_fix_count, r.created_repository, r.updated_repository,
        ${this.repoCol('ecosystem')}, ${this.repoCol('active_installs')},
        ${this.repoCol('downloads')}, ${this.repoCol('package_url')},
        tc.total
      FROM repositories r
      INNER JOIN filtered_repos fr ON fr.fullpath = r.fullpath
      CROSS JOIN total_count tc
      LEFT JOIN cve_counts cc ON cc.repository_fullpath = r.fullpath
      ORDER BY ${orderBy}
      LIMIT ? OFFSET ?
    `;

    const rows = this.db.all<Record<string, unknown>>(sql, [
      ...params,
      pageSize,
      offset
    ]);
    const total = rows.length > 0 ? Number(rows[0].total ?? 0) : 0;

    const results: RepositorySearchResult[] = rows.map((row) => ({
      fullpath: row.fullpath as string,
      name: (row.name as string) ?? null,
      stars: row.stars == null ? null : Number(row.stars),
      size: row.size == null ? null : Number(row.size),
      languageMain: (row.languageMain as string) ?? null,
      cve_count: Number(row.cve_count ?? 0),
      commits_fix_count:
        row.commits_fix_count == null ? null : Number(row.commits_fix_count),
      created_repository: (row.created_repository as string) ?? null,
      updated_repository: (row.updated_repository as string) ?? null,
      ecosystem: (row.ecosystem as string) ?? null,
      active_installs:
        row.active_installs == null ? null : Number(row.active_installs),
      downloads: row.downloads == null ? null : Number(row.downloads),
      package_url: (row.package_url as string) ?? null
    }));

    return {
      results,
      total,
      page,
      pageSize,
      totalPages: Math.ceil(total / pageSize)
    };
  }

  getRepositoryDetails(fullpath: string) {
    const rows = this.db.all<Record<string, unknown>>(
      `SELECT * FROM repositories WHERE fullpath = ?`,
      [fullpath]
    );
    if (rows.length === 0) return null;
    const count = this.db.get<{ count: number }>(
      `SELECT COUNT(*) as count FROM cve_repositories WHERE repository_fullpath = ?`,
      [fullpath]
    );
    return { ...rows[0], cve_count: count?.count ?? 0 };
  }

  getRepositoryCVEs(fullpath: string, page = 1, pageSize = 20) {
    const offset = (page - 1) * pageSize;
    const count = this.db.get<{ count: number }>(
      `SELECT COUNT(*) as count FROM cve_repositories WHERE repository_fullpath = ?`,
      [fullpath]
    );
    const total = count?.count ?? 0;

    const rows = this.db.all<{
      cve_id: string;
      title: string | null;
      description: string | null;
      date_published: string | null;
      date_updated: string | null;
      exists_exploit: number;
      exists_commit: number;
      max_score: number | null;
      relation_type: string | null;
    }>(
      `SELECT c.cve_id, c.title, c.description, c.date_published, c.date_updated,
        c.exists_exploit, c.exists_commit,
        (SELECT MAX(score) FROM cve_scores WHERE cve_id = c.cve_id) as max_score,
        cr.relation_type
      FROM cve_repositories cr
      JOIN cves c ON cr.cve_id = c.cve_id
      WHERE cr.repository_fullpath = ?
      ORDER BY c.date_published DESC LIMIT ? OFFSET ?`,
      [fullpath, pageSize, offset]
    );

    const cves = rows.map((cve) => ({
      cve_id: cve.cve_id,
      title: cve.title,
      description: cve.description,
      date_published: cve.date_published,
      date_updated: cve.date_updated,
      exists_exploit: Boolean(cve.exists_exploit),
      exists_commit: Boolean(cve.exists_commit),
      max_score: cve.max_score,
      severity: getSeverityFromScore(cve.max_score ?? 0),
      relation_type: cve.relation_type
    }));

    return { cves, total, totalPages: Math.ceil(total / pageSize) };
  }

  getRepoStats() {
    const s = this.db.get<{
      totalRepos: number;
      withCVEs: number;
      withCommitFix: number;
    }>(
      `SELECT
        (SELECT COUNT(*) FROM repositories) as totalRepos,
        (SELECT COUNT(DISTINCT repository_fullpath) FROM cve_repositories) as withCVEs,
        (SELECT COUNT(*) FROM repositories WHERE commits_fix_count > 0) as withCommitFix`
    );
    return {
      totalRepos: s?.totalRepos ?? 0,
      withCVEs: s?.withCVEs ?? 0,
      withCommitFix: s?.withCommitFix ?? 0
    };
  }

  getRepoFilteredStats(filters: RepositorySearchFilters) {
    const { where, params } = this.buildRepoWhere(filters);
    const s = this.db.get<{
      totalRepos: number;
      withCVEs: number;
      withCommitFix: number;
    }>(
      `WITH filtered_repos AS (
        SELECT r.fullpath, r.commits_fix_count FROM repositories r ${where}
      )
      SELECT
        COUNT(*) as totalRepos,
        (SELECT COUNT(DISTINCT fr.fullpath)
           FROM filtered_repos fr
           JOIN cve_repositories cr ON cr.repository_fullpath = fr.fullpath) as withCVEs,
        SUM(CASE WHEN commits_fix_count > 0 THEN 1 ELSE 0 END) as withCommitFix
      FROM filtered_repos`,
      params
    );
    return {
      totalRepos: s?.totalRepos ?? 0,
      withCVEs: s?.withCVEs ?? 0,
      withCommitFix: s?.withCommitFix ?? 0
    };
  }

  getRepoFilterOptions() {
    const languages = this.db.all<{ languageMain: string; count: number }>(
      `SELECT languageMain, COUNT(*) as count FROM repositories
       WHERE languageMain IS NOT NULL AND languageMain != ''
       GROUP BY languageMain ORDER BY count DESC LIMIT 50`
    );
    return { languages };
  }

  // ---- Dashboard / analytics -------------------------------------------

  getRecentStats() {
    const d = daysAgoISO(30);
    const r = this.db.get<{
      newCVEs: number;
      newWithExploit: number;
      newWithFix: number;
      newCriticalCVEs: number;
    }>(
      `SELECT
        (SELECT COUNT(*) FROM cves WHERE date_published >= ?) as newCVEs,
        (SELECT COUNT(*) FROM cves WHERE date_published >= ? AND exists_exploit = 1) as newWithExploit,
        (SELECT COUNT(*) FROM cves WHERE date_published >= ? AND exists_commit = 1) as newWithFix,
        (SELECT COUNT(*) FROM cves c WHERE c.date_published >= ?
          AND EXISTS (SELECT 1 FROM cve_scores cs WHERE cs.cve_id = c.cve_id AND cs.score >= 9.0)) as newCriticalCVEs`,
      [d, d, d, d]
    );
    return {
      newCVEs: r?.newCVEs ?? 0,
      newCriticalCVEs: r?.newCriticalCVEs ?? 0,
      newWithExploit: r?.newWithExploit ?? 0,
      newWithFix: r?.newWithFix ?? 0
    };
  }

  getSeverityDistribution(period: '7d' | '30d' | '120d' = '30d') {
    const days = period === '7d' ? 7 : period === '30d' ? 30 : 120;
    const d = daysAgoISO(days);
    const r = this.db.get<{
      critical: number;
      high: number;
      medium: number;
      low: number;
      unknown: number;
    }>(
      `WITH recent_cves AS (SELECT cve_id FROM cves WHERE date_published >= ?),
       cve_with_scores AS (
         SELECT rc.cve_id,
           (SELECT MAX(score) FROM cve_scores cs WHERE cs.cve_id = rc.cve_id) as max_score
         FROM recent_cves rc
       )
       SELECT
         SUM(CASE WHEN max_score >= 9.0 THEN 1 ELSE 0 END) as critical,
         SUM(CASE WHEN max_score >= 7.0 AND max_score < 9.0 THEN 1 ELSE 0 END) as high,
         SUM(CASE WHEN max_score >= 4.0 AND max_score < 7.0 THEN 1 ELSE 0 END) as medium,
         SUM(CASE WHEN max_score > 0 AND max_score < 4.0 THEN 1 ELSE 0 END) as low,
         SUM(CASE WHEN max_score IS NULL OR max_score = 0 THEN 1 ELSE 0 END) as unknown
       FROM cve_with_scores`,
      [d]
    );
    return {
      critical: r?.critical ?? 0,
      high: r?.high ?? 0,
      medium: r?.medium ?? 0,
      low: r?.low ?? 0,
      unknown: r?.unknown ?? 0
    };
  }

  getCriticalCVEsWithPOC() {
    return this.db.all(
      `SELECT c.cve_id, c.title, c.description,
        (SELECT MAX(score) FROM cve_scores WHERE cve_id = c.cve_id) as score,
        c.date_published,
        c.exists_exploit, c.exists_commit, c.exists_nuclei,
        c.in_kev, c.missing_nuclei_template
      FROM cves c
      WHERE c.exists_exploit = 1
        AND EXISTS (SELECT 1 FROM cve_scores cs WHERE cs.cve_id = c.cve_id AND cs.score >= 9.0)
      ORDER BY c.date_published DESC LIMIT 5`
    );
  }

  getCVEsByPeriod(period: '30d' | '1y' | '5y' = '30d') {
    let sql: string;
    if (period === '30d') {
      sql = `SELECT date(date_published) as period,
          strftime('%d/%m', date_published) as label,
          COUNT(*) as total,
          SUM(CASE WHEN exists_exploit = 1 THEN 1 ELSE 0 END) as withExploit
        FROM cves
        WHERE date_published >= date('now', '-30 days') AND date_published IS NOT NULL
        GROUP BY date(date_published) ORDER BY period ASC`;
    } else if (period === '1y') {
      sql = `SELECT strftime('%Y-%m', date_published) as period,
          strftime('%m', date_published) as label,
          COUNT(*) as total,
          SUM(CASE WHEN exists_exploit = 1 THEN 1 ELSE 0 END) as withExploit
        FROM cves
        WHERE date_published >= date('now', '-12 months') AND date_published IS NOT NULL
        GROUP BY strftime('%Y-%m', date_published) ORDER BY period ASC`;
    } else {
      sql = `SELECT strftime('%Y', date_published) as period,
          strftime('%Y', date_published) as label,
          COUNT(*) as total,
          SUM(CASE WHEN exists_exploit = 1 THEN 1 ELSE 0 END) as withExploit
        FROM cves
        WHERE date_published >= date('now', '-5 years') AND date_published IS NOT NULL
        GROUP BY strftime('%Y', date_published) ORDER BY period ASC`;
    }
    return this.db.all(sql);
  }

  getCWETrend(period: '30d' | '1y' | '5y' = '30d', topN = 5) {
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

    const topCWEs = this.db.all<{ cwe_id: string }>(
      `SELECT cw.cwe_id FROM cve_cwes cw
       JOIN cves c ON cw.cve_id = c.cve_id
       WHERE c.date_published >= date('now', '${sqlPeriod}')
       GROUP BY cw.cwe_id ORDER BY COUNT(*) DESC LIMIT ?`,
      [topN]
    );
    const cwes = topCWEs.map((r) => r.cwe_id);
    if (cwes.length === 0) return { data: [], cwes: [] };

    const trend = this.db.all<{
      period: string;
      label: string;
      cwe_id: string;
      count: number;
    }>(
      `SELECT ${periodFormat} as period, ${labelFormat} as label, cw.cwe_id, COUNT(*) as count
       FROM cve_cwes cw JOIN cves c ON cw.cve_id = c.cve_id
       WHERE c.date_published >= date('now', '${sqlPeriod}')
         AND c.date_published IS NOT NULL
         AND cw.cwe_id IN (${cwes.map(() => '?').join(',')})
       GROUP BY ${groupBy}, cw.cwe_id ORDER BY period ASC`,
      cwes
    );

    const grouped = new Map<string, Record<string, string | number>>();
    for (const row of trend) {
      if (!grouped.has(row.period)) {
        const entry: Record<string, string | number> = {
          period: row.period,
          label: row.label
        };
        for (const cwe of cwes) entry[cwe] = 0;
        grouped.set(row.period, entry);
      }
      grouped.get(row.period)![row.cwe_id] = row.count;
    }
    return { data: Array.from(grouped.values()), cwes };
  }

  getTopCWEs(limit = 5, period: '30d' | '1y' | '5y' = '30d') {
    const sqlPeriod =
      period === '30d'
        ? '-30 days'
        : period === '1y'
          ? '-12 months'
          : '-5 years';
    return this.db.all<{ cwe_id: string; count: number }>(
      `SELECT cw.cwe_id, COUNT(*) as count FROM cve_cwes cw
       JOIN cves c ON cw.cve_id = c.cve_id
       WHERE c.date_published >= date('now', '${sqlPeriod}')
       GROUP BY cw.cwe_id ORDER BY count DESC LIMIT ?`,
      [limit]
    );
  }

  health() {
    const count = this.db.get<{ n: number }>(`SELECT COUNT(*) as n FROM cves`);
    return {
      status: 'ok',
      db_path: this.db.path,
      total_cves: count?.n ?? 0,
      has_nuclei_column: this.hasNucleiCol
    };
  }
}
