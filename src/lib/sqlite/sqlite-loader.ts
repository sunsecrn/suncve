/**
 * SQLite WASM Loader
 * Based on https://dsonbaker.github.io/sqliteWASMGithub/
 *
 * Utilitários para baixar, descomprimir e abrir um SQLite grande no navegador
 * usando sql.js (WASM). Mantém o arquivo no OPFS quando disponível.
 */
import { withBasePath } from '@/lib/base-path';

const VERSION_KEY = 'sqlite.version';
const FILE_KEY = 'sqlite.file';
const SOURCE_KEY = 'sqlite.source';
const SQLJS_CDN = 'https://cdnjs.cloudflare.com/ajax/libs/sql.js/1.10.2';

// eslint-disable-next-line @typescript-eslint/no-explicit-any
type SqlJsStatic = any;
// eslint-disable-next-line @typescript-eslint/no-explicit-any
type SqlJsDatabase = any;

export interface ManifestSource {
  url: string;
  encoding?: string;
  size?: number;
  sha256?: string;
}

export interface Manifest {
  version: string;
  sources: {
    gzip?: ManifestSource;
    brotli?: ManifestSource;
    br?: ManifestSource;
  };
}

export interface DatabaseStore {
  location: 'opfs' | 'memory';
  handle?: FileSystemFileHandle;
  buffer?: Uint8Array;
  source: ManifestSource & { encoding: string };
  version: string;
}

export interface DatabaseContext {
  db: SqlJsDatabase;
  SQL: SqlJsStatic;
  location: 'opfs' | 'memory';
  version: string;
  source: ManifestSource & { encoding: string };
}

export interface LoadOptions {
  preferBrotli?: boolean;
  fileName?: string;
  force?: boolean;
  signal?: AbortSignal;
  wasmUrl?: string;
  onProgress?: (progress: number) => void;
}

let sqlJsPromise: Promise<SqlJsStatic> | null = null;

/**
 * Carrega o manifest JSON com informações do banco
 */
export async function loadManifest(url: string): Promise<Manifest> {
  const res = await fetch(url, { cache: 'no-cache' });
  if (!res.ok)
    throw new Error(`Falha ao baixar manifest ${url}: ${res.status}`);
  const manifest = (await res.json()) as Manifest;
  const sources = manifest?.sources;

  // Resolve source URLs: absolute URLs (http/https) are kept as-is,
  // relative URLs get the site base path prepended.
  const resolveUrl = (u: string) =>
    /^https?:\/\//.test(u) ? u : withBasePath(u);

  if (sources?.gzip?.url) {
    sources.gzip.url = resolveUrl(sources.gzip.url);
  }
  if (sources?.brotli?.url) {
    sources.brotli.url = resolveUrl(sources.brotli.url);
  }
  if (sources?.br?.url) {
    sources.br.url = resolveUrl(sources.br.url);
  }
  return manifest;
}

/**
 * Garante que o sql.js está carregado (via CDN)
 */
async function ensureSqlJs(wasmUrl?: string): Promise<SqlJsStatic> {
  if (sqlJsPromise) return sqlJsPromise;

  const scriptUrl = `${SQLJS_CDN}/sql-wasm.js`;
  sqlJsPromise = new Promise((resolve, reject) => {
    // Check if already loaded
    if (
      typeof window !== 'undefined' &&
      (window as unknown as { initSqlJs?: unknown }).initSqlJs
    ) {
      const init = (
        window as unknown as {
          initSqlJs: (config: {
            locateFile: (file: string) => string;
          }) => Promise<SqlJsStatic>;
        }
      ).initSqlJs;
      init({
        locateFile: (file: string) => wasmUrl ?? `${SQLJS_CDN}/${file}`
      })
        .then(resolve)
        .catch(reject);
      return;
    }

    const tag = document.createElement('script');
    tag.src = scriptUrl;
    tag.onload = async () => {
      try {
        const init = (
          window as unknown as {
            initSqlJs?: (config: {
              locateFile: (file: string) => string;
            }) => Promise<SqlJsStatic>;
          }
        ).initSqlJs;
        if (!init) throw new Error('initSqlJs não encontrado');
        const SQL = await init({
          locateFile: (file: string) => wasmUrl ?? `${SQLJS_CDN}/${file}`
        });
        resolve(SQL);
      } catch (err) {
        reject(err);
      }
    };
    tag.onerror = () => reject(new Error(`Erro ao carregar ${scriptUrl}`));
    document.head.appendChild(tag);
  });

  return sqlJsPromise;
}

/**
 * Verifica se o navegador suporta DecompressionStream para o encoding
 */
function supportsDecompression(encoding: string): boolean {
  if (typeof DecompressionStream === 'undefined') return false;
  // Brotli ('br') não é suportado nativamente pelo DecompressionStream
  if (encoding === 'br' || encoding === 'brotli') return false;
  try {
    new DecompressionStream(encoding as CompressionFormat);
    return true;
  } catch {
    return false;
  }
}

/**
 * Obtém handle de arquivo no OPFS
 */
async function getOpfsFileHandle(
  fileName: string,
  create = true
): Promise<FileSystemFileHandle | null> {
  if (!navigator.storage?.getDirectory) return null;
  try {
    const root = await navigator.storage.getDirectory();
    return root.getFileHandle(fileName, { create });
  } catch {
    return null;
  }
}

/**
 * Verifica se arquivo existe no OPFS
 */
async function fileExistsInOpfs(fileName: string): Promise<{
  exists: boolean;
  size: number;
  handle: FileSystemFileHandle | null;
}> {
  try {
    const handle = await getOpfsFileHandle(fileName, false);
    if (!handle) return { exists: false, size: 0, handle: null };
    const file = await handle.getFile();
    return { exists: true, size: file.size, handle };
  } catch {
    return { exists: false, size: 0, handle: null };
  }
}

/**
 * Escolhe a melhor fonte do manifest
 */
function pickSource(
  manifest: Manifest,
  preferBrotli = true
): ManifestSource & { encoding: string } {
  const { sources } = manifest || {};
  if (!sources) throw new Error('Manifest sem sources');

  const brotli = sources.brotli || sources.br;
  const gzip = sources.gzip;

  if (preferBrotli && brotli?.url) {
    const encoding = brotli.encoding || 'br';
    if (!supportsDecompression(encoding)) {
      if (gzip?.url) return { ...gzip, encoding: gzip.encoding || 'gzip' };
      throw new Error('Brotli sem suporte; use gzip');
    }
    return { ...brotli, encoding };
  }

  if (gzip?.url) return { ...gzip, encoding: gzip.encoding || 'gzip' };

  if (brotli?.url) {
    const encoding = brotli.encoding || 'br';
    if (!supportsDecompression(encoding)) {
      throw new Error('Brotli sem suporte; use gzip');
    }
    return { ...brotli, encoding };
  }

  throw new Error('Nenhuma fonte válida no manifest');
}

/**
 * Stream de descompressão para writable
 */
async function streamDecompressToWritable({
  response,
  encoding,
  writable,
  signal,
  onProgress,
  totalSize
}: {
  response: Response;
  encoding: string;
  writable: FileSystemWritableFileStream;
  signal?: AbortSignal;
  onProgress?: (progress: number) => void;
  totalSize?: number;
}): Promise<void> {
  let stream = response.body;
  if (!stream) throw new Error('Response sem stream');

  if (encoding && encoding !== 'identity') {
    if (!supportsDecompression(encoding)) {
      throw new Error(`Sem suporte a DecompressionStream para ${encoding}`);
    }
    stream = stream.pipeThrough(
      new DecompressionStream(encoding as CompressionFormat)
    );
  }

  const reader = stream.getReader();
  let loaded = 0;

  try {
    while (true) {
      const { done, value } = await reader.read();
      if (done) break;
      if (signal?.aborted) throw new Error('Download abortado');
      await writable.write(value);
      loaded += value.length;
      if (onProgress && totalSize) {
        onProgress(Math.min(100, Math.round((loaded / totalSize) * 100)));
      }
    }
    await writable.close();
  } finally {
    reader.releaseLock();
  }
}

/**
 * Fetch direto para memória (fallback)
 */
async function fetchToMemory({
  url,
  encoding,
  signal,
  onProgress
}: {
  url: string;
  encoding?: string;
  signal?: AbortSignal;
  onProgress?: (progress: number) => void;
}): Promise<Uint8Array> {
  const res = await fetch(url, { signal });
  if (!res.ok) throw new Error(`Falha ao baixar ${url}: ${res.status}`);

  const contentLength = res.headers.get('Content-Length');
  const total = contentLength ? parseInt(contentLength, 10) : 0;

  if (!res.body) {
    const buffer = new Uint8Array(await res.arrayBuffer());
    onProgress?.(100);
    return decompressBuffer(buffer, encoding);
  }

  const reader = res.body.getReader();
  const chunks: Uint8Array[] = [];
  let loaded = 0;

  while (true) {
    const { done, value } = await reader.read();
    if (done) break;
    chunks.push(value);
    loaded += value.length;
    if (onProgress && total > 0) {
      onProgress(Math.round((loaded / total) * 100));
    }
  }

  const totalLength = chunks.reduce((sum, chunk) => sum + chunk.length, 0);
  const combined = new Uint8Array(totalLength);
  let offset = 0;
  for (const chunk of chunks) {
    combined.set(chunk, offset);
    offset += chunk.length;
  }

  return decompressBuffer(combined, encoding);
}

/**
 * Descomprime buffer se necessário
 */
async function decompressBuffer(
  buffer: Uint8Array,
  encoding?: string
): Promise<Uint8Array> {
  if (!encoding || encoding === 'identity') return buffer;

  // Try using DecompressionStream if available
  if (supportsDecompression(encoding)) {
    const ds = new DecompressionStream(encoding as CompressionFormat);
    const writer = ds.writable.getWriter();
    const reader = ds.readable.getReader();

    writer.write(buffer);
    writer.close();

    const chunks: Uint8Array[] = [];
    while (true) {
      const { done, value } = await reader.read();
      if (done) break;
      chunks.push(value);
    }

    const totalLength = chunks.reduce((sum, chunk) => sum + chunk.length, 0);
    const result = new Uint8Array(totalLength);
    let offset = 0;
    for (const chunk of chunks) {
      result.set(chunk, offset);
      offset += chunk.length;
    }
    return result;
  }

  // Fallback: try pako for gzip
  if (encoding.startsWith('gz') && typeof window !== 'undefined') {
    const pako = (
      window as unknown as {
        pako?: { ungzip: (data: Uint8Array) => Uint8Array };
      }
    ).pako;
    if (pako?.ungzip) return pako.ungzip(buffer);
  }

  throw new Error(`Encoding não suportado: ${encoding}`);
}

/**
 * Download para OPFS com streaming
 */
async function downloadToOpfs({
  url,
  encoding,
  fileName,
  size,
  signal,
  onProgress
}: {
  url: string;
  encoding: string;
  fileName: string;
  size?: number;
  signal?: AbortSignal;
  onProgress?: (progress: number) => void;
}): Promise<FileSystemFileHandle | null> {
  const handle = await getOpfsFileHandle(fileName, true);
  if (!handle) return null;

  const res = await fetch(url, { signal });
  if (!res.ok) throw new Error(`Falha ao baixar ${url}: ${res.status}`);

  const writable = await handle.createWritable();
  await streamDecompressToWritable({
    response: res,
    encoding,
    writable,
    signal,
    onProgress,
    totalSize: size
  });

  const file = await handle.getFile();
  if (size && file.size !== size) {
    console.warn(`Tamanho esperado ${size}, obtido ${file.size}`);
  }

  return handle;
}

/**
 * Lê arquivo do OPFS
 */
async function readOpfsFile(handle: FileSystemFileHandle): Promise<Uint8Array> {
  const file = await handle.getFile();
  const buffer = await file.arrayBuffer();
  return new Uint8Array(buffer);
}

/**
 * Persiste versão no localStorage
 */
function persistVersion(
  version: string,
  fileName: string,
  source: ManifestSource
): void {
  localStorage.setItem(VERSION_KEY, version);
  localStorage.setItem(FILE_KEY, fileName);
  localStorage.setItem(SOURCE_KEY, JSON.stringify(source));
}

/**
 * Limpa versão do localStorage
 */
function clearVersion(): void {
  localStorage.removeItem(VERSION_KEY);
  localStorage.removeItem(FILE_KEY);
  localStorage.removeItem(SOURCE_KEY);
}

/**
 * Limpa banco armazenado
 */
export async function clearStoredDatabase(
  fileName = 'db.sqlite'
): Promise<void> {
  try {
    if (navigator.storage?.getDirectory) {
      const root = await navigator.storage.getDirectory();
      await root.removeEntry(fileName);
    }
  } catch (err) {
    console.warn('Erro ao remover do OPFS', err);
  }
  clearVersion();
}

/**
 * Garante que o banco está armazenado (OPFS ou memória)
 */
export async function ensureDatabaseStored(
  manifest: Manifest,
  options: LoadOptions = {}
): Promise<DatabaseStore> {
  const preferBrotli = options.preferBrotli ?? true;
  const fileName = options.fileName ?? 'db.sqlite';
  const force = options.force ?? false;
  const signal = options.signal;
  const onProgress = options.onProgress;

  const source = pickSource(manifest, preferBrotli);
  const cachedVersion = localStorage.getItem(VERSION_KEY);
  const cachedFile = localStorage.getItem(FILE_KEY);

  // Check cache
  if (!force && cachedVersion === manifest.version && cachedFile === fileName) {
    const { exists, handle } = await fileExistsInOpfs(fileName);
    if (exists && handle) {
      onProgress?.(100);
      return { location: 'opfs', handle, source, version: cachedVersion };
    }
  }

  // Try OPFS streaming download
  let handle: FileSystemFileHandle | null = null;
  try {
    handle = await downloadToOpfs({
      url: source.url,
      encoding: source.encoding,
      fileName,
      size: source.size,
      signal,
      onProgress
    });
  } catch (err) {
    console.warn(
      'Falhou download streaming/OPFS, tentando fallback em memória:',
      err
    );
  }

  if (handle) {
    persistVersion(manifest.version, fileName, source);
    return { location: 'opfs', handle, source, version: manifest.version };
  }

  // Fallback to memory
  console.warn('OPFS indisponível; caindo para buffer em memória');
  const buffer = await fetchToMemory({
    url: source.url,
    encoding: source.encoding,
    signal,
    onProgress
  });
  return { location: 'memory', buffer, source, version: manifest.version };
}

/**
 * Migrações defensivas aplicadas ao banco recém-aberto.
 *
 * O snapshot é carregado read-only do disco, mas o sql.js o mantém em memória de
 * forma gravável (as alterações não são persistidas). Isso garante que um snapshot
 * mais antigo, gerado antes destas colunas existirem, não quebre as queries que
 * fazem SELECT delas — fechando a janela entre publicar o front e regenerar o
 * snapshot. As DDLs são idempotentes: se a coluna já existe, o erro é ignorado.
 */
function applyClientSchemaMigrations(db: SqlJsDatabase): void {
  const addColumns = [
    'ALTER TABLE repositories ADD COLUMN downloads INTEGER',
    'ALTER TABLE repositories ADD COLUMN package_url TEXT',
    // Enriquecimento Nuclei: flag + lista de templates relacionados por CVE.
    'ALTER TABLE cves ADD COLUMN exists_nuclei BOOLEAN DEFAULT 0',
    'ALTER TABLE cves ADD COLUMN list_nuclei TEXT',
    // EPSS (empiricalsec/epss_scores): probabilidade de exploração em 30 dias.
    'ALTER TABLE cves ADD COLUMN epss REAL',
    'ALTER TABLE cves ADD COLUMN epss_percentile REAL',
    'ALTER TABLE cves ADD COLUMN epss_date TEXT'
  ];
  for (const sql of addColumns) {
    try {
      db.run(sql);
    } catch {
      // Coluna já existe (snapshot já migrado) — ignora.
    }
  }
  // Unifica os downloads legados do WordPress ('downloaded') na coluna canônica.
  try {
    db.run(
      'UPDATE repositories SET downloads = downloaded WHERE downloads IS NULL AND downloaded IS NOT NULL'
    );
  } catch {
    // 'downloaded' pode não existir em snapshots muito antigos — ignora.
  }
}

/**
 * Abre o banco de dados
 */
export async function openDatabase(
  store: DatabaseStore,
  options: LoadOptions = {}
): Promise<DatabaseContext> {
  const SQL = await ensureSqlJs(options.wasmUrl);

  if (store.location === 'opfs' && store.handle) {
    const bytes = await readOpfsFile(store.handle);
    const db = new SQL.Database(bytes);
    applyClientSchemaMigrations(db);
    return {
      db,
      SQL,
      location: store.location,
      version: store.version,
      source: store.source
    };
  }

  if (store.location === 'memory' && store.buffer) {
    const db = new SQL.Database(store.buffer);
    applyClientSchemaMigrations(db);
    return {
      db,
      SQL,
      location: store.location,
      version: store.version,
      source: store.source
    };
  }

  throw new Error('Store inválido para openDatabase');
}

/**
 * Carrega o banco de dados completo (manifest -> download -> open)
 */
export async function loadDatabase(
  manifestUrl: string,
  options: LoadOptions = {}
): Promise<DatabaseContext> {
  const manifest = await loadManifest(manifestUrl);
  const stored = await ensureDatabaseStored(manifest, options);
  return openDatabase(stored, options);
}

/**
 * Carrega banco diretamente de uma URL (sem manifest)
 * Útil para bancos não comprimidos ou quando não há manifest
 */
export async function loadDatabaseFromUrl(
  url: string,
  options: LoadOptions = {}
): Promise<DatabaseContext> {
  const onProgress = options.onProgress;
  const signal = options.signal;

  const SQL = await ensureSqlJs(options.wasmUrl);

  const buffer = await fetchToMemory({
    url,
    signal,
    onProgress
  });

  const db = new SQL.Database(buffer);
  applyClientSchemaMigrations(db);
  return {
    db,
    SQL,
    location: 'memory',
    version: 'direct',
    source: { url, encoding: 'identity' }
  };
}
