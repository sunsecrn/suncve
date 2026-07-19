#!/usr/bin/env python3
from __future__ import annotations

import zipfile
import sqlite3
import os
import json
import re
import time
import socket
import shutil
import hashlib
import ipaddress
from functools import lru_cache
from pathlib import Path
from datetime import datetime, timezone
from urllib.parse import urlparse

try:
    import requests
    from requests.adapters import HTTPAdapter
except ModuleNotFoundError:
    requests = None  # type: ignore[assignment]
    HTTPAdapter = None  # type: ignore[assignment]
try:
    from urllib3.util.retry import Retry
except ModuleNotFoundError:
    Retry = None  # type: ignore[assignment]
try:
    from cvss import CVSS2, CVSS3, CVSS4
except ModuleNotFoundError:
    CVSS2 = CVSS3 = CVSS4 = None  # type: ignore[assignment]
try:
    from bs4 import BeautifulSoup
except ModuleNotFoundError:
    BeautifulSoup = None  # type: ignore[assignment]


def derive_cve_title(raw_title: str | None, description: str | None) -> str:
    """Deriva o título da CVE de forma consistente em todos os caminhos.

    Regra (idêntica à usada em formatDataVersion5_2): usa o título explícito
    quando presente; senão, deriva a partir da description (trunca em 140 chars
    quebrando na última palavra e sufixa '...'); senão, retorna 'No Title Found'.

    Reutilizada pela ingestão incremental (cvelistV5), pela criação de CVEs via
    GitHub Advisory e pelo backfill retroativo (comando 'backfill-titles').
    """
    title = raw_title or ""
    if not title and description:
        title = description.strip()[:140]
        if len(description) > 140:
            title = title.rsplit(" ", 1)[0]
        if not title.endswith("."):
            title += "..."
    if not title:
        title = "No Title Found"
    return title


def _build_http_session() -> requests.Session:
    if requests is None or HTTPAdapter is None:
        return None  # type: ignore[return-value]
    session = requests.Session()
    if Retry is not None:
        retries = Retry(
            total=3,
            connect=3,
            read=3,
            status=3,
            backoff_factor=1.0,
            status_forcelist=[429, 500, 502, 503, 504],
            allowed_methods=frozenset(["GET", "POST", "HEAD"]),
        )
        adapter = HTTPAdapter(max_retries=retries, pool_connections=20, pool_maxsize=20)
    else:
        adapter = HTTPAdapter(pool_connections=20, pool_maxsize=20)
    session.mount("https://", adapter)
    session.mount("http://", adapter)
    return session


HTTP_SESSION = _build_http_session()
REQUEST_EXCEPTION = requests.RequestException if requests else Exception


def _is_ip_public(ip_str: str) -> bool:
    try:
        ip = ipaddress.ip_address(ip_str)
    except ValueError:
        return False
    return not (
        ip.is_private
        or ip.is_loopback
        or ip.is_link_local
        or ip.is_multicast
        or ip.is_reserved
        or ip.is_unspecified
    )


@lru_cache(maxsize=1024)
def _is_host_public(host: str) -> bool:
    host_lower = host.lower().strip()
    if host_lower in {"localhost", "localhost.localdomain"}:
        return False
    if host_lower.endswith(".local"):
        return False
    if host_lower.endswith(".internal"):
        return False
    if _is_ip_public(host_lower):
        return True
    try:
        addr_info = socket.getaddrinfo(host_lower, None)
    except socket.gaierror:
        # DNS failure should not break ingestion; treat as potentially public host.
        return True
    ips = {item[4][0] for item in addr_info if item and item[4]}
    if not ips:
        return True
    # Accept hostname if at least one resolved IP is public.
    # Some domains may have mixed DNS records and shouldn't be blocked outright.
    return any(_is_ip_public(ip) for ip in ips)


def validate_external_url(url: str) -> None:
    parsed = urlparse(url)
    if parsed.scheme not in {"http", "https"}:
        raise ValueError(f"Unsupported URL scheme: {url}")
    host = parsed.hostname
    if not host:
        raise ValueError(f"Invalid URL host: {url}")
    if not _is_host_public(host):
        raise ValueError(f"Blocked non-public host: {host}")


def http_get(url: str, **kwargs):
    if HTTP_SESSION is None:
        raise RuntimeError("Missing dependency: requests")
    validate_external_url(url)
    timeout = kwargs.pop("timeout", 30)
    return HTTP_SESSION.get(url, timeout=timeout, **kwargs)


def http_post(url: str, **kwargs):
    if HTTP_SESSION is None:
        raise RuntimeError("Missing dependency: requests")
    validate_external_url(url)
    timeout = kwargs.pop("timeout", 30)
    return HTTP_SESSION.post(url, timeout=timeout, **kwargs)


def _github_api_headers(token: str | None = None) -> dict:
    headers = {"Accept": "application/vnd.github+json", "User-Agent": "suncve-bot"}
    token = token or os.environ.get("GITHUB_TOKEN")
    if token:
        headers["Authorization"] = f"Bearer {token}"
    return headers


def github_branch_head_sha(
    repo: str, branch: str, token: str | None = None
) -> str | None:
    """Retorna o SHA do commit HEAD de um branch via REST API."""
    url = f"https://api.github.com/repos/{repo}/commits/{branch}"
    try:
        resp = http_get(url, headers=_github_api_headers(token))
        resp.raise_for_status()
        return resp.json().get("sha")
    except REQUEST_EXCEPTION as e:
        print(f"[WARN] Failed to resolve HEAD sha for {repo}@{branch}: {e}")
        return None


def github_compare_files(
    repo: str, base_sha: str, head: str, token: str | None = None
) -> list[str] | None:
    """
    Lista os arquivos alterados (added/modified/renamed) entre base_sha e head.

    Retorna None quando não é possível comparar de forma confiável
    (sha desconhecido, resposta truncada em 300 arquivos) — sinaliza ao
    chamador para cair no scan completo.
    """
    url = f"https://api.github.com/repos/{repo}/compare/{base_sha}...{head}"
    try:
        resp = http_get(url, headers=_github_api_headers(token))
    except REQUEST_EXCEPTION as e:
        print(f"[WARN] compare failed for {repo}: {e}")
        return None
    if resp.status_code == 404:
        return None
    resp.raise_for_status()
    files = resp.json().get("files", [])
    if len(files) >= 300:
        # A API trunca a lista de arquivos em 300; força scan completo.
        return None
    return [
        f.get("filename")
        for f in files
        if f.get("status") in ("added", "modified", "renamed")
    ]


def download_to(url: str, dest_path: Path, headers: dict | None = None) -> Path:
    """Baixa uma URL para dest_path em streaming (sem progress)."""
    dest_path.parent.mkdir(parents=True, exist_ok=True)
    with http_get(url, stream=True, timeout=(30, 300), headers=headers or {}) as resp:
        resp.raise_for_status()
        with open(dest_path, "wb") as f:
            for chunk in resp.iter_content(chunk_size=1024 * 1024):
                if chunk:
                    f.write(chunk)
    return dest_path


def _sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _gzip_file(src: Path, dst: Path) -> None:
    import gzip

    with src.open("rb") as f_src, dst.open("wb") as f_dst:
        with gzip.GzipFile(
            filename="", mode="wb", fileobj=f_dst, compresslevel=9, mtime=0
        ) as gz:
            for chunk in iter(lambda: f_src.read(1024 * 1024), b""):
                gz.write(chunk)


def generate_db_manifest(
    db_dir: Path,
    base_url: str = "/db",
    version: str | None = None,
    output_path: Path | None = None,
    compress_gzip: bool = False,
    db_file_name: str = "source_com_repositorios.sqlite",
) -> Path:
    db_dir = db_dir.resolve()
    base_db = db_dir / db_file_name
    gzip_db = db_dir / f"{db_file_name}.gz"
    brotli_db = db_dir / f"{db_file_name}.br"

    if compress_gzip and base_db.exists() and not gzip_db.exists():
        print(f"[INFO] Generating gzip file from {base_db}...")
        _gzip_file(base_db, gzip_db)

    sources = {}
    if gzip_db.exists():
        sources["gzip"] = {
            "url": f"{base_url.rstrip('/')}/{gzip_db.name}",
            "encoding": "gzip",
            "size": gzip_db.stat().st_size,
            "sha256": _sha256_file(gzip_db),
        }
    if brotli_db.exists():
        sources["brotli"] = {
            "url": f"{base_url.rstrip('/')}/{brotli_db.name}",
            "encoding": "br",
            "size": brotli_db.stat().st_size,
            "sha256": _sha256_file(brotli_db),
        }

    if not sources:
        raise FileNotFoundError(
            f"No compressed DB file found in {db_dir}. Expected {gzip_db.name} and/or {brotli_db.name}"
        )

    manifest = {
        "version": version or datetime.now(timezone.utc).strftime("%Y%m%d%H%M%S"),
        "generated_at": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
        "sources": sources,
    }

    target = output_path or (db_dir / "manifest.json")
    target.parent.mkdir(parents=True, exist_ok=True)
    with target.open("w", encoding="utf-8") as f:
        json.dump(manifest, f, ensure_ascii=False, indent=2)
        f.write("\n")

    print(f"[INFO] Manifest generated at: {target}")
    return target


def calculateScoreCVSS(vector: str, version: str) -> float:
    if CVSS2 is None or CVSS3 is None or CVSS4 is None:
        return 0.0
    if not vector:
        return 0.0
    # Normaliza: alguns advisories trazem o vetor com espaços ou "/" sobrando no
    # final, o que faz a lib do CVSS levantar exceção (ex.: trailing "/").
    vector = vector.strip().rstrip("/")
    try:
        if vector.startswith("CVSS:2"):
            return CVSS2(vector).scores()[0]
        elif vector.startswith("CVSS:3"):
            return CVSS3(vector).scores()[0]
        elif vector.startswith("CVSS:4"):
            return CVSS4(vector).scores()[0]
        elif version == "2.0":
            return CVSS2(vector).scores()[0]
        else:
            return 0.0
    except Exception as e:
        # Vetor malformado não pode derrubar todo o pipeline; trata como "sem score".
        print(f"[WARN] Invalid CVSS vector {vector!r}: {e}")
        return 0.0


class GitHubExtractor:
    """
    Extrai fullpath de repositórios do GitHub a partir de URLs de referências.

    Endpoints relevantes (alta chance de ser o repositório da CVE):
    - /releases/tag/ ou /releases/
    - /issues/
    - /pull/
    - /commit/ ou /commits/
    - /security/advisories/
    """

    # Padrões de URL que indicam forte relação com o repositório
    RELEVANT_PATTERNS = [
        "/releases/",
        "/issues/",
        "/pull/",
        "/commit/",
        "/commits/",
        "/security/advisories/",
    ]

    @staticmethod
    def extractFullpath(url: str) -> str | None:
        """
        Extrai o fullpath (owner/repo) de uma URL do GitHub.

        Args:
            url: URL do GitHub

        Returns:
            fullpath em minúsculo (ex: 'btcpayserver/btcpayserver') ou None
        """
        if "github.com" not in url.lower():
            return None

        # Verifica se é um padrão relevante
        url_lower = url.lower()
        is_relevant = any(
            pattern in url_lower for pattern in GitHubExtractor.RELEVANT_PATTERNS
        )

        if not is_relevant:
            return None

        # Extrai owner/repo da URL
        # Padrão: https://github.com/OWNER/REPO/...
        match = re.search(r"github\.com/([^/]+)/([^/]+)", url, re.IGNORECASE)
        if not match:
            return None

        owner = match.group(1).lower()
        repo = match.group(2).lower()

        # Remove .git se existir no final do repo
        if repo.endswith(".git"):
            repo = repo[:-4]

        fullpath = f"{owner}/{repo}"
        return fullpath

    @staticmethod
    def extractFromReferences(references: list) -> list[str]:
        """
        Extrai fullpaths únicos de uma lista de referências.

        Args:
            references: lista de dicts com 'url'

        Returns:
            lista de fullpaths únicos
        """
        fullpaths = set()

        for ref in references:
            url = ref.get("url", "")
            fullpath = GitHubExtractor.extractFullpath(url)
            if fullpath:
                fullpaths.add(fullpath)

        return list(fullpaths)


class WordPressExtractor:
    """
    Extrai o slug de um plugin WordPress a partir de URLs de referências de uma CVE.

    Uma CVE é considerada do ecossistema WordPress quando conseguimos extrair um slug
    de plugin de alguma referência. O slug é o identificador do plugin no diretório
    oficial (ex.: 'contact-form-7') e também a chave usada na base de metadados.

    Padrões suportados:
    - https://plugins.trac.wordpress.org/browser/<slug>/trunk/...        -> após /browser/
    - https://plugins.trac.wordpress.org/changeset/<num>/<slug>          -> após /changeset/<num>/
    - https://wordpress.org/plugins/<slug>/                              -> após /plugins/
    - https://plugins.trac.wordpress.org/changeset?...old=<num>%40<slug>&new=<num>%40<slug>
                                                                        -> após %40
    """

    # fullpath sintético usado na tabela repositories
    FULLPATH_PREFIX = "wordpress.org/plugins/"

    @staticmethod
    def fullpathFromSlug(slug: str) -> str:
        return f"{WordPressExtractor.FULLPATH_PREFIX}{slug}"

    @staticmethod
    def _cleanSlug(slug: str | None) -> str | None:
        if not slug:
            return None
        slug = slug.strip().strip("/").lower()
        # Slugs do diretório WP são [a-z0-9-]; descarta qualquer coisa fora disso
        if not slug or not re.fullmatch(r"[a-z0-9][a-z0-9._-]*", slug):
            return None
        return slug

    @staticmethod
    def extractSlug(url: str) -> str | None:
        """Extrai o slug do plugin de uma única URL, ou None se não for WordPress."""
        if not url or "wordpress.org" not in url.lower():
            return None

        # 1) /browser/<slug>/...
        match = re.search(
            r"plugins\.trac\.wordpress\.org/browser/([^/?#]+)", url, re.IGNORECASE
        )
        if match:
            return WordPressExtractor._cleanSlug(match.group(1))

        # 2) /changeset/<num>/<slug>
        match = re.search(
            r"plugins\.trac\.wordpress\.org/changeset/\d+/([^/?#]+)", url, re.IGNORECASE
        )
        if match:
            return WordPressExtractor._cleanSlug(match.group(1))

        # 3) /changeset?...old=<num>%40<slug>&new=<num>%40<slug>  (%40 == '@')
        if "trac.wordpress.org/changeset?" in url.lower():
            match = re.search(r"%40([A-Za-z0-9][A-Za-z0-9._-]*)", url, re.IGNORECASE)
            if match:
                return WordPressExtractor._cleanSlug(match.group(1))

        # 4) wordpress.org/plugins/<slug>/
        match = re.search(r"wordpress\.org/plugins/([^/?#]+)", url, re.IGNORECASE)
        if match:
            return WordPressExtractor._cleanSlug(match.group(1))

        return None

    @staticmethod
    def extractFromReferences(references: list) -> list[str]:
        """Retorna a lista de slugs únicos encontrados nas referências."""
        slugs = set()
        for ref in references:
            slug = WordPressExtractor.extractSlug(ref.get("url", ""))
            if slug:
                slugs.add(slug)
        return list(slugs)


class GitHubRepositoryVerifier:
    """
    Verifica repositórios do GitHub via GraphQL API e extrai metadados.
    """

    GRAPHQL_URL = "https://api.github.com/graphql"

    GRAPHQL_QUERY = """
    query ($owner: String!, $name: String!) {
        repository(owner: $owner, name: $name) {
            name
            diskUsage
            stargazerCount
            createdAt
            updatedAt
            primaryLanguage {
                name
            }
            languages(first: 10, orderBy: {field: SIZE, direction: DESC}) {
                edges {
                    size
                    node {
                        name
                    }
                }
            }
            repositoryTopics(first: 10) {
                nodes {
                    topic {
                        name
                    }
                }
            }
        }
    }
    """

    def __init__(self, token: str):
        """
        Inicializa o verificador com o token do GitHub.

        Args:
            token: GitHub Personal Access Token (PAT)
        """
        self.token = token
        self.headers = {
            "Authorization": f"bearer {token}",
            "Content-Type": "application/json",
        }

    def _calculateLanguagePercentages(self, languages_edges: list) -> dict:
        """
        Calcula a porcentagem de cada linguagem baseado no tamanho em bytes.

        Args:
            languages_edges: lista de edges com size e node.name

        Returns:
            dict com {linguagem: porcentagem} ex: {"Python": 60, "TypeScript": 30, "Shell": 10}
        """
        if not languages_edges:
            return {}

        total_size = sum(edge["size"] for edge in languages_edges)
        if total_size == 0:
            return {}

        percentages = {}
        for edge in languages_edges:
            lang_name = edge["node"]["name"]
            percentage = round((edge["size"] / total_size) * 100)

            if percentage > 0:  # Ignora linguagens com menos de 1%
                percentages[lang_name] = percentage

        return percentages

    # Configurações de retry para rate limit
    RATE_LIMIT_MAX_RETRIES = 3
    RATE_LIMIT_DEFAULT_DELAY = 300  # 5 minutos padrão

    def verifyRepository(self, fullpath: str) -> dict | None | bool:
        """
        Verifica um repositório via GraphQL API.

        Args:
            fullpath: caminho completo (owner/repo)

        Returns:
            dict: dados do repositório se encontrado
            None: se repositório não existe
            False: se rate limited (não marcar como não encontrado, pular)
        """
        parts = fullpath.split("/")
        if len(parts) != 2:
            print(f"[WARN] Invalid fullpath format: {fullpath}")
            return None

        owner, name = parts

        payload = {
            "query": self.GRAPHQL_QUERY,
            "variables": {"owner": owner, "name": name},
        }

        for attempt in range(self.RATE_LIMIT_MAX_RETRIES + 1):
            try:
                response = http_post(
                    self.GRAPHQL_URL, headers=self.headers, json=payload, timeout=30
                )

                # Tratamento de Rate Limit (429)
                if response.status_code == 429:
                    if attempt < self.RATE_LIMIT_MAX_RETRIES:
                        # Pega o tempo de espera do header ou usa o padrão
                        retry_after = int(
                            response.headers.get(
                                "Retry-After", self.RATE_LIMIT_DEFAULT_DELAY
                            )
                        )
                        print(
                            f"[WARN] Rate limited (429). Waiting {retry_after}s before retry {attempt + 1}/{self.RATE_LIMIT_MAX_RETRIES}..."
                        )
                        time.sleep(retry_after)
                        continue
                    else:
                        print(
                            f"[WARN] Rate limit exceeded after {self.RATE_LIMIT_MAX_RETRIES} retries for {fullpath}. Skipping..."
                        )
                        return (
                            False  # Indica para pular (não marcar como não encontrado)
                        )

                # Tratamento de outros erros HTTP
                if response.status_code == 404:
                    print(f"[INFO] Repository not found (404): {fullpath}")
                    return None

                response.raise_for_status()

                data = response.json()

                # Verifica se há erros na resposta GraphQL
                if "errors" in data:
                    error_msg = data["errors"][0].get("message", "Unknown error")
                    if "Could not resolve" in error_msg or "NOT_FOUND" in error_msg:
                        print(f"[INFO] Repository not found: {fullpath}")
                        return None
                    # Rate limit também pode vir como erro GraphQL
                    if "rate limit" in error_msg.lower():
                        if attempt < self.RATE_LIMIT_MAX_RETRIES:
                            print(
                                f"[WARN] GraphQL rate limit. Waiting {self.RATE_LIMIT_DEFAULT_DELAY}s before retry {attempt + 1}/{self.RATE_LIMIT_MAX_RETRIES}..."
                            )
                            time.sleep(self.RATE_LIMIT_DEFAULT_DELAY)
                            continue
                        else:
                            print(
                                f"[WARN] Rate limit exceeded after {self.RATE_LIMIT_MAX_RETRIES} retries for {fullpath}. Skipping..."
                            )
                            return False
                    print(f"[WARN] GraphQL error for {fullpath}: {error_msg}")
                    return None

                repo = data.get("data", {}).get("repository")
                if not repo:
                    print(f"[INFO] Repository not found: {fullpath}")
                    return None

                # Extrai linguagens com porcentagens
                languages_edges = repo.get("languages", {}).get("edges", [])
                languages_percentages = self._calculateLanguagePercentages(
                    languages_edges
                )

                # Extrai topics/tags
                topics_nodes = repo.get("repositoryTopics", {}).get("nodes", [])
                tags = [
                    node["topic"]["name"] for node in topics_nodes if node.get("topic")
                ]

                # Linguagem principal
                primary_lang = repo.get("primaryLanguage")
                language_main = primary_lang["name"] if primary_lang else None

                return {
                    "is_exists": True,
                    "name": repo.get("name"),
                    "size": repo.get("diskUsage"),  # Em KB
                    "stars": repo.get("stargazerCount"),
                    "languageMain": language_main,
                    "languages": json.dumps(languages_percentages),
                    "tags": json.dumps(tags),
                    "created_repository": repo.get("createdAt"),
                    "updated_repository": repo.get("updatedAt"),
                }

            except REQUEST_EXCEPTION as e:
                print(f"[WARN] Failed to verify repository {fullpath}: {e}")
                return None
            except (KeyError, json.JSONDecodeError) as e:
                print(f"[WARN] Failed to parse response for {fullpath}: {e}")
                return None

        return False  # Fallback: se sair do loop sem retornar, pular

    def run(self, db: "databaseSQLite", batch_size: int = 100) -> int:
        """
        Verifica todos os repositórios pendentes no banco.

        Args:
            db: instância do banco de dados
            batch_size: quantidade de repositórios por batch

        Returns:
            int: quantidade total de repositórios verificados
        """
        total_verified = 0
        total_found = 0
        total_not_found = 0
        total_skipped = 0
        rate_limited = False

        while True:
            pending = db.getPendingRepositories(limit=batch_size)
            if not pending:
                break

            for fullpath in pending:
                print(f"[INFO] Verifying repository: {fullpath}")

                result = self.verifyRepository(fullpath)

                # result pode ser:
                # - dict: repositório encontrado
                # - None: repositório não existe
                # - False: rate limited, pular (manter pendente)

                if result is False:
                    # Rate limited - parar execução para evitar loop
                    total_skipped += 1
                    rate_limited = True
                    print(
                        f"[WARN] Rate limited! Stopping execution. Run again later to continue."
                    )
                    break
                elif result:
                    # Repositório encontrado
                    db.updateRepository(fullpath, result)
                    # Atualiza commits_fix baseado nas CVEs relacionadas
                    db.updateRepositoryCommitsFix(fullpath)
                    total_found += 1
                else:
                    # Repositório não encontrado (None)
                    db.markRepositoryNotFound(fullpath)
                    total_not_found += 1

                total_verified += 1

                # Commit a cada 10 repositórios
                if total_verified % 10 == 0:
                    db.conn.commit()
                    print(
                        f"[INFO] Progress: {total_verified} verified ({total_found} found, {total_not_found} not found)"
                    )

            # Se foi rate limited, sai do loop principal
            if rate_limited:
                break

        db.conn.commit()

        if rate_limited:
            print(
                f"[WARN] Execution stopped due to rate limit. Verified {total_verified} repos ({total_found} found, {total_not_found} not found)"
            )
            print(
                f"[INFO] Run the command again later to continue from where it stopped."
            )
        else:
            print(
                f"[INFO] Repository verification complete: {total_verified} total ({total_found} found, {total_not_found} not found)"
            )

        return total_verified


class databaseSQLite:
    def __init__(self, path: Path):
        self.path = path
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.conn = sqlite3.connect(path)
        self.cursor = self.conn.cursor()

    def createTable(self) -> None:
        # Tabela principal de CVEs
        self.cursor.execute("""
        CREATE TABLE IF NOT EXISTS sources (
            source_name TEXT PRIMARY KEY,
            last_verified TEXT,
            last_updated TEXT,
            last_release_file TEXT,
            base_release_file TEXT
        )
        """)

        self.cursor.execute("""
        CREATE TABLE IF NOT EXISTS repositories (
            fullpath TEXT PRIMARY KEY,
            is_exists BOOLEAN DEFAULT NULL,
            name TEXT,
            size INTEGER,
            stars INTEGER,
            languageMain TEXT,
            languages TEXT,
            tags TEXT,
            categories TEXT,
            commits_fix JSON,
            commits_fix_count INTEGER,
            researchs JSON,
            researchs_count INTEGER,
            scm_id_repository TEXT,
            created_repository TEXT,
            updated_repository TEXT,
            ecosystem TEXT DEFAULT 'github',
            active_installs INTEGER,
            downloaded INTEGER,
            package_url TEXT,
            downloads INTEGER
        )
        """)

        # Migração: adiciona coluna is_exists se não existir (para bancos antigos)
        try:
            self.cursor.execute(
                "ALTER TABLE repositories ADD COLUMN is_exists BOOLEAN DEFAULT NULL"
            )
        except sqlite3.OperationalError:
            pass  # Coluna já existe

        # Migração: colunas do ecossistema WordPress (plugins) para bancos antigos
        for column_ddl in (
            "ALTER TABLE repositories ADD COLUMN ecosystem TEXT DEFAULT 'github'",
            "ALTER TABLE repositories ADD COLUMN active_installs INTEGER",
            "ALTER TABLE repositories ADD COLUMN downloaded INTEGER",
            # Métricas de pacote unificadas (npm/Packagist/WordPress)
            "ALTER TABLE repositories ADD COLUMN package_url TEXT",
            "ALTER TABLE repositories ADD COLUMN downloads INTEGER",
        ):
            try:
                self.cursor.execute(column_ddl)
            except sqlite3.OperationalError:
                pass  # Coluna já existe

        # Backfill único: a coluna 'downloads' unifica as métricas de download de todos
        # os ecossistemas. Snapshots antigos só têm os downloads do WordPress em
        # 'downloaded'; trazemos esse valor para a coluna canônica. A coluna física
        # 'downloaded' é mantida apenas por compatibilidade com snapshots distribuídos.
        try:
            self.cursor.execute(
                "UPDATE repositories SET downloads = downloaded "
                "WHERE downloads IS NULL AND downloaded IS NOT NULL"
            )
        except sqlite3.OperationalError:
            pass

        # 1. Tabela Principal de CVEs
        self.cursor.execute("""
        CREATE TABLE IF NOT EXISTS cves (
            cve_id TEXT PRIMARY KEY,
            state TEXT,
            date_published TEXT,
            date_updated TEXT,
            date_reserved TEXT,
            title TEXT,
            description TEXT,
            exists_exploit BOOLEAN,
            exists_commit BOOLEAN,
            list_exploit JSON,
            list_commit JSON,
            list_references JSON,
            exists_nuclei BOOLEAN DEFAULT 0,
            list_nuclei JSON
        )
        """)

        # Migração: campos de templates Nuclei (projectdiscovery/nuclei-templates)
        # para bancos antigos. Espelha o par exists_exploit/list_exploit.
        # list_nuclei é um array de {template_id, path, url} (só o link do template).
        for column_ddl in (
            # DEFAULT 0 para que, em bancos novos, CVEs sem template fiquem 0
            # (o insert nao grava exists_nuclei). O enriquecimento nuclei marca 1
            # quem tem template e normaliza NULLs remanescentes de bancos antigos.
            "ALTER TABLE cves ADD COLUMN exists_nuclei BOOLEAN DEFAULT 0",
            "ALTER TABLE cves ADD COLUMN list_nuclei JSON",
        ):
            try:
                self.cursor.execute(column_ddl)
            except sqlite3.OperationalError:
                pass  # Coluna já existe

        # Migração: campos KEV (CISA Known Exploited Vulnerabilities)
        for column_ddl in (
            "ALTER TABLE cves ADD COLUMN in_kev BOOLEAN DEFAULT 0",
            "ALTER TABLE cves ADD COLUMN kev_date_added TEXT",
            "ALTER TABLE cves ADD COLUMN kev_due_date TEXT",
            "ALTER TABLE cves ADD COLUMN kev_ransomware BOOLEAN DEFAULT 0",
        ):
            try:
                self.cursor.execute(column_ddl)
            except sqlite3.OperationalError:
                pass  # Coluna já existe

        # Migração: missing template indicator (edoardottt/missing-cve-nuclei-templates)
        for column_ddl in (
            "ALTER TABLE cves ADD COLUMN missing_nuclei_template BOOLEAN DEFAULT 0",
        ):
            try:
                self.cursor.execute(column_ddl)
            except sqlite3.OperationalError:
                pass  # Coluna já existe

        # 2. Tabela de Scores (1 CVE -> N Scores)
        self.cursor.execute("""
        CREATE TABLE IF NOT EXISTS cve_scores (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            cve_id TEXT,
            version TEXT,
            score REAL,  
            FOREIGN KEY (cve_id) REFERENCES cves (cve_id) ON DELETE CASCADE
        )
        """)

        # 3. Tabela de CWEs (N CVE <-> N CWE)
        self.cursor.execute("""
        CREATE TABLE IF NOT EXISTS cve_cwes (
            cve_id TEXT,
            cwe_id TEXT,
            PRIMARY KEY (cve_id, cwe_id),
            FOREIGN KEY (cve_id) REFERENCES cves (cve_id) ON DELETE CASCADE
        )
        """)

        # 4. Tabela de Produtos Afetados (N CVE <-> N Produtos)
        self.cursor.execute("""
        CREATE TABLE IF NOT EXISTS cve_affected (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            cve_id TEXT,
            vendor TEXT,
            product TEXT,
            UNIQUE (cve_id, vendor, product),
            FOREIGN KEY (cve_id) REFERENCES cves (cve_id) ON DELETE CASCADE
        )
        """)

        # 5. Tabela de Relação CVE <-> Repositório (N:N, OPCIONAL)
        self.cursor.execute("""
        CREATE TABLE IF NOT EXISTS cve_repositories (
            cve_id TEXT,
            repository_fullpath TEXT,
            relation_type TEXT,
            PRIMARY KEY (cve_id, repository_fullpath),
            FOREIGN KEY (cve_id) REFERENCES cves (cve_id) ON DELETE CASCADE,
            FOREIGN KEY (repository_fullpath) REFERENCES repositories (fullpath) ON DELETE CASCADE
        )
        """)

        # 6. Tabela de Cache de URLs verificadas
        self.cursor.execute("""
        CREATE TABLE IF NOT EXISTS url_cache (
            url TEXT PRIMARY KEY,
            has_exploit BOOLEAN,
            verified_at TEXT
        )
        """)

        # 7. Cache de manifestos de pacote lidos da branch default de cada repo.
        # Fonte de verdade do NOME canônico do pacote: o 'name' do package.json
        # (npm) / composer.json (Packagist) na raiz da branch default. A presença
        # da linha significa "já varrido em definitivo" (mesmo sem manifesto), para
        # que o scanner não revisite o repo. Falhas transitórias (rate limit/rede)
        # NÃO gravam linha, então são re-tentadas no próximo run.
        self.cursor.execute("""
        CREATE TABLE IF NOT EXISTS repo_manifests (
            fullpath TEXT PRIMARY KEY,
            npm_name TEXT,
            composer_name TEXT,
            default_branch TEXT,
            checked_at TEXT,
            FOREIGN KEY (fullpath) REFERENCES repositories (fullpath) ON DELETE CASCADE
        )
        """)

        # Cache do repositório CANÔNICO de cada pacote npm, resolvido no registry
        # (registry.npmjs.org/<nome>/latest -> .repository). Fonte de verdade para o
        # guard "esse pacote é mesmo deste repo?". fullpath NULL = verificado e sem
        # repo GitHub conhecido (não rejeita); linha ausente = ainda não verificado.
        # Persiste entre snapshots (restaurados incrementalmente), tornando a
        # verificação barata depois da primeira passada.
        self.cursor.execute("""
        CREATE TABLE IF NOT EXISTS npm_repo_cache (
            name TEXT PRIMARY KEY,
            fullpath TEXT,
            checked_at TEXT
        )
        """)

        # Limpeza retroativa: PoCs de exploit não são repositórios. Toda a informação
        # já vive em cves.list_exploit; removemos a redundância em cve_repositories e os
        # repos cujo ÚNICO papel era 'poc'. Idempotente (após rodar uma vez, vira no-op).
        # Ordem importa: primeiro removemos os repos "apenas-poc" (enquanto o vínculo
        # 'poc' ainda existe para identificá-los), depois removemos os vínculos 'poc'.
        try:
            self.cursor.execute("""
                DELETE FROM repositories
                WHERE fullpath IN (
                    SELECT repository_fullpath FROM cve_repositories
                    GROUP BY repository_fullpath
                    HAVING SUM(CASE WHEN relation_type != 'poc' THEN 1 ELSE 0 END) = 0
                )
            """)
            self.cursor.execute(
                "DELETE FROM cve_repositories WHERE relation_type = 'poc'"
            )
        except sqlite3.OperationalError:
            pass

        # --- ÍNDICES PARA BUSCA ULTRA RÁPIDA ---
        self.cursor.execute(
            "CREATE INDEX IF NOT EXISTS idx_score_val ON cve_scores(score)"
        )
        self.cursor.execute(
            "CREATE INDEX IF NOT EXISTS idx_cwe_lookup ON cve_cwes(cwe_id)"
        )
        self.cursor.execute(
            "CREATE INDEX IF NOT EXISTS idx_product_lookup ON cve_affected(product)"
        )
        self.cursor.execute(
            "CREATE INDEX IF NOT EXISTS idx_vendor_lookup ON cve_affected(vendor)"
        )
        self.cursor.execute(
            "CREATE INDEX IF NOT EXISTS idx_repo_cve ON cve_repositories(cve_id)"
        )
        self.cursor.execute(
            "CREATE INDEX IF NOT EXISTS idx_repo_fullpath ON cve_repositories(repository_fullpath)"
        )
        self.cursor.execute(
            "CREATE INDEX IF NOT EXISTS idx_repo_ecosystem ON repositories(ecosystem)"
        )
        self.cursor.execute(
            "CREATE INDEX IF NOT EXISTS idx_repo_downloads ON repositories(downloads)"
        )
        self.cursor.execute(
            "CREATE INDEX IF NOT EXISTS idx_cves_exists_nuclei ON cves(exists_nuclei)"
        )
        self.cursor.execute(
            "CREATE INDEX IF NOT EXISTS idx_manifest_npm ON repo_manifests(npm_name)"
        )
        self.cursor.execute(
            "CREATE INDEX IF NOT EXISTS idx_manifest_composer ON repo_manifests(composer_name)"
        )

        """
        EXEMPLOS DE QUERY CONSULTA:
        
        -- CVEs com score alto, CWE específico e produto
        SELECT DISTINCT c.cve_id, c.title, s.score
            FROM cves c
            JOIN cve_cwes cw ON c.cve_id = cw.cve_id
            JOIN cve_scores s ON c.cve_id = s.cve_id
            JOIN cve_affected a ON c.cve_id = a.cve_id
            WHERE a.product = 'linux' 
              AND cw.cwe_id = 'CWE-79' 
              AND s.score > 5.0;
        
        -- CVEs COM repositório associado (INNER JOIN)
        SELECT c.cve_id, c.title, r.name as repo_name
            FROM cves c
            JOIN cve_repositories cr ON c.cve_id = cr.cve_id
            JOIN repositories r ON cr.repository_fullpath = r.fullpath;
        
        -- CVEs com ou SEM repositório (LEFT JOIN - opcional)
        SELECT c.cve_id, c.title, r.name as repo_name
            FROM cves c
            LEFT JOIN cve_repositories cr ON c.cve_id = cr.cve_id
            LEFT JOIN repositories r ON cr.repository_fullpath = r.fullpath;

        -- CVEs com exploit, mostrando linguagem do repositório e se tem commit
        SELECT c.cve_id, c.title, c.exists_exploit, c.exists_commit, r.languageMain, r.name as repo_name, cr.relation_type
            FROM cves c
            LEFT JOIN cve_repositories cr ON c.cve_id = cr.cve_id
            LEFT JOIN repositories r ON cr.repository_fullpath = r.fullpath
            WHERE c.exists_exploit = 1;

        -- Filtrar por linguagem específica (ex: Python)
        SELECT c.cve_id, c.title, r.languageMain
            FROM cves c
            JOIN cve_repositories cr ON c.cve_id = cr.cve_id
            JOIN repositories r ON cr.repository_fullpath = r.fullpath
            WHERE c.exists_exploit = 1 
              AND r.languageMain = 'Python';

        -- CVEs com exploit E commit
        SELECT c.cve_id, c.title, r.languageMain, r.name
            FROM cves c
            LEFT JOIN cve_repositories cr ON c.cve_id = cr.cve_id
            LEFT JOIN repositories r ON cr.repository_fullpath = r.fullpath
            WHERE c.exists_exploit = 1 
              AND c.exists_commit = 1;

        -- Contar CVEs com exploit por linguagem
        SELECT r.languageMain, COUNT(DISTINCT c.cve_id) as total
            FROM cves c
            JOIN cve_repositories cr ON c.cve_id = cr.cve_id
            JOIN repositories r ON cr.repository_fullpath = r.fullpath
            WHERE c.exists_exploit = 1
            GROUP BY r.languageMain
            ORDER BY total DESC;
        """

        self.conn.commit()

    def getSourceInfo(self, source_name: str) -> dict | None:
        """
        Consulta a tabela sources para verificar se já existe base_release_file.

        Returns:
            dict com os dados da source ou None se não existir
        """
        self.cursor.execute(
            """
        SELECT source_name, last_verified, last_updated, last_release_file, base_release_file
        FROM sources
        WHERE source_name = ?
        """,
            (source_name,),
        )

        row = self.cursor.fetchone()
        if row:
            return {
                "source_name": row[0],
                "last_verified": row[1],
                "last_updated": row[2],
                "last_release_file": row[3],
                "base_release_file": row[4],
            }
        return None

    def updateSource(
        self,
        source_name: str,
        last_verified: str,
        last_updated: str,
        last_release_file: str,
        base_release_file: str = None,
    ) -> None:
        """
        Insere ou atualiza registro na tabela sources.

        Args:
            source_name: nome da fonte (ex: "cvelistV5")
            last_verified: timestamp de início do script
            last_updated: updated_at da release
            last_release_file: URL do arquivo baixado (delta ou full)
            base_release_file: URL do all_CVEs (apenas na primeira vez)
        """
        # Verifica se já existe
        existing = self.getSourceInfo(source_name)

        if existing:
            # Se já existe e não passou base_release_file, mantém o existente
            if base_release_file is None:
                base_release_file = existing.get("base_release_file")

            self.cursor.execute(
                """
            UPDATE sources 
            SET last_verified = ?, last_updated = ?, last_release_file = ?, base_release_file = ?
            WHERE source_name = ?
            """,
                (
                    last_verified,
                    last_updated,
                    last_release_file,
                    base_release_file,
                    source_name,
                ),
            )
        else:
            self.cursor.execute(
                """
            INSERT INTO sources (source_name, last_verified, last_updated, last_release_file, base_release_file)
            VALUES (?, ?, ?, ?, ?)
            """,
                (
                    source_name,
                    last_verified,
                    last_updated,
                    last_release_file,
                    base_release_file,
                ),
            )

        self.conn.commit()

    def insertRepository(self, fullpath: str) -> None:
        """
        Insere um repositório na tabela repositories (apenas fullpath por enquanto).

        Args:
            fullpath: caminho completo do repositório (ex: 'owner/repo')
        """
        try:
            self.cursor.execute(
                """
            INSERT OR IGNORE INTO repositories (fullpath)
            VALUES (?)
            """,
                (fullpath,),
            )
        except sqlite3.Error as e:
            print(f"[WARN] Failed to insert repository {fullpath}: {e}")

    def insertWordpressRepository(self, slug: str) -> None:
        """
        Insere um plugin WordPress como repositório sintético.

        Marca is_exists=1 e ecosystem='wordpress' para que não seja verificado via
        GraphQL do GitHub. Métricas (active_installs/downloaded) são preenchidas pelo
        comando 'wordpress'. Não sobrescreve dados existentes.
        """
        try:
            self.cursor.execute(
                """
            INSERT OR IGNORE INTO repositories (fullpath, is_exists, ecosystem, name)
            VALUES (?, 1, 'wordpress', ?)
            """,
                (WordPressExtractor.fullpathFromSlug(slug), slug),
            )
        except sqlite3.Error as e:
            print(f"[WARN] Failed to insert wordpress plugin {slug}: {e}")

    def backfillWordpressClassification(self) -> int:
        """
        Reclassifica CVEs que JÁ estão no banco como ecossistema WordPress.

        O pipeline incremental só roda complementCVE quando o CVE reaparece num
        delta, então CVEs antigos nunca seriam classificados. Aqui varremos as
        referências já gravadas (cves.list_references), extraímos o slug do plugin
        e criamos o repositório sintético + o vínculo em cve_repositories. Também
        alimentamos list_commit com os changesets do Trac. Tudo sem rede e
        idempotente (INSERT OR IGNORE).

        Returns:
            Quantidade de CVEs classificadas como WordPress.
        """
        # Pré-filtro barato: só CVEs cujas referências mencionam wordpress.org
        self.cursor.execute(
            "SELECT cve_id, list_references, list_commit FROM cves "
            "WHERE list_references LIKE '%wordpress.org%'"
        )
        rows = self.cursor.fetchall()
        classified = 0
        for cve_id, refs_json, commit_json in rows:
            try:
                references = json.loads(refs_json) if refs_json else []
            except (json.JSONDecodeError, TypeError):
                continue

            slugs = WordPressExtractor.extractFromReferences(references)
            if not slugs:
                continue

            # Changesets do Trac viram "commits" de fix; mescla com os existentes.
            try:
                commits = json.loads(commit_json) if commit_json else []
            except (json.JSONDecodeError, TypeError):
                commits = []
            commits = list(commits) if isinstance(commits, list) else []
            added_commit = False
            for ref in references:
                url = ref.get("url", "") if isinstance(ref, dict) else ""
                if "trac.wordpress.org/changeset" in url.lower() and url not in commits:
                    commits.append(url)
                    added_commit = True
            if added_commit:
                self.cursor.execute(
                    "UPDATE cves SET list_commit = ?, exists_commit = 1 WHERE cve_id = ?",
                    (json.dumps(commits), cve_id),
                )

            commit_blob = " ".join(commits).lower()
            for slug in slugs:
                self.insertWordpressRepository(slug)
                fullpath = WordPressExtractor.fullpathFromSlug(slug)
                relation = (
                    "fix_commit"
                    if (
                        "trac.wordpress.org/changeset" in commit_blob
                        and slug in commit_blob
                    )
                    else "referenced"
                )
                self.cursor.execute(
                    "INSERT OR IGNORE INTO cve_repositories "
                    "(cve_id, repository_fullpath, relation_type) VALUES (?, ?, ?)",
                    (cve_id, fullpath, relation),
                )

            classified += 1
            if classified % 1000 == 0:
                self.conn.commit()
                print(f"[INFO] wordpress: classified {classified} CVEs so far...")

        self.conn.commit()
        return classified

    def getPendingRepositories(self, limit: int = 100) -> list[str]:
        """
        Retorna lista de repositórios que ainda não foram verificados (is_exists IS NULL).

        Args:
            limit: quantidade máxima de repositórios a retornar

        Returns:
            Lista de fullpaths de repositórios pendentes
        """
        self.cursor.execute(
            """
        SELECT fullpath FROM repositories 
        WHERE is_exists IS NULL 
        LIMIT ?
        """,
            (limit,),
        )
        return [row[0] for row in self.cursor.fetchall()]

    def countPendingRepositories(self) -> int:
        self.cursor.execute("""
        SELECT COUNT(*) FROM repositories
        WHERE is_exists IS NULL
        """)
        row = self.cursor.fetchone()
        return int(row[0]) if row and row[0] is not None else 0

    def updateRepository(self, fullpath: str, data: dict) -> None:
        """
        Atualiza os dados de um repositório verificado.

        Args:
            fullpath: caminho completo do repositório (ex: 'owner/repo')
            data: dicionário com os dados do repositório:
                - is_exists: bool - se o repositório existe
                - name: str - nome do repositório
                - size: int - tamanho em KB
                - stars: int - quantidade de stars
                - languageMain: str - linguagem principal
                - languages: str - JSON com porcentagens das linguagens
                - tags: str - JSON com lista de topics/tags
                - created_repository: str - data de criação
                - updated_repository: str - data de atualização
        """
        try:
            self.cursor.execute(
                """
            UPDATE repositories SET
                is_exists = ?,
                name = ?,
                size = ?,
                stars = ?,
                languageMain = ?,
                languages = ?,
                tags = ?,
                created_repository = ?,
                updated_repository = ?
            WHERE fullpath = ?
            """,
                (
                    data.get("is_exists"),
                    data.get("name"),
                    data.get("size"),
                    data.get("stars"),
                    data.get("languageMain"),
                    data.get("languages"),
                    data.get("tags"),
                    data.get("created_repository"),
                    data.get("updated_repository"),
                    fullpath,
                ),
            )
        except sqlite3.Error as e:
            print(f"[WARN] Failed to update repository {fullpath}: {e}")

    def markRepositoryNotFound(self, fullpath: str) -> None:
        """
        Marca um repositório como não encontrado (is_exists = False).

        Args:
            fullpath: caminho completo do repositório
        """
        try:
            self.cursor.execute(
                """
            UPDATE repositories SET is_exists = 0 WHERE fullpath = ?
            """,
                (fullpath,),
            )
        except sqlite3.Error as e:
            print(f"[WARN] Failed to mark repository {fullpath} as not found: {e}")

    def getRepositoryFixCVEs(self, fullpath: str) -> list[str]:
        """
        Retorna lista de CVE IDs que têm fix_commit neste repositório.

        Args:
            fullpath: caminho completo do repositório

        Returns:
            Lista de cve_ids com relation_type = 'fix_commit'
        """
        self.cursor.execute(
            """
        SELECT cve_id FROM cve_repositories 
        WHERE repository_fullpath = ? AND relation_type = 'fix_commit'
        """,
            (fullpath,),
        )
        return [row[0] for row in self.cursor.fetchall()]

    def updateRepositoryCommitsFix(self, fullpath: str) -> None:
        """
        Atualiza commits_fix e commits_fix_count de um repositório
        baseado nas CVEs relacionadas com relation_type = 'fix_commit'.

        Args:
            fullpath: caminho completo do repositório
        """
        cve_ids = self.getRepositoryFixCVEs(fullpath)
        commits_fix_json = json.dumps(cve_ids) if cve_ids else None
        commits_fix_count = len(cve_ids)

        try:
            self.cursor.execute(
                """
            UPDATE repositories SET 
                commits_fix = ?,
                commits_fix_count = ?
            WHERE fullpath = ?
            """,
                (commits_fix_json, commits_fix_count, fullpath),
            )
        except sqlite3.Error as e:
            print(f"[WARN] Failed to update commits_fix for {fullpath}: {e}")

    def updateAllRepositoriesCommitsFix(self) -> int:
        """
        Atualiza commits_fix e commits_fix_count de TODOS os repositórios.
        Útil para rodar após processar todas as CVEs.

        Returns:
            int: quantidade de repositórios atualizados
        """
        # Pega todos os repositórios que existem
        self.cursor.execute("SELECT fullpath FROM repositories WHERE is_exists = 1")
        repos = [row[0] for row in self.cursor.fetchall()]

        count = 0
        for fullpath in repos:
            self.updateRepositoryCommitsFix(fullpath)
            count += 1

            if count % 100 == 0:
                self.conn.commit()
                print(f"[INFO] Updated commits_fix for {count} repositories...")

        self.conn.commit()
        print(f"[INFO] Updated commits_fix for {count} repositories total")
        return count

    def _normalizeUrlForCache(self, url: str) -> str:
        """Remove fragmento (#section) da URL para evitar verificar o mesmo recurso múltiplas vezes."""
        fragment_pos = url.find("#")
        return url[:fragment_pos] if fragment_pos != -1 else url

    def getUrlCache(self, url: str) -> bool | None:
        """
        Retorna o resultado do cache ou None se não existir.

        Args:
            url: URL a verificar no cache

        Returns:
            True se tem exploit, False se não tem, None se não está no cache
        """
        url = self._normalizeUrlForCache(url)
        self.cursor.execute("SELECT has_exploit FROM url_cache WHERE url = ?", (url,))
        row = self.cursor.fetchone()
        return row[0] if row else None

    def setUrlCache(self, url: str, has_exploit: bool) -> None:
        """
        Salva resultado da verificação de URL no cache.

        Args:
            url: URL verificada
            has_exploit: True se contém exploit, False caso contrário
        """
        url = self._normalizeUrlForCache(url)
        self.cursor.execute(
            """
        INSERT OR REPLACE INTO url_cache (url, has_exploit, verified_at)
        VALUES (?, ?, ?)
        """,
            (url, has_exploit, datetime.now(timezone.utc).isoformat()),
        )

    def getNpmRepoFromCache(self, name: str) -> tuple[bool, str | None]:
        """
        Repositório canônico de um pacote npm no cache.

        Returns:
            (cached, fullpath): cached=False quando não há linha (ainda não
            verificado); cached=True com fullpath podendo ser None ("verificado,
            sem repo GitHub conhecido").
        """
        self.cursor.execute(
            "SELECT fullpath FROM npm_repo_cache WHERE name = ?", (name,)
        )
        row = self.cursor.fetchone()
        if row is None:
            return False, None
        return True, row[0]

    def setNpmRepoCache(self, name: str, fullpath: str | None) -> None:
        """Grava o repositório canônico (ou None) de um pacote npm no cache."""
        self.cursor.execute(
            """
        INSERT OR REPLACE INTO npm_repo_cache (name, fullpath, checked_at)
        VALUES (?, ?, ?)
        """,
            (name, fullpath, datetime.now(timezone.utc).isoformat()),
        )

    def complementCVE(
        self, dataReferences: list, persist_repositories: bool = True
    ) -> dict:
        """
        Processa referências de uma CVE e extrai dados complementares:
        - repository_fullpath: repositório do GitHub relacionado
        - exists_commit: se tem commit de fix
        - exists_exploit: se tem exploit
        - list_commit: lista de URLs de commits
        - list_exploit: lista de URLs de exploits
        """
        complementData = {
            "repository_fullpath": None,
            "repository_fullpaths": [],
            "wordpress_fullpaths": [],
            "exists_commit": False,
            "exists_exploit": False,
            "list_commit": [],
            "list_exploit": [],
        }

        # Extrai fullpaths de repositórios das referências
        fullpaths = GitHubExtractor.extractFromReferences(dataReferences)
        complementData["repository_fullpaths"] = fullpaths
        if fullpaths:
            # Pega o primeiro (mais relevante)
            complementData["repository_fullpath"] = fullpaths[0]
            if persist_repositories:
                # Insere todos os repositórios encontrados na tabela
                for fullpath in fullpaths:
                    self.insertRepository(fullpath)

        # Ecossistema WordPress: a CVE é classificada quando extraímos um slug de plugin.
        # Plugins viram "repositórios" sintéticos (wordpress.org/plugins/<slug>) já marcados
        # como existentes (is_exists=1), pois não passam pela verificação GraphQL do GitHub.
        wp_slugs = WordPressExtractor.extractFromReferences(dataReferences)
        wp_fullpaths = [WordPressExtractor.fullpathFromSlug(slug) for slug in wp_slugs]
        complementData["wordpress_fullpaths"] = wp_fullpaths
        if wp_fullpaths and persist_repositories:
            for slug in wp_slugs:
                self.insertWordpressRepository(slug)

        for reference in dataReferences:
            url = reference.get("url", "")
            tags = reference.get("tags", [])

            # Pegando Commits do GitHub
            if "github.com" in url and "/commit/" in url:
                complementData["exists_commit"] = True
                complementData["list_commit"].append(url)
            # Changesets do Trac de plugins WordPress são "commits" de fix (cobre /changeset/ e /changeset?)
            elif "trac.wordpress.org/changeset" in url.lower():
                complementData["exists_commit"] = True
                complementData["list_commit"].append(url)
            elif "exploit" in tags:
                complementData["exists_exploit"] = True
                complementData["list_exploit"].append(url)
            # Notei que quando não tem tag com exploit, mas tem outras tags não é um exploit. Por isso se for 0 eu busco nesse link
            elif len(tags) == 0:
                # Verifica no cache primeiro
                cached = self.getUrlCache(url)
                if cached is not None:
                    # Já foi verificado antes
                    if cached:
                        complementData["exists_exploit"] = True
                        complementData["list_exploit"].append(url)
                else:
                    # Não está no cache, faz a verificação (usa URL sem fragmento)
                    url_to_verify = self._normalizeUrlForCache(url)
                    try:
                        result = findExploits().run(url_to_verify)
                    except Exception as e:
                        print(
                            f"[WARN] Exploit verification failed for {url_to_verify}: {e}"
                        )
                        result = False
                    self.setUrlCache(url, result)
                    if result:
                        complementData["exists_exploit"] = True
                        complementData["list_exploit"].append(url)

        return complementData

    def insertCVE(self, data: dict, complement: dict | None = None) -> None:
        """
        Insere um CVE nas tabelas normalizadas:
        - cves (dados principais + complementares)
        - cve_scores (CVSS scores)
        - cve_cwes (CWE IDs)
        - cve_affected (produtos afetados)
        - cve_repositories (relação com repositórios)
        """
        try:
            cve_id = data.get("cve_id")
            if not cve_id:
                return

            # Processa dados complementares (exploit, commit, repository)
            references = data.get("references", [])
            if complement is None:
                complement = self.complementCVE(references, persist_repositories=True)
            else:
                for fullpath in complement.get("repository_fullpaths", []):
                    self.insertRepository(fullpath)
                for fullpath in complement.get("wordpress_fullpaths", []):
                    slug = fullpath.split("/")[-1]
                    self.insertWordpressRepository(slug)

            # Converte para JSON
            references_json = json.dumps(references)
            list_exploit_json = json.dumps(complement["list_exploit"])
            list_commit_json = json.dumps(complement["list_commit"])

            # Insert CVE principal com dados complementares
            self.cursor.execute(
                """
            INSERT OR REPLACE INTO cves 
            (cve_id, state, date_published, date_updated, date_reserved, title, description,
             exists_exploit, exists_commit, list_exploit, list_commit, list_references)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
                (
                    cve_id,
                    data.get("state"),
                    data.get("published"),
                    data.get("updated"),
                    data.get("reserved"),
                    data.get("title"),
                    data.get("description"),
                    complement["exists_exploit"],
                    complement["exists_commit"],
                    list_exploit_json,
                    list_commit_json,
                    references_json,
                ),
            )

            # Delete dados antigos das tabelas relacionadas (para UPDATE)
            self.cursor.execute("DELETE FROM cve_scores WHERE cve_id = ?", (cve_id,))
            self.cursor.execute("DELETE FROM cve_cwes WHERE cve_id = ?", (cve_id,))
            self.cursor.execute("DELETE FROM cve_affected WHERE cve_id = ?", (cve_id,))
            self.cursor.execute(
                "DELETE FROM cve_repositories WHERE cve_id = ?", (cve_id,)
            )

            # Insert CVSS scores
            for cvss in data.get("cvss", []):
                self.cursor.execute(
                    """
                INSERT INTO cve_scores (cve_id, version, score)
                VALUES (?, ?, ?)
                """,
                    (cve_id, cvss.get("version"), cvss.get("score")),
                )

            # Insert CWEs
            for cwe_id in data.get("cwe_ids", []):
                if cwe_id:
                    self.cursor.execute(
                        """
                    INSERT OR IGNORE INTO cve_cwes (cve_id, cwe_id)
                    VALUES (?, ?)
                    """,
                        (cve_id, cwe_id),
                    )

            # Insert Affected Products
            for affected in data.get("affected", []):
                self.cursor.execute(
                    """
                INSERT OR IGNORE INTO cve_affected (cve_id, vendor, product)
                VALUES (?, ?, ?)
                """,
                    (cve_id, affected.get("vendor"), affected.get("product")),
                )

            # Insert relação CVE <-> Repositório (se existir)
            if complement["repository_fullpath"]:
                # Determina o tipo de relação baseado nos dados
                relation_type = "referenced"
                if complement["exists_commit"]:
                    relation_type = "fix_commit"

                self.cursor.execute(
                    """
                INSERT OR IGNORE INTO cve_repositories (cve_id, repository_fullpath, relation_type)
                VALUES (?, ?, ?)
                """,
                    (cve_id, complement["repository_fullpath"], relation_type),
                )

            # Insert relação CVE <-> Plugin WordPress (pode haver vários por CVE).
            # Usa 'fix_commit' quando há um changeset Trac do plugin em list_commit, senão 'referenced'.
            list_commit_blob = " ".join(complement.get("list_commit", []))
            for wp_fullpath in complement.get("wordpress_fullpaths", []):
                slug = wp_fullpath.split("/")[-1]
                wp_relation = (
                    "fix_commit"
                    if (
                        "trac.wordpress.org/changeset" in list_commit_blob.lower()
                        and slug in list_commit_blob.lower()
                    )
                    else "referenced"
                )
                self.cursor.execute(
                    """
                INSERT OR IGNORE INTO cve_repositories (cve_id, repository_fullpath, relation_type)
                VALUES (?, ?, ?)
                """,
                    (cve_id, wp_fullpath, wp_relation),
                )

        except sqlite3.Error as e:
            print(f"[WARN] Failed to insert {cve_id}: {e}")

    # --- Helpers de enriquecimento (fontes complementares: GHSA, PoC-in-GitHub) ---

    @staticmethod
    def _fullpathFromUrl(url: str) -> str | None:
        """Extrai 'owner/repo' de qualquer URL do GitHub (inclusive raiz do repo)."""
        if not url or "github.com" not in url.lower():
            return None
        match = re.search(r"github\.com/([^/\s]+)/([^/\s#?]+)", url, re.IGNORECASE)
        if not match:
            return None
        owner = match.group(1).lower()
        repo = match.group(2).lower()
        if repo.endswith(".git"):
            repo = repo[:-4]
        if owner in (
            "sponsors",
            "orgs",
            "topics",
            "collections",
            "marketplace",
            "about",
            "settings",
            "advisories",
            "security",
        ):
            return None
        return f"{owner}/{repo}"

    def enrichPackage(
        self,
        fullpath: str,
        ecosystem: str,
        package_url: str | None,
        downloads: int | None,
    ) -> bool:
        """
        Enriquece um repositório GitHub já existente com metadados de pacote
        (npm/Packagist): marca o ecossistema, a URL do pacote no registro e a
        contagem de downloads. Só atualiza repos já verificados (is_exists=1),
        nunca cria linhas novas. COALESCE preserva valores já gravados quando a
        fonte atual não tem o dado. Retorna True se alguma linha foi alterada.
        """
        if not fullpath:
            return False
        self.cursor.execute(
            """
            UPDATE repositories SET
                ecosystem = ?,
                package_url = COALESCE(?, package_url),
                downloads = COALESCE(?, downloads)
            WHERE fullpath = ? AND is_exists = 1
            """,
            (ecosystem, package_url, downloads, fullpath),
        )
        return self.cursor.rowcount > 0

    def getReposNeedingManifestScan(self, limit: int) -> list[str]:
        """
        Repos GitHub verificados ainda não varridos (sem linha em repo_manifests).
        Exclui pseudo-repos do WordPress, que não existem no GitHub. Resumível:
        repos com falha transitória ficam sem linha e reaparecem no próximo run.
        """
        self.cursor.execute(
            """
            SELECT r.fullpath FROM repositories r
            WHERE r.is_exists = 1
              AND COALESCE(r.ecosystem, 'github') != 'wordpress'
              AND r.fullpath LIKE '%/%'
              AND NOT EXISTS (
                  SELECT 1 FROM repo_manifests m WHERE m.fullpath = r.fullpath
              )
            LIMIT ?
            """,
            (limit,),
        )
        return [row[0] for row in self.cursor.fetchall() if row[0]]

    def saveRepoManifest(
        self,
        fullpath: str,
        npm_name: str | None,
        composer_name: str | None,
        default_branch: str | None,
    ) -> None:
        """Grava (definitivamente) o resultado da varredura do manifesto de um repo."""
        self.cursor.execute(
            """
            INSERT OR REPLACE INTO repo_manifests
                (fullpath, npm_name, composer_name, default_branch, checked_at)
            VALUES (?, ?, ?, ?, ?)
            """,
            (
                fullpath,
                npm_name,
                composer_name,
                default_branch,
                datetime.now(timezone.utc).isoformat(),
            ),
        )

    def overrideManifestNpmName(self, fullpath: str, npm_name: str) -> bool:
        """
        Define/sobrescreve APENAS o npm_name canônico de um repo em repo_manifests,
        preservando composer_name/default_branch (UPSERT). Usado pela fonte OSV (npm),
        cujo mapeamento CVE->pacote é mais confiável que o manifesto raiz lido por
        RepoManifestScanner. Retorna True quando o nome de fato mudou.
        """
        if not fullpath or not npm_name:
            return False
        self.cursor.execute(
            """
            INSERT INTO repo_manifests (fullpath, npm_name, checked_at)
            VALUES (?, ?, ?)
            ON CONFLICT(fullpath) DO UPDATE SET
                npm_name = excluded.npm_name,
                checked_at = excluded.checked_at
            WHERE repo_manifests.npm_name IS NOT excluded.npm_name
            """,
            (fullpath, npm_name, datetime.now(timezone.utc).isoformat()),
        )
        return self.cursor.rowcount > 0

    def getCveGithubRepos(self, cve_id: str) -> list[str]:
        """
        Repositórios GitHub (owner/repo) relacionados a um CVE, em qualquer
        relation_type. Filtra pseudo-repos do WordPress (wordpress.org/plugins/<slug>,
        que têm 2 barras) exigindo exatamente uma '/'.
        """
        self.cursor.execute(
            "SELECT repository_fullpath FROM cve_repositories WHERE cve_id = ?",
            (cve_id,),
        )
        return [
            row[0]
            for row in self.cursor.fetchall()
            if row[0] and row[0].count("/") == 1
        ]

    def resetScannedPackageEnrichment(
        self, ecosystem: str, missing_name_column: str | None = None
    ) -> int:
        """
        Reverte para 'github' (limpando package_url/downloads) os repos JÁ VARRIDOS
        (presentes em repo_manifests) cujo ecossistema atual é `ecosystem` — removendo
        falsos-positivos da lógica antiga. Toca apenas repos varridos em definitivo,
        nunca os ainda pendentes (migração incremental fica segura).

        Se `missing_name_column` for dado ('npm_name'/'composer_name'), limita aos repos
        cujo nome daquele ecossistema está AUSENTE no cache (definitivamente não são
        pacotes daquele ecossistema, sem precisar revalidar no registro).
        """
        sql = (
            "UPDATE repositories SET ecosystem = 'github', package_url = NULL, downloads = NULL "
            "WHERE ecosystem = ? AND fullpath IN (SELECT fullpath FROM repo_manifests"
        )
        if missing_name_column in ("npm_name", "composer_name"):
            sql += f" WHERE {missing_name_column} IS NULL"
        sql += ")"
        self.cursor.execute(sql, (ecosystem,))
        return self.cursor.rowcount

    def resetRepoToGithub(self, fullpath: str, only_if_ecosystem: str) -> bool:
        """Reverte um único repo para 'github' apenas se o ecossistema atual casar."""
        self.cursor.execute(
            "UPDATE repositories SET ecosystem = 'github', package_url = NULL, downloads = NULL "
            "WHERE fullpath = ? AND ecosystem = ?",
            (fullpath, only_if_ecosystem),
        )
        return self.cursor.rowcount > 0

    def cveExists(self, cve_id: str) -> bool:
        self.cursor.execute("SELECT 1 FROM cves WHERE cve_id = ?", (cve_id,))
        return self.cursor.fetchone() is not None

    def linkRepository(
        self,
        cve_id: str,
        fullpath: str | None,
        relation_type: str,
        mark_exists: int | None = None,
    ) -> None:
        """
        Registra um repositório e sua relação com o CVE.

        mark_exists=None deixa is_exists NULL (o passo 'repos'/GraphQL irá buscar
        metadados). mark_exists=1 marca como existente sem buscar metadados (usado
        para PoCs). A PK de cve_repositories garante que a primeira relation_type
        registrada prevalece (INSERT OR IGNORE).
        """
        if not fullpath:
            return
        if mark_exists is None:
            self.cursor.execute(
                "INSERT OR IGNORE INTO repositories (fullpath) VALUES (?)", (fullpath,)
            )
        else:
            self.cursor.execute(
                "INSERT OR IGNORE INTO repositories (fullpath, is_exists) VALUES (?, ?)",
                (fullpath, mark_exists),
            )
        self.cursor.execute(
            "INSERT OR IGNORE INTO cve_repositories (cve_id, repository_fullpath, relation_type) VALUES (?, ?, ?)",
            (cve_id, fullpath, relation_type),
        )

    def addCwes(self, cve_id: str, cwe_ids: list[str]) -> None:
        """Adiciona CWEs a um CVE existente (idempotente via PRIMARY KEY)."""
        for cwe_id in cwe_ids:
            if cwe_id:
                self.cursor.execute(
                    "INSERT OR IGNORE INTO cve_cwes (cve_id, cwe_id) VALUES (?, ?)",
                    (cve_id, cwe_id),
                )

    def _loadJsonList(self, cve_id: str, column: str) -> list | None:
        """Lê uma coluna JSON (list) de um CVE. Retorna None se o CVE não existir."""
        self.cursor.execute(f"SELECT {column} FROM cves WHERE cve_id = ?", (cve_id,))
        row = self.cursor.fetchone()
        if row is None:
            return None
        try:
            value = json.loads(row[0]) if row[0] else []
        except (json.JSONDecodeError, TypeError):
            value = []
        return value if isinstance(value, list) else []

    def enrichExploitUrls(
        self, cve_id: str, urls: list[str], relation_type: str = "poc"
    ) -> bool:
        """
        Mescla URLs de exploit/PoC no list_exploit de um CVE existente (dedup) e
        seta exists_exploit=1.

        PoCs de exploit (relation_type='poc') NÃO são tratados como repositórios:
        ficam apenas em cves.list_exploit. Para outros papéis (ex.: 'referenced')
        registramos a relação em cve_repositories marcando is_exists=1 (sem buscar
        metadados via GraphQL).
        """
        current = self._loadJsonList(cve_id, "list_exploit")
        if current is None:
            return False
        existing = set(current)
        added = False
        for url in urls:
            if url and url not in existing:
                current.append(url)
                existing.add(url)
                added = True
        if added:
            self.cursor.execute(
                "UPDATE cves SET exists_exploit = 1, list_exploit = ? WHERE cve_id = ?",
                (json.dumps(current), cve_id),
            )
        # PoCs vivem apenas em cves.list_exploit, não são "repositórios relacionados".
        # Só registramos a relação/repositório para papéis reais (ex.: referenced).
        if relation_type != "poc":
            for url in urls:
                self.linkRepository(
                    cve_id, self._fullpathFromUrl(url), relation_type, mark_exists=1
                )
        return added

    def mergeCommitUrls(self, cve_id: str, urls: list[str]) -> bool:
        """Mescla URLs de commit no list_commit de um CVE existente (dedup)."""
        current = self._loadJsonList(cve_id, "list_commit")
        if current is None:
            return False
        existing = set(current)
        added = False
        for url in urls:
            if url and url not in existing:
                current.append(url)
                existing.add(url)
                added = True
        if added:
            self.cursor.execute(
                "UPDATE cves SET exists_commit = 1, list_commit = ? WHERE cve_id = ?",
                (json.dumps(current), cve_id),
            )
        return added

    def mergeReferences(self, cve_id: str, new_refs: list[dict]) -> None:
        """
        Mescla novas referências em list_references (dedup por URL) e, para as
        referências realmente novas, reaproveita complementCVE para extrair
        exploits/commits/repositórios.
        """
        refs = self._loadJsonList(cve_id, "list_references")
        if refs is None:
            return
        existing_urls = {r.get("url") for r in refs if isinstance(r, dict)}
        to_process = []
        for ref in new_refs:
            url = ref.get("url")
            if not url or url in existing_urls:
                continue
            refs.append({"url": url, "tags": ref.get("tags", [])})
            existing_urls.add(url)
            to_process.append(ref)
        if not to_process:
            return
        self.cursor.execute(
            "UPDATE cves SET list_references = ? WHERE cve_id = ?",
            (json.dumps(refs), cve_id),
        )
        complement = self.complementCVE(to_process, persist_repositories=True)
        if complement["list_exploit"]:
            self.enrichExploitUrls(
                cve_id, complement["list_exploit"], relation_type="referenced"
            )
        if complement["list_commit"]:
            self.mergeCommitUrls(cve_id, complement["list_commit"])
        # Vincula os repositórios descobertos nas referências (commit => fix_commit)
        commit_repos = {self._fullpathFromUrl(u) for u in complement["list_commit"]}
        for fullpath in complement.get("repository_fullpaths", []):
            relation = "fix_commit" if fullpath in commit_repos else "referenced"
            self.linkRepository(cve_id, fullpath, relation)

    def addScores(self, cve_id: str, cvss_list: list[dict]) -> None:
        """Adiciona scores CVSS a um CVE existente, evitando duplicar version+score."""
        for cvss in cvss_list:
            version = cvss.get("version")
            score = cvss.get("score")
            self.cursor.execute(
                "SELECT 1 FROM cve_scores WHERE cve_id = ? AND version = ? AND score = ?",
                (cve_id, version, score),
            )
            if self.cursor.fetchone():
                continue
            self.cursor.execute(
                "INSERT INTO cve_scores (cve_id, version, score) VALUES (?, ?, ?)",
                (cve_id, version, score),
            )

    def addAffected(self, cve_id: str, affected_list: list[dict]) -> None:
        """Adiciona produtos afetados a um CVE existente (idempotente via UNIQUE)."""
        for aff in affected_list:
            self.cursor.execute(
                "INSERT OR IGNORE INTO cve_affected (cve_id, vendor, product) VALUES (?, ?, ?)",
                (cve_id, aff.get("vendor"), aff.get("product")),
            )

    def addNucleiTemplates(self, cve_id: str, templates: list[dict]) -> bool:
        """
        Mescla templates Nuclei no list_nuclei de um CVE existente (dedup por
        `path`, a identidade única do arquivo — o mesmo CVE pode ter mais de um
        template, e todos compartilham o mesmo template_id/nome) e seta
        exists_nuclei=1. Espelha enrichExploitUrls: só grava quando o CVE existe
        e há template novo. Cada template é um dict {template_id, path, url}.
        """
        current = self._loadJsonList(cve_id, "list_nuclei")
        if current is None:
            return False
        existing_paths = {t.get("path") for t in current if isinstance(t, dict)}
        added = False
        for tpl in templates:
            if not isinstance(tpl, dict):
                continue
            path = tpl.get("path")
            if path and path in existing_paths:
                continue
            current.append(tpl)
            if path:
                existing_paths.add(path)
            added = True
        if added:
            self.cursor.execute(
                "UPDATE cves SET exists_nuclei = 1, list_nuclei = ? WHERE cve_id = ?",
                (json.dumps(current), cve_id),
            )
        return added


class CVElistV5:
    # Paths centralizados - todos relativos ao root do projeto
    PROJECT_ROOT = Path(__file__).parent.parent.absolute()
    DATA_DIR = PROJECT_ROOT / "data"
    DOWNLOAD_ZIP = DATA_DIR / "cvelistV5_all_CVEs.zip"
    EXTRACTED_FOLDER = DATA_DIR / "cves"
    SQLITE_DB = DATA_DIR / "source.sqlite"

    def __init__(self):
        print(f"[DEBUG] Project root: {self.PROJECT_ROOT}")
        print(f"[DEBUG] Data directory: {self.DATA_DIR}")

    @staticmethod
    def _detect_release_asset_type(asset: dict) -> str | None:
        """
        Classifica asset de release como 'all' ou 'delta' com matching tolerante.
        """
        name = str(asset.get("name", "")).lower()
        download_url = str(asset.get("browser_download_url", "")).lower()
        haystack = f"{name} {download_url}"
        if "all_cves" in haystack or "all-cves" in haystack:
            return "all"
        if "delta_cves" in haystack or "delta-cves" in haystack:
            return "delta"
        return None

    def _extract_release_asset_urls(
        self, release_data: dict
    ) -> tuple[str | None, str | None]:
        all_url = None
        delta_url = None
        for asset in release_data.get("assets", []):
            download_url = asset.get("browser_download_url", "")
            asset_type = self._detect_release_asset_type(asset)
            if asset_type == "all" and not all_url:
                all_url = download_url
            elif asset_type == "delta" and not delta_url:
                delta_url = download_url
            if all_url and delta_url:
                break
        return all_url, delta_url

    @staticmethod
    def _extract_year_from_cve_id(cve_id: str | None) -> int | None:
        if not cve_id:
            return None
        parts = cve_id.upper().split("-")
        if len(parts) != 3 or parts[0] != "CVE":
            return None
        try:
            return int(parts[1])
        except (TypeError, ValueError):
            return None

    @staticmethod
    def _list_years_in_extracted_dataset(folderDatabase: Path) -> list[int]:
        years: set[int] = set()
        for file_path in sorted(folderDatabase.rglob("CVE-*.json")):
            year = CVElistV5._extract_year_from_cve_id(file_path.stem)
            if year is not None:
                years.add(year)
        return sorted(years)

    def _resolve_target_year(
        self,
        db: "databaseSQLite",
        folderDatabase: Path,
        year: int | None = None,
        year_auto: bool = False,
    ) -> int | None:
        if year is not None and year_auto:
            raise ValueError("--year and --year-auto cannot be used together")
        if year is not None:
            return year
        if not year_auto:
            return None

        years = self._list_years_in_extracted_dataset(folderDatabase)
        if not years:
            raise RuntimeError("No CVE years found in extracted dataset")

        progress = db.getSourceInfo("cvelistV5-year-bootstrap")
        next_year = None
        if progress:
            try:
                next_year = int(progress.get("last_release_file") or "")
            except (TypeError, ValueError):
                next_year = None

        if next_year is None:
            return years[0]
        if next_year in years:
            return next_year

        for y in years:
            if y > next_year:
                return y
        return years[-1]

    def listReleases(self) -> dict:
        """
        Retorna metadados completos da release mais recente.

        Returns:
            dict com:
            - all_cves_url: URL do zip completo
            - delta_cves_url: URL do delta
            - created_at: data de criação da release
            - updated_at: data de atualização
        """
        url = "https://api.github.com/repos/CVEProject/cvelistV5/releases/latest"
        response = http_get(url)
        response.raise_for_status()

        release_data = response.json()
        latest_all_url, latest_delta_url = self._extract_release_asset_urls(
            release_data
        )
        result = {
            "all_cves_url": latest_all_url,
            "delta_cves_url": latest_delta_url,
            "created_at": release_data.get("created_at"),
            "updated_at": release_data.get(
                "published_at"
            ),  # published_at é mais confiável
        }

        # Fallback: em alguns snapshots o "latest" não traz ambos os pacotes.
        # Busca algumas releases recentes para completar URLs ausentes.
        if not result["all_cves_url"] or not result["delta_cves_url"]:
            page = 1
            per_page = 30
            while page <= 3 and (
                not result["all_cves_url"] or not result["delta_cves_url"]
            ):
                page_url = (
                    f"https://api.github.com/repos/CVEProject/cvelistV5/releases"
                    f"?per_page={per_page}&page={page}"
                )
                page_response = http_get(page_url)
                page_response.raise_for_status()
                releases = page_response.json()
                if not releases:
                    break
                for release in releases:
                    all_url, delta_url = self._extract_release_asset_urls(release)
                    if all_url and not result["all_cves_url"]:
                        result["all_cves_url"] = all_url
                    if delta_url and not result["delta_cves_url"]:
                        result["delta_cves_url"] = delta_url
                    if result["all_cves_url"] and result["delta_cves_url"]:
                        break
                if len(releases) < per_page:
                    break
                page += 1

        return result

    def getDeltasAfterRelease(self, last_release_file: str) -> list:
        """
        Retorna lista de deltas mais recentes que o last_release_file.
        Busca página por página e para assim que encontrar o último processado.

        Args:
            last_release_file: URL do último arquivo processado

        Returns:
            list de dicts com delta_url e published_at, ordenados do mais antigo ao mais recente
        """
        # Extrai o tag_name da URL do last_release_file
        # Ex: https://github.com/CVEProject/cvelistV5/releases/download/cve_2026-01-18_1600Z/2026-01-18_all_CVEs_at_midnight.zip.zip
        # -> tag: cve_2026-01-18_1600Z
        last_tag = None
        if last_release_file:
            parts = last_release_file.split("/download/")
            if len(parts) > 1:
                last_tag = parts[1].split("/")[0]

        print(f"[DEBUG] Last release tag: {last_tag}")

        deltas_needed = []
        found_last = False
        page = 1
        per_page = 30  # Não precisa de muitos por página

        # Busca página por página até encontrar o last_tag
        while not found_last:
            url = f"https://api.github.com/repos/CVEProject/cvelistV5/releases?per_page={per_page}&page={page}"
            print(f"[DEBUG] Fetching releases page {page}...")

            response = http_get(url)
            response.raise_for_status()

            releases = response.json()
            if not releases:
                print(
                    f"[WARN] No more releases found. Last tag '{last_tag}' not found."
                )
                break

            for release in releases:
                tag = release.get("tag_name")

                # Se encontrou o tag do último processado, para
                if tag == last_tag:
                    found_last = True
                    print(f"[DEBUG] Found last processed tag: {last_tag}")
                    break

                # Coleta delta se tiver URL
                delta_url = None
                for asset in release.get("assets", []):
                    if self._detect_release_asset_type(asset) == "delta":
                        delta_url = asset.get("browser_download_url", "")
                        break

                if delta_url:
                    deltas_needed.append(
                        {
                            "tag_name": tag,
                            "delta_url": delta_url,
                            "published_at": release.get("published_at"),
                        }
                    )

            # Se já encontrou ou não há mais páginas, para
            if found_last or len(releases) < per_page:
                break

            page += 1

        # Inverte para processar do mais antigo ao mais recente
        deltas_needed.reverse()

        print(f"[INFO] Found {len(deltas_needed)} deltas to process")
        for delta in deltas_needed:
            print(f"  - {delta['tag_name']}: {delta['delta_url']}")

        return deltas_needed

    def listRecentDeltas(self, max_deltas: int = 20) -> list[dict]:
        """
        Lista deltas recentes (mais novo -> mais antigo).
        Útil para smoke test quando precisamos encontrar CVEs "completos".
        """
        deltas: list[dict] = []
        page = 1
        per_page = 30

        while len(deltas) < max_deltas:
            url = f"https://api.github.com/repos/CVEProject/cvelistV5/releases?per_page={per_page}&page={page}"
            response = http_get(url)
            response.raise_for_status()
            releases = response.json()
            if not releases:
                break

            for release in releases:
                tag = release.get("tag_name")
                for asset in release.get("assets", []):
                    if self._detect_release_asset_type(asset) == "delta":
                        deltas.append(
                            {
                                "tag_name": tag,
                                "delta_url": asset.get("browser_download_url", ""),
                                "published_at": release.get("published_at"),
                            }
                        )
                        break
                if len(deltas) >= max_deltas:
                    break

            if len(releases) < per_page:
                break
            page += 1

        return deltas

    @staticmethod
    def _bucket_from_cve_id(cve_id: str) -> tuple[str, str]:
        # CVE-2026-25117 -> year=2026, bucket=25xxx
        parts = cve_id.upper().split("-")
        if len(parts) != 3 or parts[0] != "CVE":
            raise ValueError(f"Invalid CVE ID format: {cve_id}")
        year = parts[1]
        num = int(parts[2])
        bucket = f"{num // 1000}xxx"
        return year, bucket

    def fetchCVEById(self, cve_id: str) -> dict:
        cve_id = cve_id.strip().upper()
        year, bucket = self._bucket_from_cve_id(cve_id)

        candidates = [
            f"https://cveawg.mitre.org/api/cve/{cve_id}",
            f"https://raw.githubusercontent.com/CVEProject/cvelistV5/main/cves/{year}/{bucket}/{cve_id}.json",
        ]

        last_error: Exception | None = None
        for url in candidates:
            try:
                response = http_get(url, timeout=30)
                if response.status_code == 404:
                    continue
                response.raise_for_status()
                return response.json()
            except Exception as e:
                last_error = e
                continue

        raise RuntimeError(f"Unable to fetch CVE record for {cve_id}: {last_error}")

    def runByIds(self, cve_ids: list[str]) -> None:
        """
        Importa uma lista fixa de CVE IDs para smoke test.
        """
        if not cve_ids:
            print("[WARN] No CVE IDs provided.")
            return

        start_time = datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")
        print(f"[INFO] Start time: {start_time}")
        print(f"[INFO] Initializing database at {self.SQLITE_DB}")

        db = databaseSQLite(self.SQLITE_DB)
        db.createTable()

        imported = 0
        skipped = 0
        for raw_id in cve_ids:
            cve_id = raw_id.strip().upper()
            if not cve_id:
                continue
            try:
                print(f"[INFO] Fetching {cve_id}...")
                data = self.fetchCVEById(cve_id)
                formatted = self.formatDataVersion5_2(data)
                if not formatted or formatted.get("state") in ["RESERVED", "REJECTED"]:
                    skipped += 1
                    print(
                        f"[INFO] Skipping {cve_id} (state={formatted.get('state') if formatted else 'unknown'})"
                    )
                    continue
                db.insertCVE(formatted)
                imported += 1
                db.conn.commit()
            except Exception as e:
                skipped += 1
                print(f"[WARN] Failed to import {cve_id}: {e}")

        db.updateSource(
            source_name="cvelistV5",
            last_verified=start_time,
            last_updated=start_time,
            last_release_file="hardcoded-cve-ids",
            base_release_file="hardcoded-cve-ids",
        )
        db.conn.close()

        print(f"\n[INFO] ==============================")
        print(f"[INFO] SQLite database saved to: {self.SQLITE_DB}")
        print(f"[INFO] CVEs requested: {len(cve_ids)}")
        print(f"[INFO] CVEs imported: {imported}")
        print(f"[INFO] CVEs skipped/failed: {skipped}")
        print("[INFO] Done!")

    def downloadFile(self, url: str, dest_path: Path) -> Path:
        """
        Baixa um arquivo de uma URL com retry e progress.

        Args:
            url: URL do arquivo a baixar
            dest_path: caminho de destino

        Returns:
            Path do arquivo baixado
        """
        self.DATA_DIR.mkdir(parents=True, exist_ok=True)

        print(f"[INFO] Downloading from: {url}")

        max_retries = 3
        for attempt in range(1, max_retries + 1):
            try:
                with http_get(url, stream=True, timeout=(30, 300)) as response:
                    response.raise_for_status()

                    # Pega o tamanho total
                    total_size = int(response.headers.get("content-length", 0))
                    total_mb = total_size / (1024 * 1024)
                    print(f"[INFO] Total size: {total_mb:.2f} MB")

                    downloaded = 0
                    chunk_size = 1024 * 1024  # 1MB chunks

                    with open(dest_path, "wb") as f:
                        for chunk in response.iter_content(chunk_size=chunk_size):
                            if chunk:
                                f.write(chunk)
                                downloaded += len(chunk)
                                # Progress a cada 10MB
                                if downloaded % (10 * 1024 * 1024) < chunk_size:
                                    progress_mb = downloaded / (1024 * 1024)
                                    percent = (
                                        (downloaded / total_size * 100)
                                        if total_size > 0
                                        else 0
                                    )
                                    print(
                                        f"[INFO] Downloaded: {progress_mb:.2f} MB ({percent:.1f}%)"
                                    )

                    print(
                        f"[INFO] Download completed: {downloaded / (1024 * 1024):.2f} MB"
                    )
                    return dest_path

            except (REQUEST_EXCEPTION, OSError) as e:
                print(f"[WARN] Download failed (attempt {attempt}/{max_retries}): {e}")
                if attempt < max_retries:
                    import time

                    wait_time = 5 * attempt
                    print(f"[INFO] Retrying in {wait_time} seconds...")
                    time.sleep(wait_time)
                    # Remove arquivo parcial
                    if dest_path.exists():
                        dest_path.unlink()
                else:
                    raise Exception(
                        f"Download failed after {max_retries} attempts: {e}"
                    )

        raise Exception(f"Failed to download {url}")

    def unzipDatabase(self, zip_file: Path) -> Path | None:
        """
        Extrai um arquivo zip.

        Returns:
            Path da pasta extraída, ou None se o zip estiver vazio ou inválido
        """
        extract_to = zip_file.parent
        try:
            zip_ref_check = zipfile.ZipFile(zip_file, "r")
            zip_ref_check.close()
        except zipfile.BadZipFile:
            print(f"[WARN] Invalid or empty zip file (skipping delta): {zip_file}")
            return None
        with zipfile.ZipFile(zip_file, "r") as zip_ref:
            file_list = zip_ref.namelist()

            # Verifica se o zip está vazio
            if not file_list:
                print(f"[INFO] Zip file is empty: {zip_file}")
                return None

            # Descobre o nome da pasta raiz do zip
            first_member = file_list[0]
            root_folder = first_member.split("/")[0] if "/" in first_member else ""

            zip_ref.extractall(extract_to)

            # Processa zips internos recursivamente
            for file_name in file_list:
                if file_name.endswith(".zip"):
                    inner_zip_path = extract_to / file_name
                    print(f"[INFO] Unzipping inner file: {file_name}...")
                    extracted_inner = self.unzipDatabase(inner_zip_path)
                    print(f"[INFO] Deleting inner zip: {file_name}")
                    inner_zip_path.unlink()
                    # Retorna o path do zip interno extraído (se não vazio)
                    if extracted_inner:
                        root_folder = extracted_inner.name

        final_path = extract_to / root_folder if root_folder else extract_to
        print(f"[DEBUG] Extracted to: {final_path}")
        return final_path

    def formatDataVersion5_2(self, data: dict) -> dict:
        metadata = data.get("cveMetadata", {})
        cve_id = metadata.get("cveId")
        state = metadata.get("state")
        date_reserved = metadata.get("dateReserved")
        date_published = metadata.get("datePublished")
        date_updated = metadata.get("dateUpdated")

        cna = data.get("containers", {}).get("cna", {})

        # Affected products/versions
        affected = [
            {"product": item.get("product"), "vendor": item.get("vendor")}
            for item in cna.get("affected", [])
        ]

        # CWE IDs - busca em cna E adp
        problem_types = cna.get("problemTypes", []).copy()
        adp_list = data.get("containers", {}).get("adp", [])
        for adp in adp_list:
            problem_types.extend(adp.get("problemTypes", []))

        cwe_ids = []
        for problemType in problem_types:
            for desc in problemType.get("descriptions", []):
                cwe_id = desc.get("cweId")
                if cwe_id:
                    cwe_ids.append(cwe_id)
                else:
                    # Tenta extrair do description com regex
                    description_text = desc.get("description", "")
                    matches = re.findall(r"CWE-(\d+)", description_text, re.IGNORECASE)
                    for match in matches:
                        cwe_ids.append(f"CWE-{match}")

        cwe_ids = list(set(filter(None, cwe_ids)))

        # Description e Title
        descriptions = cna.get("descriptions", [])
        description = descriptions[0].get("value") if descriptions else None
        title = derive_cve_title(cna.get("title"), description)

        # References
        references = [
            {
                "url": ref.get("url"),
                "tags": list(
                    set([tag for tag in ref.get("tags", []) if "x_" not in tag])
                ),
            }
            for ref in cna.get("references", [])
        ]

        # CVSS - tenta pegar do cna, senão busca no adp.
        # Importante: o fallback precisa acontecer quando o CNA não traz um vetor
        # CVSS de verdade, e não apenas quando a lista de metrics está vazia. Muitos
        # CVEs têm no CNA somente uma métrica textual ("other") e o vetor CVSS real
        # fica no container ADP (adicionado pela CISA/ADP).
        def _extract_cvss(metrics: list) -> list:
            return [
                {
                    "vectorString": value.get("vectorString"),
                    "version": value.get("version"),
                    "score": calculateScoreCVSS(
                        value.get("vectorString", ""), value.get("version", "")
                    ),
                }
                for metric in metrics
                for key, value in metric.items()
                if isinstance(value, dict) and "vectorString" in value
            ]

        cvss = _extract_cvss(cna.get("metrics", []))
        if not cvss:
            adp_metrics = []
            for adp in data.get("containers", {}).get("adp", []):
                adp_metrics.extend(adp.get("metrics", []))
            cvss = _extract_cvss(adp_metrics)

        return {
            "cve_id": cve_id,
            "state": state,
            "reserved": date_reserved,
            "published": date_published,
            "updated": date_updated,
            "title": title,
            "description": description,
            "affected": affected,
            "cwe_ids": cwe_ids,
            "references": references,
            "cvss": cvss,
        }

    @staticmethod
    def isCompleteCVE(formatted: dict, complement: dict) -> bool:
        """
        Define se um CVE é "completo" para smoke tests:
        - possui dados básicos
        - possui ao menos 1 score CVSS
        - possui ao menos 1 CWE
        - possui ao menos 1 produto afetado
        - possui repositório relacionado
        - possui commit de fix
        - possui exploit
        """
        if not formatted.get("cve_id"):
            return False
        if not formatted.get("title") or not formatted.get("description"):
            return False
        if not formatted.get("published"):
            return False
        if not formatted.get("cvss"):
            return False
        if not formatted.get("cwe_ids"):
            return False

        affected = formatted.get("affected", [])
        has_affected = any(a.get("vendor") or a.get("product") for a in affected)
        if not has_affected:
            return False

        if not complement.get("repository_fullpath"):
            return False
        if not complement.get("exists_commit"):
            return False
        if not complement.get("exists_exploit"):
            return False

        return True

    def convertJSONToSQLite(
        self,
        folderDatabase: Path,
        db: databaseSQLite,
        max_cves: int | None = None,
        min_pending_repos: int = 0,
        require_complete_cve: bool = False,
        target_complete_cves: int = 1,
        year: int | None = None,
    ) -> dict:
        """
        Converte JSONs de CVE para SQLite.

        Args:
            folderDatabase: pasta com os JSONs extraídos
            db: instância do banco de dados

        Returns:
            int: quantidade de CVEs processados
        """
        base_path = self.DATA_DIR / folderDatabase
        count = 0
        scanned = 0
        batch_size = 1000

        skipped_incomplete = 0

        for file_path in sorted(base_path.rglob("CVE*.json")):
            try:
                with open(file_path, "r", encoding="utf-8") as f:
                    data = json.load(f)
                    formattedData = self.formatDataVersion5_2(data)

                    # Ignora RESERVED e REJECTED
                    if formattedData and formattedData.get("state") not in [
                        "RESERVED",
                        "REJECTED",
                    ]:
                        if year is not None:
                            cve_year = self._extract_year_from_cve_id(
                                formattedData.get("cve_id")
                            )
                            if cve_year != year:
                                continue
                        scanned += 1
                        references = formattedData.get("references", [])
                        complement = db.complementCVE(
                            references,
                            persist_repositories=not require_complete_cve,
                        )

                        if require_complete_cve and not self.isCompleteCVE(
                            formattedData, complement
                        ):
                            skipped_incomplete += 1
                            if max_cves is not None and scanned >= max_cves:
                                print(
                                    f"[INFO] Reached max CVEs scan limit ({max_cves}) in complete-only mode."
                                )
                                break
                            continue

                        db.insertCVE(formattedData, complement=complement)
                        count += 1

                        if require_complete_cve and count >= target_complete_cves:
                            print(
                                f"[INFO] Reached target complete CVEs "
                                f"({count}/{target_complete_cves}). Stopping import."
                            )
                            break

                        # Commit a cada batch_size registros
                        if count % batch_size == 0:
                            db.conn.commit()
                            print(f"[INFO] Processed {count} CVEs...")

                        pending_repos = (
                            db.countPendingRepositories()
                            if min_pending_repos > 0 and (count % 5 == 0 or count == 1)
                            else 0
                        )

                        if min_pending_repos > 0 and pending_repos >= min_pending_repos:
                            print(
                                f"[INFO] Reached pending repositories target "
                                f"({pending_repos}/{min_pending_repos}). Stopping import early."
                            )
                            break

                        if max_cves is not None and count >= max_cves:
                            print(
                                f"[INFO] Reached max CVEs limit ({max_cves}). Stopping import early."
                            )
                            break

                        if (
                            require_complete_cve
                            and max_cves is not None
                            and scanned >= max_cves
                        ):
                            print(
                                f"[INFO] Reached max CVEs scan limit ({max_cves}) in complete-only mode."
                            )
                            break

            except (json.JSONDecodeError, KeyError, IOError, AttributeError) as e:
                print(f"[WARN] Erro ao processar {file_path}: {e}")
                continue

        # Commit final
        db.conn.commit()
        if require_complete_cve:
            print(f"[INFO] Skipped incomplete CVEs: {skipped_incomplete}")
        print(f"[INFO] Total CVEs processed: {count}")
        return {
            "processed": count,
            "scanned": scanned,
            "skipped_incomplete": skipped_incomplete,
        }

    def cleanupExtractedFolder(self, folder: Path) -> None:
        """Remove pasta extraída para liberar espaço."""
        import shutil

        if folder.exists() and folder.is_dir():
            print(f"[INFO] Cleaning up: {folder}")
            shutil.rmtree(folder)

    def run(
        self,
        max_cves: int | None = None,
        force_delta: bool = False,
        min_pending_repos: int = 0,
        require_complete_cve: bool = False,
        target_complete_cves: int = 1,
        max_deltas: int = 5,
        year: int | None = None,
        year_auto: bool = False,
    ) -> None:
        from datetime import datetime, timezone
        import shutil

        # Timestamp de início
        start_time = datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")
        print(f"[INFO] Start time: {start_time}")

        # Inicializa o banco de dados
        print(f"[INFO] Initializing database at {self.SQLITE_DB}")
        db = databaseSQLite(self.SQLITE_DB)
        db.createTable()

        # Verifica se já existe base_release_file
        source_info = db.getSourceInfo("cvelistV5")
        has_base = source_info and source_info.get("base_release_file")
        last_release_file = (
            source_info.get("last_release_file") if source_info else None
        )

        total_count = 0
        total_scanned = 0
        total_skipped_incomplete = 0

        if has_base:
            # Modo Delta: busca todos os deltas desde o último processado
            print(f"[INFO] Base release exists: {source_info.get('base_release_file')}")
            print(f"[INFO] Last release processed: {last_release_file}")

            deltas = self.getDeltasAfterRelease(last_release_file)

            if not deltas:
                print("[INFO] No new deltas to process. Database is up-to-date!")
            else:
                print(f"[INFO] Processing {len(deltas)} delta(s)...")

                for i, delta in enumerate(deltas, 1):
                    print(
                        f"\n[INFO] === Processing delta {i}/{len(deltas)}: {delta['tag_name']} ==="
                    )

                    delta_url = delta["delta_url"]
                    dest_path = self.DATA_DIR / f"delta_{delta['tag_name']}.zip"

                    # Download delta
                    pathFileZip = self.downloadFile(delta_url, dest_path)

                    # Unzip
                    print(f"[INFO] Unzipping delta {delta['tag_name']}...")
                    folderDatabase = self.unzipDatabase(pathFileZip)

                    # Verifica se o delta está vazio
                    if folderDatabase is None:
                        print(
                            f"[INFO] Delta {delta['tag_name']} is empty (0 CVEs changed). Skipping..."
                        )
                        count = 0
                    else:
                        print(f"[INFO] Delta extracted to: {folderDatabase}")

                        # Convert JSONs to SQLite
                        print(f"[INFO] Converting delta JSON to SQLite...")
                        remaining = (
                            None
                            if max_cves is None
                            else max(0, max_cves - total_scanned)
                        )
                        result = self.convertJSONToSQLite(
                            folderDatabase,
                            db,
                            max_cves=remaining,
                            min_pending_repos=min_pending_repos,
                            require_complete_cve=require_complete_cve,
                            target_complete_cves=target_complete_cves,
                        )
                        count = result["processed"]
                        total_count += count
                        total_scanned += result["scanned"]
                        total_skipped_incomplete += result["skipped_incomplete"]

                        # Cleanup pasta extraída
                        self.cleanupExtractedFolder(folderDatabase)

                    # Atualiza last_release_file após cada delta processado (mesmo se vazio)
                    db.updateSource(
                        source_name="cvelistV5",
                        last_verified=start_time,
                        last_updated=delta.get("published_at", ""),
                        last_release_file=delta_url,
                        base_release_file=None,  # Mantém o existente
                    )

                    print(f"[INFO] Delta {delta['tag_name']} processed: {count} CVEs")

                    if require_complete_cve and total_count >= target_complete_cves:
                        print(
                            f"[INFO] Reached target complete CVEs "
                            f"({total_count}/{target_complete_cves}) during delta processing."
                        )
                        if pathFileZip.exists():
                            pathFileZip.unlink()
                        break

                    if (
                        require_complete_cve
                        and max_cves is not None
                        and total_scanned >= max_cves
                    ):
                        print(
                            f"[INFO] Reached max CVEs scan limit ({max_cves}) during delta processing."
                        )
                        if pathFileZip.exists():
                            pathFileZip.unlink()
                        break

                    if (
                        not require_complete_cve
                        and max_cves is not None
                        and total_count >= max_cves
                    ):
                        print(
                            f"[INFO] Reached max CVEs limit ({max_cves}) during delta processing."
                        )
                        # Cleanup: remove zip
                        if pathFileZip.exists():
                            pathFileZip.unlink()
                        break

                    # Cleanup: remove zip
                    if pathFileZip.exists():
                        pathFileZip.unlink()
        else:
            # Modo Full: primeira execução, baixa dataset completo
            print("[INFO] No base release found. Downloading initial dataset...")

            release_info = self.listReleases()
            if force_delta:
                if require_complete_cve:
                    recent_deltas = self.listRecentDeltas(max_deltas=max_deltas)
                    if not recent_deltas:
                        raise Exception("No recent delta_CVEs URL found")
                    print(
                        f"[INFO] force_delta + complete mode: scanning up to "
                        f"{len(recent_deltas)} recent deltas for complete CVEs"
                    )

                    for i, delta in enumerate(recent_deltas, 1):
                        if require_complete_cve and total_count >= target_complete_cves:
                            break
                        if (
                            require_complete_cve
                            and max_cves is not None
                            and total_scanned >= max_cves
                        ):
                            break

                        print(
                            f"\n[INFO] === Processing recent delta {i}/{len(recent_deltas)}: {delta['tag_name']} ==="
                        )
                        delta_url = delta["delta_url"]
                        dest_path = self.DATA_DIR / f"delta_{delta['tag_name']}.zip"
                        pathFileZip = self.downloadFile(delta_url, dest_path)
                        print(f"[INFO] Unzipping delta {delta['tag_name']}...")
                        folderDatabase = self.unzipDatabase(pathFileZip)

                        if folderDatabase is not None:
                            remaining = (
                                None
                                if max_cves is None
                                else max(0, max_cves - total_scanned)
                            )
                            result = self.convertJSONToSQLite(
                                folderDatabase,
                                db,
                                max_cves=remaining,
                                min_pending_repos=min_pending_repos,
                                require_complete_cve=require_complete_cve,
                                target_complete_cves=target_complete_cves,
                            )
                            total_count += result["processed"]
                            total_scanned += result["scanned"]
                            total_skipped_incomplete += result["skipped_incomplete"]
                            self.cleanupExtractedFolder(folderDatabase)

                        db.updateSource(
                            source_name="cvelistV5",
                            last_verified=start_time,
                            last_updated=delta.get("published_at", ""),
                            last_release_file=delta_url,
                            base_release_file=delta_url,
                        )

                        if pathFileZip.exists():
                            pathFileZip.unlink()

                    db.conn.close()
                    print(f"\n[INFO] ==============================")
                    print(f"[INFO] SQLite database saved to: {self.SQLITE_DB}")
                    print(f"[INFO] Total CVEs processed: {total_count}")
                    print(f"[INFO] Total CVEs scanned: {total_scanned}")
                    if require_complete_cve:
                        print(
                            f"[INFO] Total CVEs skipped (incomplete): {total_skipped_incomplete}"
                        )
                    print("[INFO] Done!")
                    return
                download_url = release_info.get("delta_cves_url")
                if not download_url:
                    raise Exception("No delta_CVEs URL found in latest release")
                print(
                    "[INFO] force_delta enabled: using delta package instead of full package"
                )
            else:
                download_url = release_info.get("all_cves_url")
                if not download_url:
                    raise Exception("No all_CVEs URL found in latest release")

            dest_path = self.DOWNLOAD_ZIP

            # Download
            pathFileZip = self.downloadFile(download_url, dest_path)

            # Unzip
            print("[INFO] Unzipping full database...")
            folderDatabase = self.unzipDatabase(pathFileZip)
            print(f"[INFO] Database extracted to: {folderDatabase}")

            target_year = self._resolve_target_year(
                db=db,
                folderDatabase=folderDatabase,
                year=year,
                year_auto=year_auto,
            )
            if target_year is not None:
                print(
                    f"[INFO] Year filter enabled. Importing only CVEs from year {target_year}"
                )

            # Convert JSONs to SQLite
            print("[INFO] Converting JSON to SQLite...")
            result = self.convertJSONToSQLite(
                folderDatabase,
                db,
                max_cves=max_cves,
                min_pending_repos=min_pending_repos,
                require_complete_cve=require_complete_cve,
                target_complete_cves=target_complete_cves,
                year=target_year,
            )
            total_count = result["processed"]
            total_scanned = result["scanned"]
            total_skipped_incomplete = result["skipped_incomplete"]

            if year_auto:
                years = self._list_years_in_extracted_dataset(folderDatabase)
                if not years:
                    raise RuntimeError(
                        "No CVE years found while persisting year-auto progress"
                    )
                if target_year not in years:
                    raise RuntimeError(
                        f"Resolved target year {target_year} not found in extracted dataset years={years}"
                    )
                idx = years.index(target_year)
                next_year = years[idx + 1] if idx + 1 < len(years) else None
                if next_year is None:
                    db.updateSource(
                        source_name="cvelistV5",
                        last_verified=start_time,
                        last_updated=release_info.get("updated_at", ""),
                        last_release_file=download_url,
                        base_release_file=download_url,
                    )
                    db.updateSource(
                        source_name="cvelistV5-year-bootstrap",
                        last_verified=start_time,
                        last_updated=release_info.get("updated_at", ""),
                        last_release_file="completed",
                        base_release_file="completed",
                    )
                    print(
                        "[INFO] Yearly bootstrap completed. Next runs can use delta mode."
                    )
                else:
                    db.updateSource(
                        source_name="cvelistV5-year-bootstrap",
                        last_verified=start_time,
                        last_updated=release_info.get("updated_at", ""),
                        last_release_file=str(next_year),
                        base_release_file=str(target_year),
                    )
                    print(
                        f"[INFO] Yearly bootstrap progress saved. "
                        f"Next run with --year-auto will process year {next_year}."
                    )
            else:
                # Define base_release_file e last_release_file como o mesmo (primeira vez)
                db.updateSource(
                    source_name="cvelistV5",
                    last_verified=start_time,
                    last_updated=release_info.get("updated_at", ""),
                    last_release_file=download_url,
                    base_release_file=download_url,
                )

            # Cleanup
            if pathFileZip.exists():
                pathFileZip.unlink()
            self.cleanupExtractedFolder(folderDatabase)

        db.conn.close()
        print(f"\n[INFO] ==============================")
        print(f"[INFO] SQLite database saved to: {self.SQLITE_DB}")
        print(f"[INFO] Total CVEs processed: {total_count}")
        print(f"[INFO] Total CVEs scanned: {total_scanned}")
        if require_complete_cve:
            print(f"[INFO] Total CVEs skipped (incomplete): {total_skipped_incomplete}")
        print("[INFO] Done!")


class findExploits:
    EXPLOITDB_EXPLOITS = "exploit-db.com/exploits/"
    HUNTR_EXPLOITS = "huntr.com/bounties/"
    HUNTR_EXPLOITS_LEGACY = "huntr.dev/bounties/"  # URLs antigas ainda usam huntr.dev
    GHSA_EXPLOITS = "/security/advisories/"
    MEDIUM_EXPLOITS = "medium.com/"
    SNYK_EXPLOITS = "snyk.io/vuln/"
    WPSCAN_EXPLOITS = "wpscan.com/vulnerability/"
    GITHUB_PATH = "github.com/"  # Para arquivos .md, .txt, etc no GitHub
    PACKETSTORM_EXPLOITS = ["packetstormsecurity.com/", "packetstorm.news/"]
    HACKERONE_EXPLOITS = "hackerone.com/reports/"
    # Palavras-chave para identificar exploits (devem estar isoladas)
    EXPLOIT_KEYWORDS = [
        "poc",
        "curl",  # Em pocs é comum ver o curl para executar o exploit
        "payload",
        "steps to reproduce",
        "steps to exploit",
        "how i hacked",
        "how to reproduce",
        "demo video",
        "proof-of-concept",
        "proof of concept",
        "proof of vulnerability",
    ]

    # Extensões de arquivo que podem conter exploits no GitHub
    GITHUB_EXPLOIT_EXTENSIONS = [".md", ".txt"]

    HEADERS_BROWSER = {
        "User-Agent": "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/144.0.0.0 Safari/537.36",
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8",
        "Accept-Language": "en-US,en;q=0.5",
    }

    # EM um futuro quando for acessar todos os blogs isso será utilizado
    DENYLIST_URLS = [
        "plugins.trac.wordpress.org/",  # código-fonte de plugins WP (arquivo vulnerável / patch), nunca exploit
        "plugins.svn.wordpress.org/",  # repositório SVN bruto de plugins WP, nunca exploit
        "zerodayinitiative.com/",
        "snyk.io/",
        "chromium.org/",
        "ecostruxureit.com/",
        "openwall.com/",
        "wpscan.com/",
        "hitachi.com/",
        "hitachi.co.jp/",
        "vuldb.com/",
        "github.com/",
        "netapp.com/",
        "netgear.com/",
        "foxit.com/",
        "mattermost.com/",
        "hpe.com/",
        ".se.com/",
        "ibm.com/",
        "ibmcloud.com/",
        "qualcomm.com/",
        "dell.com/",
        "delltechnologies.com/",
        "facebook.com/",
        "microsoft.com/",
        "oracle.com/",
        "redhat.com/",
        "ubuntu.com/",
        "vmware.com/",
        "patchstack.com/",
        "jenkins.io/",
        "debian.org/",
        "apple.com/",
        "dlink.com/",
        "cisco.com/",
        "gitlab.com/",
        "google.com/",
        "googleblog.com/",
        "docker.com/",
        "mozilla.org/",
        "kernel.org/",
        "linux.org/",
        "linuxfoundation.org/",
        "linuxfoundation.org/",
        "cisa.gov/",
        "nist.gov/",
        "nsa.gov/",
        "nvd.nist.gov/",
        "nvd.nist.gov/",
        "adobe.com/",
        "twitter.com/",
        "instagram.com/",
        "linkedin.com/",
        "youtube.com/",
        "tiktok.com/",
        "reddit.com/",
        "pinterest.com/",
        "wordfence.com/",
        "intel.com/",
        "amd.com/",
        "nvidia.com/",
        "arm.com/",
        "trendmicro.com/",
        "autodesk.com/",
        "sap.com/",
        "huawei.com/",
        "seclists.org/",
        "gentoo.org/",
        "fedoraproject.org/",
        "archlinux.org/",
        "siemens.com/",
        "custhelp.com/",
        "apache.org/",
        "samsung.com/",
        "lg.com/",
        "sony.com/",
        "toshiba.com/",
        "panasonic.com/",
        "sharp.com/",
        "jvc.com/",
        "yamaha.com/",
        "roku.com/",
        "android.com/",
        "ios.com/",
        "windows.com/",
        "macos.com/",
        "linux.com/",
        "bsd.com/",
        "openbsd.org/",
        "freebsd.org/",
        "netbsd.org/",
        "samsung.com/",
        "samsungmobile.com/",
        "googlesource.com/",
    ]

    def _containsExploitKeywords(self, text: str) -> bool:
        """
        Verifica se o texto contém palavras-chave de exploit.
        As palavras devem estar isoladas (não precedidas/seguidas por caracteres alfanuméricos).
        """
        text_lower = text.lower()
        for keyword in self.EXPLOIT_KEYWORDS:
            # Regex: \b = word boundary (início/fim de palavra)
            # Isso garante que a keyword não está colada em outro texto alfanumérico
            pattern = r"(?<![a-zA-Z0-9])" + re.escape(keyword) + r"(?![a-zA-Z])"
            if re.search(pattern, text_lower):
                return True
        return False

    def _convertGithubBlobToRaw(self, url: str) -> str | None:
        """
        Converte URL do GitHub /blob/ para raw.githubusercontent.com

        Ex: https://github.com/USER/REPO/blob/main/path/file.md
        ->  https://raw.githubusercontent.com/USER/REPO/refs/heads/main/path/file.md

        Returns:
            URL convertida ou None se não for um arquivo válido
        """
        # Verifica se é uma URL de arquivo (contém /blob/)
        if "/blob/" not in url:
            return None

        # Verifica se termina com uma extensão de arquivo válida
        url_lower = url.lower()
        if not any(ext in url_lower for ext in self.GITHUB_EXPLOIT_EXTENSIONS):
            return None

        # Converte: github.com/USER/REPO/blob/BRANCH/PATH
        # Para: raw.githubusercontent.com/USER/REPO/refs/heads/BRANCH/PATH
        raw_url = url.replace("github.com", "raw.githubusercontent.com")
        raw_url = raw_url.replace("/blob/", "/refs/heads/")

        return raw_url

    def verifyGithubFile(self, url: str) -> bool:
        """
        Verifica se um arquivo no GitHub contém informações de exploit.
        Converte para raw URL e busca keywords no texto.
        """
        print(f"[INFO] Verifying GitHub file {url}")
        try:
            raw_url = self._convertGithubBlobToRaw(url)
            if not raw_url:
                return False

            response = http_get(raw_url, headers=self.HEADERS_BROWSER, timeout=15)
            response.raise_for_status()

            # Arquivo raw é texto puro, busca keywords diretamente
            return self._containsExploitKeywords(response.text)

        except REQUEST_EXCEPTION as e:
            print(f"[WARN] Failed to verify GitHub file {url}: {e}")
            return False

    # Extensões de arquivos binários que não devem ser parseados como HTML
    BINARY_EXTENSIONS = [
        ".pdf",
        ".zip",
        ".gz",
        ".tar",
        ".rar",
        ".exe",
        ".dll",
        ".bin",
        ".iso",
        ".img",
        ".dmg",
        ".apk",
        ".jar",
        ".war",
        ".ear",
        ".deb",
        ".rpm",
        ".msi",
        ".7z",
        ".bz2",
        ".xz",
        ".doc",
        ".docx",
        ".xls",
        ".xlsx",
        ".ppt",
        ".pptx",
    ]

    def verifyBlog(self, url: str) -> bool:
        """
        Verifica se a de qualquer site como blog, forum, etc. contém informações de exploit.
        Faz request, parse do HTML, e busca por palavras-chave.
        """
        # Ignora arquivos binários
        url_lower = url.lower()
        if any(url_lower.endswith(ext) for ext in self.BINARY_EXTENSIONS):
            print(f"[INFO] Skipping binary file {url}")
            return False

        print(f"[INFO] Verifying blog URL {url}")
        try:
            response = http_get(url, headers=self.HEADERS_BROWSER, timeout=15)
            response.raise_for_status()

            # Verifica Content-Type para evitar parse de binários
            content_type = response.headers.get("Content-Type", "").lower()
            if not any(t in content_type for t in ["text/", "html", "json", "xml"]):
                print(f"[INFO] Skipping non-text content: {content_type}")
                return False

            # Tenta parse HTML, se falhar usa texto bruto
            try:
                if BeautifulSoup is None:
                    text = response.text
                else:
                    soup = BeautifulSoup(response.text, "html.parser")
                    # Remove scripts e styles
                    for element in soup(["script", "style", "noscript"]):
                        element.decompose()
                    # Extrai texto limpo
                    text = soup.get_text(separator=" ", strip=True)
            except Exception as parse_error:
                # Se falhar o parse HTML (ex: arquivo .txt), usa texto bruto
                print(
                    f"[WARN] HTML parse failed for {url}, using raw text: {parse_error}"
                )
                text = response.text

            return self._containsExploitKeywords(text)

        except REQUEST_EXCEPTION as e:
            print(f"[WARN] Failed to verify blog URL {url}: {e}")
            return False

    def verifyHUNTR(self, url: str) -> bool:
        """
        Verifica se a URL do Huntr contém informações de exploit.
        Faz request especial com headers do Next.js e busca keywords na resposta.
        """
        print(f"[INFO] Verifying HUNTR URL {url}")
        try:
            # Converte huntr.dev para huntr.com (URLs antigas)
            request_url = url.replace("huntr.dev", "huntr.com")

            # Extrai o bounty ID da URL
            # Ex: https://huntr.com/bounties/d7b8ea75-c74a-4721-89bb-12e5c80fb0ba
            match = re.search(r"bounties/([a-f0-9-]+)", request_url)
            if not match:
                return False

            bounty_id = match.group(1)

            headers = {
                "User-Agent": "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/144.0.0.0 Safari/537.36",
                "Accept": "text/x-component",
                "Accept-Language": "en-US,en;q=0.5",
                "Content-Type": "text/plain;charset=UTF-8",
                "Next-Action": "beb1d533b815727477b3a692f916569675036c0f",
                "Referer": request_url,
            }

            response = http_post(
                request_url, headers=headers, data=f'["{bounty_id}"]', timeout=15
            )
            response.raise_for_status()

            # Busca keywords diretamente na string de resposta (sem parse)
            return self._containsExploitKeywords(response.text)

        except REQUEST_EXCEPTION as e:
            print(f"[WARN] Failed to verify HUNTR URL {url}: {e}")
            return False

    def verifyPacketStorm(self, url: str) -> bool:
        """
        Verifica se a URL do Packet Storm contém informações de exploit.
        Faz request e busca keywords na resposta.
        """
        print(f"[INFO] Verifying Packet Storm URL {url}")
        try:
            # Cookie necessário para aceitar os termos de serviço
            cookies = {"tos": "20250912"}
            response = http_get(
                url, headers=self.HEADERS_BROWSER, cookies=cookies, timeout=15
            )
            response.raise_for_status()

            # Busca keywords diretamente na string de resposta (sem parse)
            return self._containsExploitKeywords(response.text)

        except REQUEST_EXCEPTION as e:
            print(f"[WARN] Failed to verify Packet Storm URL {url}: {e}")
            return False

    def verifyHackerOne(self, url: str) -> bool:
        """
        Verifica se a URL do Hacker One contém informações de exploit.
        Faz request e busca keywords na resposta.
        """
        print(f"[INFO] Verifying Hacker One URL {url}")
        try:
            response = http_get(url + ".json", headers=self.HEADERS_BROWSER, timeout=15)
            response.raise_for_status()

            # Busca keywords diretamente na string de resposta (sem parse)
            return self._containsExploitKeywords(response.text)

        except REQUEST_EXCEPTION as e:
            print(f"[WARN] Failed to verify Hacker One URL {url}: {e}")
            return False

    def verifyHandler(self, url: str) -> bool:
        """
        Direciona para a função de verificação apropriada baseado na URL.
        """
        url_lower = url.lower()
        if self.EXPLOITDB_EXPLOITS in url_lower or self.MEDIUM_EXPLOITS in url_lower:
            return True
        elif (
            self.HUNTR_EXPLOITS in url_lower or self.HUNTR_EXPLOITS_LEGACY in url_lower
        ):
            return self.verifyHUNTR(url)
        elif self.GHSA_EXPLOITS in url_lower and self.GITHUB_PATH in url_lower:
            return self.verifyBlog(url)
        elif self.GITHUB_PATH in url_lower and "/blob/" in url_lower:
            # Arquivo no GitHub (.md, .txt) - converte para raw e verifica
            return self.verifyGithubFile(url)
        elif any(packetstorm in url_lower for packetstorm in self.PACKETSTORM_EXPLOITS):
            return self.verifyPacketStorm(url)
        elif self.SNYK_EXPLOITS in url_lower or self.WPSCAN_EXPLOITS in url_lower:
            return self.verifyBlog(url)
        elif self.HACKERONE_EXPLOITS in url_lower:
            return self.verifyHackerOne(url)
        else:
            if any(denylist in url_lower for denylist in self.DENYLIST_URLS):
                return False
            else:
                return self.verifyBlog(url)

    def run(self, url: str) -> bool:
        """
        Verifica uma URL e retorna se é um exploit.
        """
        return self.verifyHandler(url)


class GitHubArchiveSource:
    """
    Base para fontes que clonam um repositório GitHub (zip do branch) e, por
    padrão, enriquecem CVEs já existentes no banco. Subclasses podem optar por
    criar CVEs novas (ex.: GitHubAdvisory semeia CVEs publicadas no GitHub
    Advisory antes do cvelist); PoCInGitHub permanece somente enriquecimento.

    Estado é rastreado na tabela `sources` guardando o commit SHA processado em
    `last_release_file`. Na primeira execução faz scan completo (download do zip);
    nas seguintes usa a Compare API para processar só os arquivos alterados,
    buscando cada um via raw.githubusercontent (sem rebaixar o repo inteiro).

    Subclasses definem: REPO, BRANCH, SOURCE_NAME, _isRelevantPath, _iterFiles,
    _processFile.
    """

    PROJECT_ROOT = Path(__file__).parent.parent.absolute()
    DATA_DIR = PROJECT_ROOT / "data"

    REPO = ""
    BRANCH = "main"
    SOURCE_NAME = ""

    def _isRelevantPath(self, path: str) -> bool:
        raise NotImplementedError

    def _iterFiles(self, root: Path):
        """Itera (rel_path, data_dict) de todos os arquivos relevantes do scan completo."""
        raise NotImplementedError

    def _processFile(self, db: "databaseSQLite", data, rel_path: str) -> int:
        """Processa um arquivo. Retorna quantos CVEs foram enriquecidos."""
        raise NotImplementedError

    def _downloadArchive(self) -> Path:
        url = f"https://codeload.github.com/{self.REPO}/zip/refs/heads/{self.BRANCH}"
        zip_path = self.DATA_DIR / f"{self.SOURCE_NAME}.zip"
        extract_dir = self.DATA_DIR / f"{self.SOURCE_NAME}_extracted"
        print(f"[INFO] Downloading archive {self.REPO}@{self.BRANCH} ...")
        download_to(url, zip_path, headers=_github_api_headers())
        if extract_dir.exists():
            shutil.rmtree(extract_dir)
        with zipfile.ZipFile(zip_path, "r") as zf:
            zf.extractall(extract_dir)
        zip_path.unlink(missing_ok=True)
        roots = [p for p in extract_dir.iterdir() if p.is_dir()]
        return roots[0] if roots else extract_dir

    def _fetchRawFile(self, rel_path: str, sha: str):
        url = f"https://raw.githubusercontent.com/{self.REPO}/{sha}/{rel_path}"
        try:
            resp = http_get(url, headers=_github_api_headers())
            if resp.status_code != 200:
                return None
            return resp.json()
        except (REQUEST_EXCEPTION, ValueError) as e:
            print(f"[WARN] Failed to fetch {rel_path}: {e}")
            return None

    def run(self, db: "databaseSQLite", force_full: bool = False) -> None:
        info = db.getSourceInfo(self.SOURCE_NAME)
        prior_sha = info.get("last_release_file") if info else None
        head_sha = github_branch_head_sha(self.REPO, self.BRANCH)
        if not head_sha:
            print(f"[WARN] {self.SOURCE_NAME}: could not resolve HEAD sha; skipping")
            return
        # force_full (backfill): ignora prior_sha e reprocessa todos os arquivos via
        # scan completo, para aplicar retroativamente lógica nova de _processFile
        # (ex.: criar CVEs ausentes a partir do advisory) ao histórico já varrido.
        if force_full:
            print(f"[INFO] {self.SOURCE_NAME}: forced full re-scan (backfill)")
        if not force_full and prior_sha == head_sha:
            print(f"[INFO] {self.SOURCE_NAME}: already up to date ({head_sha[:8]})")
            return

        started = datetime.now(timezone.utc).isoformat()
        processed = 0

        # Caminho incremental (pulado quando force_full)
        if prior_sha and not force_full:
            changed = github_compare_files(self.REPO, prior_sha, head_sha)
            if changed is not None:
                relevant = [p for p in changed if p and self._isRelevantPath(p)]
                print(
                    f"[INFO] {self.SOURCE_NAME}: incremental — {len(relevant)} relevant changed files"
                )
                for i, rel_path in enumerate(relevant, 1):
                    data = self._fetchRawFile(rel_path, head_sha)
                    if data is None:
                        continue
                    processed += self._processFile(db, data, rel_path)
                    if i % 500 == 0:
                        db.conn.commit()
                db.conn.commit()
                db.updateSource(self.SOURCE_NAME, started, started, head_sha)
                print(
                    f"[INFO] {self.SOURCE_NAME}: enriched {processed} CVEs (incremental)"
                )
                return
            print(
                f"[WARN] {self.SOURCE_NAME}: compare unavailable, falling back to full scan"
            )

        # Scan completo (primeira execução ou fallback)
        root = self._downloadArchive()
        count = 0
        for rel_path, data in self._iterFiles(root):
            processed += self._processFile(db, data, rel_path)
            count += 1
            if count % 2000 == 0:
                db.conn.commit()
                print(
                    f"[INFO] {self.SOURCE_NAME}: scanned {count} files, enriched {processed} CVEs"
                )
        db.conn.commit()
        db.updateSource(
            self.SOURCE_NAME, started, started, head_sha, base_release_file=head_sha
        )
        print(
            f"[INFO] {self.SOURCE_NAME}: enriched {processed} CVEs (full scan of {count} files)"
        )


class WordPressMetadata:
    """
    Enriquece os plugins WordPress (repositories com ecosystem='wordpress') com
    métricas do diretório oficial, vindas de rix4uni/wordpress-plugins.

    Fonte: plugins.json (~35MB, ~60k plugins), um array de objetos com pelo menos
    'slug', 'name', 'active_installs' e 'downloaded'. Apenas os slugs que já existem
    no nosso banco são atualizados; plugins ausentes da fonte ficam com métricas NULL.
    """

    PROJECT_ROOT = Path(__file__).parent.parent.absolute()
    DATA_DIR = PROJECT_ROOT / "data"

    SOURCE_URL = (
        "https://raw.githubusercontent.com/rix4uni/wordpress-plugins/main/plugins.json"
    )

    @staticmethod
    def _parseLastUpdated(raw: object) -> str | None:
        """
        Normaliza o 'last_updated' do diretório WordPress (ex.: "2026-05-15 2:55am GMT")
        para uma data ISO (YYYY-MM-DD), sortável e parseável por new Date() no front.
        Retorna None quando não há data utilizável (mantém o valor existente via COALESCE).
        """
        if not isinstance(raw, str):
            return None
        match = re.match(r"\s*(\d{4}-\d{2}-\d{2})", raw)
        return match.group(1) if match else None

    def run(self, db: "databaseSQLite") -> None:
        # Garante as colunas do ecossistema (bancos restaurados de snapshots antigos).
        db.createTable()

        # Backfill: classifica CVEs já existentes a partir das referências gravadas,
        # cobrindo o backlog que o pipeline incremental (deltas) nunca reprocessaria.
        classified = db.backfillWordpressClassification()
        print(
            f"[INFO] wordpress: {classified} CVEs classified as WordPress (from stored references)"
        )

        # Slugs que precisamos enriquecer (inseridos pelo pipeline de CVEs + backfill acima)
        db.cursor.execute(
            "SELECT fullpath FROM repositories WHERE ecosystem = 'wordpress'"
        )
        prefix = WordPressExtractor.FULLPATH_PREFIX
        wp_fullpaths = [
            row[0]
            for row in db.cursor.fetchall()
            if row[0] and row[0].startswith(prefix)
        ]
        our_slugs = {fp[len(prefix) :] for fp in wp_fullpaths}
        if not our_slugs:
            print(
                "[INFO] wordpress: no WordPress plugins in database; skipping metadata fetch"
            )
            return

        # Plugins WordPress nunca passam pela verificação GraphQL (is_exists=1 na
        # inserção), que é onde commits_fix é recalculado para repos do GitHub. Sem
        # isto, a coluna/cartão "fixes" fica sempre zerada mesmo com changesets de
        # correção classificados pelo backfill acima.
        fixes_updated = 0
        for fullpath in wp_fullpaths:
            db.updateRepositoryCommitsFix(fullpath)
            fixes_updated += 1
            if fixes_updated % 500 == 0:
                db.conn.commit()
        db.conn.commit()
        print(f"[INFO] wordpress: recalculated commits_fix for {fixes_updated} plugins")

        dest = self.DATA_DIR / "wordpress_plugins.json"
        print(
            f"[INFO] wordpress: downloading plugins metadata ({len(our_slugs)} plugins to enrich)..."
        )
        download_to(self.SOURCE_URL, dest)

        with open(dest, "r", encoding="utf-8") as f:
            plugins = json.load(f)

        updated = 0
        for plugin in plugins:
            slug = (plugin.get("slug") or "").strip().lower()
            if not slug or slug not in our_slugs:
                continue
            db.cursor.execute(
                """
            UPDATE repositories SET
                active_installs = ?,
                downloads = ?,
                name = COALESCE(?, name),
                updated_repository = COALESCE(?, updated_repository)
            WHERE fullpath = ?
            """,
                (
                    plugin.get("active_installs"),
                    plugin.get("downloaded"),
                    plugin.get("name"),
                    self._parseLastUpdated(plugin.get("last_updated")),
                    WordPressExtractor.fullpathFromSlug(slug),
                ),
            )
            updated += 1
            if updated % 500 == 0:
                db.conn.commit()

        db.conn.commit()
        dest.unlink(missing_ok=True)
        print(
            f"[INFO] wordpress: enriched {updated}/{len(our_slugs)} plugins with install/download metrics"
        )


class PoCInGitHub(GitHubArchiveSource):
    """
    Fonte PoC-in-GitHub (nomi-sec/PoC-in-GitHub): mapeia CVE -> repositórios com
    PoC. Alimenta apenas os campos de exploit (exists_exploit/list_exploit) com os
    links das PoCs; metadados de cada repo (estrelas etc.) são ignorados.

    Layout: YEAR/CVE-XXXX-YYYY.json, cada arquivo é um array de objetos com html_url.
    """

    REPO = "nomi-sec/PoC-in-GitHub"
    BRANCH = "master"
    SOURCE_NAME = "poc-in-github"

    _PATH_RE = re.compile(r"^\d{4}/CVE-[^/]+\.json$", re.IGNORECASE)

    def _isRelevantPath(self, path: str) -> bool:
        return bool(self._PATH_RE.match(path))

    def _iterFiles(self, root: Path):
        for json_path in root.glob("[0-9][0-9][0-9][0-9]/CVE-*.json"):
            try:
                data = json.loads(json_path.read_text(encoding="utf-8"))
            except (json.JSONDecodeError, OSError):
                continue
            yield str(json_path.relative_to(root)), data

    def _processFile(self, db, data, rel_path) -> int:
        cve_id = Path(rel_path).stem.upper()
        if not cve_id.startswith("CVE-"):
            return 0
        if not db.cveExists(cve_id):
            return 0
        urls = []
        if isinstance(data, list):
            for item in data:
                if isinstance(item, dict) and item.get("html_url"):
                    urls.append(item["html_url"])
        if not urls:
            return 0
        db.enrichExploitUrls(cve_id, urls, relation_type="poc")
        return 1


class NucleiTemplates(GitHubArchiveSource):
    """
    Fonte Nuclei Templates (projectdiscovery/nuclei-templates): mapeia cada CVE
    para o(s) template(s) do Nuclei que a detectam, guardando apenas o LINK do
    template. Enriquece o par exists_nuclei/list_nuclei de CVEs já existentes
    (não cria CVEs).

    Descoberta por UMA chamada à Git Trees API (`?recursive=1`), que devolve todos
    os paths do repo sem baixar conteúdo. Filtramos os arquivos `CVE-XXXX-YYYY.yaml`
    (em http/network/javascript/code/dast/headless) e montamos a URL raw — nada de
    clonar o repo, baixar templates ou parsear YAML.

    Roda SEMPRE em full: como o custo é só 2 chamadas de API + match no SQLite
    (~2s, nenhum template baixado), não vale um skip por SHA — e o full garante que
    CVEs recém-adicionadas ao NOSSO banco também sejam ligadas a templates que já
    existiam antes delas (o cvelistV5 costuma entrar depois do template). O SHA do
    HEAD é gravado em `sources` só para registro. Fallback para o zip só se a Trees
    API vier `truncated` (limite da API; não ocorre nesse repo).
    """

    REPO = "projectdiscovery/nuclei-templates"
    BRANCH = "main"
    SOURCE_NAME = "nuclei-templates"

    # Nome de arquivo de template de CVE: captura o CVE id (ex.: CVE-2021-44228.yaml).
    _CVE_FILE_RE = re.compile(r"(CVE-\d{4}-\d{4,})\.ya?ml$", re.IGNORECASE)

    def _isRelevantPath(self, path: str) -> bool:
        return self._CVE_FILE_RE.search(path) is not None

    def _linkForPath(self, rel_path: str):
        """Retorna (cve_id, template_dict) para um path de template, ou None."""
        match = self._CVE_FILE_RE.search(rel_path)
        if not match:
            return None
        return match.group(1).upper(), {
            "template_id": Path(rel_path).stem,
            "path": rel_path,
            "url": f"https://raw.githubusercontent.com/{self.REPO}/{self.BRANCH}/{rel_path}",
        }

    def _fetchTreePaths(self, sha: str):
        """
        Git Trees API (recursiva): retorna (paths_relevantes, truncated).
        paths=None em caso de erro de rede/HTTP.
        """
        url = f"https://api.github.com/repos/{self.REPO}/git/trees/{sha}?recursive=1"
        try:
            resp = http_get(url, headers=_github_api_headers())
            if resp.status_code != 200:
                print(f"[WARN] {self.SOURCE_NAME}: trees API HTTP {resp.status_code}")
                return None, False
            data = resp.json()
        except (REQUEST_EXCEPTION, ValueError) as e:
            print(f"[WARN] {self.SOURCE_NAME}: trees API failed: {e}")
            return None, False
        paths = [
            node["path"]
            for node in data.get("tree", [])
            if node.get("type") == "blob" and self._isRelevantPath(node.get("path", ""))
        ]
        return paths, bool(data.get("truncated"))

    def _iterZipPaths(self, root: Path):
        """Fallback: caminhos relevantes do zip extraído (só nomes, sem ler conteúdo)."""
        for pattern in ("*.yaml", "*.yml"):
            for p in root.rglob(pattern):
                rel = str(p.relative_to(root))
                if self._isRelevantPath(rel):
                    yield rel

    def _enrich(self, db: "databaseSQLite", paths) -> int:
        enriched = 0
        for i, rel_path in enumerate(paths, 1):
            res = self._linkForPath(rel_path)
            if not res:
                continue
            cve_id, template = res
            if db.cveExists(cve_id) and db.addNucleiTemplates(cve_id, [template]):
                enriched += 1
            if i % 1000 == 0:
                db.conn.commit()
        db.conn.commit()
        return enriched

    def run(self, db: "databaseSQLite", force_full: bool = False) -> None:
        # force_full é aceito por compatibilidade com o dispatch, mas esta fonte
        # roda sempre em full (barato) — não há caminho incremental.
        db.createTable()  # garante exists_nuclei/list_nuclei em snapshots antigos
        head_sha = github_branch_head_sha(self.REPO, self.BRANCH)
        if not head_sha:
            print(f"[WARN] {self.SOURCE_NAME}: could not resolve HEAD sha; skipping")
            return

        started = datetime.now(timezone.utc).isoformat()
        paths, truncated = self._fetchTreePaths(head_sha)
        if paths is not None and not truncated:
            processed = self._enrich(db, paths)
            print(
                f"[INFO] {self.SOURCE_NAME}: enriched {processed} CVEs from {len(paths)} templates (trees API)"
            )
        else:
            reason = "trees API truncated" if truncated else "trees API unavailable"
            print(f"[WARN] {self.SOURCE_NAME}: {reason}; falling back to zip scan")
            root = self._downloadArchive()
            processed = self._enrich(db, list(self._iterZipPaths(root)))
            print(
                f"[INFO] {self.SOURCE_NAME}: enriched {processed} CVEs (zip fallback)"
            )
        # Normaliza o flag: CVEs sem template ficam explicitamente 0. A coluna nao
        # tem valor gravado no insert, entao CVEs nunca enriquecidas ficam com NULL.
        # Como em SQL 'NULL = 0' e falso, sem isso o filtro "sem Nuclei"
        # (exists_nuclei = 0) nao retornaria essas CVEs. Roda apos o enriquecimento,
        # que ja marcou 1 quem tem template.
        normalized = db.cursor.execute(
            "UPDATE cves SET exists_nuclei = 0 WHERE exists_nuclei IS NULL"
        ).rowcount
        db.conn.commit()
        print(
            f"[INFO] {self.SOURCE_NAME}: normalized {normalized} NULL exists_nuclei -> 0"
        )
        db.updateSource(
            self.SOURCE_NAME, started, started, head_sha, base_release_file=head_sha
        )


class GitHubAdvisory(GitHubArchiveSource):
    """
    Fonte GitHub Advisory Database (github/advisory-database, formato OSV).

    Casa advisories a CVEs via `aliases`. Para CVEs que JÁ existem, enriquece com
    referências, scores CVSS, CWEs e pacotes afetados. Para CVEs que AINDA NÃO
    existem no banco (publicadas no GitHub Advisory antes do cvelist/NVD), CRIA a
    CVE via insertCVE — o GitHub Advisory passa a ser fonte de CVEs novas. Quando
    o cvelist publicar a mesma CVE depois, o INSERT OR REPLACE de insertCVE
    sobrescreve com os dados autoritativos. Advisories sem CVE são ignorados;
    advisories `withdrawn` não semeiam CVE nova (mas enriquecem se já existir).

    Layout: advisories/github-reviewed/YEAR/MONTH/GHSA-xxxx/GHSA-xxxx.json
    """

    REPO = "github/advisory-database"
    BRANCH = "main"
    SOURCE_NAME = "github-advisory"

    def _isRelevantPath(self, path: str) -> bool:
        return path.startswith("advisories/github-reviewed/") and path.endswith(".json")

    def _iterFiles(self, root: Path):
        for json_path in root.glob("advisories/github-reviewed/**/GHSA-*.json"):
            try:
                data = json.loads(json_path.read_text(encoding="utf-8"))
            except (json.JSONDecodeError, OSError):
                continue
            yield str(json_path.relative_to(root)), data

    @staticmethod
    def _refTags(ref: dict) -> list[str]:
        # Mesmo padrão do CVElist: a tag "exploit" sinaliza exploit explícito;
        # as demais referências seguem SEM tag para que complementCVE faça a
        # detecção centralizada (commit do GitHub / verificação ao vivo de PoC),
        # respeitando a denylist já existente em findExploits.
        if (ref.get("type") or "").upper() == "EXPLOIT":
            return ["exploit"]
        return []

    @staticmethod
    def _cvssVersion(vector: str) -> str:
        if vector.startswith("CVSS:4"):
            return "4.0"
        if vector.startswith("CVSS:3"):
            return "3.1"
        return "2.0"

    @staticmethod
    def _buildCveData(cve_id, data, refs, cvss_list, affected, cwe_ids) -> dict:
        """
        Monta o dict no mesmo formato de formatDataVersion5_2 (consumido por
        insertCVE) a partir do advisory OSV, reaproveitando os campos que
        _processFile já extraiu. Usado para CRIAR uma CVE ausente a partir do GHSA.
        """
        return {
            "cve_id": cve_id,
            "state": "PUBLISHED",
            "reserved": None,
            "published": data.get("published"),
            "updated": data.get("modified"),
            "title": derive_cve_title(data.get("summary"), data.get("details")),
            "description": data.get("details"),
            "affected": affected,
            "cwe_ids": cwe_ids,
            "references": refs,
            "cvss": cvss_list,
        }

    def _processFile(self, db, data, rel_path) -> int:
        if not isinstance(data, dict):
            return 0
        aliases = data.get("aliases") or []
        cve_ids = [
            a for a in aliases if isinstance(a, str) and a.upper().startswith("CVE-")
        ]
        if not cve_ids:
            return 0

        refs = [
            {"url": r.get("url"), "tags": self._refTags(r)}
            for r in data.get("references", [])
            if isinstance(r, dict) and r.get("url")
        ]

        # Refs do tipo PACKAGE apontam para o repositório (URL raiz, que o
        # GitHubExtractor ignora); capturamos via _fullpathFromUrl.
        package_repos = [
            db._fullpathFromUrl(r.get("url"))
            for r in data.get("references", [])
            if isinstance(r, dict) and (r.get("type") or "").upper() == "PACKAGE"
        ]
        package_repos = [fp for fp in package_repos if fp]

        cvss_list = []
        for sev in data.get("severity", []):
            vector = sev.get("score") if isinstance(sev, dict) else None
            if isinstance(vector, str) and vector.startswith("CVSS"):
                version = self._cvssVersion(vector)
                cvss_list.append(
                    {"version": version, "score": calculateScoreCVSS(vector, version)}
                )

        affected = []
        for aff in data.get("affected", []):
            pkg = aff.get("package", {}) if isinstance(aff, dict) else {}
            name = pkg.get("name")
            if name:
                affected.append({"vendor": pkg.get("ecosystem"), "product": name})

        db_specific = data.get("database_specific") or {}
        cwe_ids = [c for c in (db_specific.get("cwe_ids") or []) if isinstance(c, str)]

        # O texto do advisory (details) às vezes descreve um PoC. Reusa o mesmo
        # detector de keywords do findExploits; se casar, o próprio link do
        # advisory do GitHub vira o link de PoC.
        details = data.get("details") or ""
        ghsa_id = data.get("id") or ""
        advisory_poc_url = None
        if details and isinstance(ghsa_id, str) and ghsa_id.upper().startswith("GHSA-"):
            if findExploits()._containsExploitKeywords(details):
                advisory_poc_url = f"https://github.com/advisories/{ghsa_id}"

        count = 0
        for cve_id in cve_ids:
            cve_id = cve_id.upper()
            if not db.cveExists(cve_id):
                # Advisory retirado não semeia CVE nova (só enriquece se já existir).
                if data.get("withdrawn"):
                    continue
                # GHSA como fonte de CVEs: cria a CVE ausente. O bloco de
                # enriquecimento abaixo roda em seguida e é idempotente (dedup),
                # virando no-op para os dados que insertCVE já gravou e mantendo
                # apenas os extras do GHSA (repos 'package' e PoC do advisory).
                db.insertCVE(
                    self._buildCveData(cve_id, data, refs, cvss_list, affected, cwe_ids)
                )
            # mergeReferences primeiro: vincula repos de commit como fix_commit,
            # prevalecendo sobre o link "package" (INSERT OR IGNORE na PK).
            if refs:
                db.mergeReferences(cve_id, refs)
            for fullpath in package_repos:
                db.linkRepository(cve_id, fullpath, "package")
            if advisory_poc_url:
                db.enrichExploitUrls(cve_id, [advisory_poc_url], relation_type="poc")
            if cwe_ids:
                db.addCwes(cve_id, cwe_ids)
            if cvss_list:
                db.addScores(cve_id, cvss_list)
            if affected:
                db.addAffected(cve_id, affected)
            count += 1
        return count


class KevEnrichment:
    """
    Enriquece CVEs com dados do CISA Known Exploited Vulnerabilities (KEV) Catalog.

    Baixa o JSON oficial do CISA KEV e atualiza as colunas:
    - in_kev: 1 se a CVE está no catálogo
    - kev_date_added: data em que a CVE foi adicionada ao KEV
    - kev_due_date: prazo de remediação (BOD 26-04)
    - kev_ransomware: 1 se a CVE é conhecida por uso em campanhas de ransomware
    """

    PROJECT_ROOT = Path(__file__).parent.parent.absolute()
    DATA_DIR = PROJECT_ROOT / "data"

    KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"

    def run(self, db: "databaseSQLite") -> None:
        db.createTable()

        print(f"[INFO] kev: downloading CISA KEV catalog from {self.KEV_URL} ...")
        try:
            resp = http_get(
                self.KEV_URL, headers={"User-Agent": "SunCVE/1.0"}, timeout=60
            )
            resp.raise_for_status()
            data = resp.json()
        except Exception as e:
            print(f"[WARN] kev: failed to download KEV JSON: {e}")
            return

        vulnerabilities = data.get(
            "vulnerabilities", data if isinstance(data, list) else []
        )
        title = data.get("title", "") if isinstance(data, dict) else ""
        catalog_version = (
            data.get("catalogVersion", "") if isinstance(data, dict) else ""
        )

        print(
            f'[INFO] kev: catalog "{title}" version {catalog_version} '
            f"with {len(vulnerabilities)} entries"
        )

        updated = 0
        skipped = 0

        for entry in vulnerabilities:
            if not isinstance(entry, dict):
                continue
            cve_id = entry.get("cveID", "").strip().upper()
            if not cve_id or not cve_id.startswith("CVE-"):
                continue

            if not db.cveExists(cve_id):
                skipped += 1
                continue

            date_added = entry.get("dateAdded", "")
            due_date = entry.get("dueDate", "")
            known_ransomware = entry.get("knownRansomwareCampaignUse", "Unknown")
            ransomware_val = 1 if known_ransomware == "Known" else 0

            db.cursor.execute(
                """
                UPDATE cves SET
                  in_kev = 1,
                  kev_date_added = ?,
                  kev_due_date = ?,
                  kev_ransomware = ?
                WHERE cve_id = ?
                """,
                (date_added, due_date, ransomware_val, cve_id),
            )
            updated += 1

        db.conn.commit()
        print(
            f"[INFO] kev: enriched {updated} CVEs, {skipped} KEV entries not in database"
        )


class WordfenceNucleiTemplates:
    """
    Enriquece CVEs com templates Nuclei do repositório topscoder/nuclei-wordfence-cve.

    Contém 77k+ templates WordPress gerados a partir do feed de inteligência do
    Wordfence, organizados por ano em nuclei-templates/YYYY/CVE-YYYY-NNNNN-*.yaml.
    Usa Git Trees API (não-recursiva) iterando por diretório de ano para evitar
    o limite de 5MB da API recursiva (o repo tem 77k arquivos).

    Cada template é adicionado ao list_nuclei da CVE com source='wordfence'.
    """

    REPO = "topscoder/nuclei-wordfence-cve"
    BRANCH = "main"
    SOURCE_NAME = "wordfence-nuclei"

    _CVE_FILE_RE = re.compile(r"^(CVE-\d{4}-\d{4,})", re.IGNORECASE)

    @staticmethod
    def _getTree(repo: str, sha: str) -> dict | None:
        url = f"https://api.github.com/repos/{repo}/git/trees/{sha}"
        try:
            resp = http_get(url, headers=_github_api_headers())
            if resp.status_code != 200:
                print(f"  [WARN] wordfence-nuclei: trees API HTTP {resp.status_code}")
                return None
            return resp.json()
        except (REQUEST_EXCEPTION, ValueError) as e:
            print(f"  [WARN] wordfence-nuclei: trees API failed: {e}")
            return None

    def run(self, db: "databaseSQLite") -> None:
        db.createTable()

        head_sha = github_branch_head_sha(self.REPO, self.BRANCH)
        if not head_sha:
            print(f"[WARN] wordfence-nuclei: could not resolve HEAD sha; skipping")
            return

        started = datetime.now(timezone.utc).isoformat()

        root_tree = self._getTree(self.REPO, head_sha)
        if not root_tree:
            return

        templates_sha = None
        for node in root_tree.get("tree", []):
            if node.get("path") == "nuclei-templates" and node.get("type") == "tree":
                templates_sha = node["sha"]
                break

        if not templates_sha:
            print("[WARN] wordfence-nuclei: nuclei-templates dir not found")
            return

        templates_tree = self._getTree(self.REPO, templates_sha)
        if not templates_tree:
            return

        enriched = 0
        total_templates = 0

        for node in templates_tree.get("tree", []):
            if node.get("type") != "tree":
                continue

            year_dir = node["path"]
            year_sha = node["sha"]

            year_tree = self._getTree(self.REPO, year_sha)
            if not year_tree:
                continue

            cve_map: dict[str, list[dict]] = {}

            for file_node in year_tree.get("tree", []):
                if file_node.get("type") != "blob":
                    continue

                name = file_node["path"]
                match = self._CVE_FILE_RE.match(name)
                if not match:
                    continue

                cve_id = match.group(1).upper()
                if not cve_id.startswith("CVE-"):
                    continue

                template_url = (
                    f"https://raw.githubusercontent.com/{self.REPO}/{self.BRANCH}"
                    f"/nuclei-templates/{year_dir}/{name}"
                )

                if cve_id not in cve_map:
                    cve_map[cve_id] = []

                cve_map[cve_id].append(
                    {
                        "template_id": Path(name).stem,
                        "path": f"nuclei-templates/{year_dir}/{name}",
                        "url": template_url,
                        "source": "wordfence",
                    }
                )

            year_enriched = 0
            for cve_id, templates in cve_map.items():
                if db.cveExists(cve_id) and db.addNucleiTemplates(cve_id, templates):
                    year_enriched += 1

            total_templates += sum(len(v) for v in cve_map.values())
            enriched += year_enriched
            db.conn.commit()
            print(
                f"  [INFO] wordfence-nuclei: year {year_dir} — "
                f"{len(cve_map)} CVEs, {year_enriched} enriched"
            )

        print(
            f"[INFO] wordfence-nuclei: {total_templates} templates, "
            f"{enriched} CVEs enriched total"
        )
        db.updateSource(
            self.SOURCE_NAME, started, started, head_sha, base_release_file=head_sha
        )


class MissingNucleiTemplates:
    """
    Enriquece CVEs com indicador de "template ausente" baseado na lista semanal do
    repositorio edoardottt/missing-cve-nuclei-templates.

    Contem 65k+ CVEs que NAO possuem template no repositorio oficial do Nuclei,
    organizadas por ano em data/year/YYYY.txt.
    Formato: [ CVE-YYYY-NNNNN ] [ vuln_type ] URL
    """

    BASE_URL = (
        "https://raw.githubusercontent.com/edoardottt/"
        "missing-cve-nuclei-templates/main/data/year"
    )
    SOURCE_NAME = "missing-nuclei-templates"

    _CVE_LINE_RE = re.compile(r"\[ (CVE-\d{4}-\d{4,}) \]")

    @staticmethod
    def _parseCveIds(text: str) -> list[str]:
        return [
            m.group(1).upper()
            for m in MissingNucleiTemplates._CVE_LINE_RE.finditer(text)
        ]

    def run(self, db: "databaseSQLite") -> None:
        db.createTable()

        started = datetime.now(timezone.utc).isoformat()
        total_cves = 0
        enriched = 0

        for year in range(1999, datetime.now().year + 1):
            url = f"{self.BASE_URL}/{year}.txt"
            try:
                resp = http_get(url, headers={"User-Agent": "SunCVE/1.0"}, timeout=30)
                if resp.status_code == 404:
                    continue
                resp.raise_for_status()
                text = resp.text
            except Exception as e:
                print(f"  [WARN] missing-templates: year {year} download failed: {e}")
                continue

            cve_ids = set(self._parseCveIds(text))
            year_enriched = 0

            for cve_id in cve_ids:
                if db.cveExists(cve_id):
                    db.cursor.execute(
                        "UPDATE cves SET missing_nuclei_template = 1 WHERE cve_id = ?",
                        (cve_id,),
                    )
                    year_enriched += 1

            total_cves += len(cve_ids)
            enriched += year_enriched
            db.conn.commit()
            print(
                f"  [INFO] missing-templates: year {year} — "
                f"{len(cve_ids)} CVEs listed, {year_enriched} in database"
            )

        print(
            f"[INFO] missing-templates: {total_cves} CVEs missing template, "
            f"{enriched} enriched in database"
        )
        db.updateSource(
            self.SOURCE_NAME,
            started,
            started,
            datetime.now(timezone.utc).isoformat(),
        )


class TitleBackfill:
    """
    Backfill retroativo de títulos.

    Re-deriva o título de CVEs já existentes que continuam com 'No Title Found'
    (ou título vazio/nulo) a partir da própria description.

    Necessário porque a ingestão de CVEs (cvelistV5) é incremental — só reprocessa
    os deltas —, então as CVEs armazenadas antes do fix de derivação de título nunca
    são reparseadas e mantêm o placeholder. Reutiliza exatamente derive_cve_title,
    é idempotente e não faz chamadas de rede: após a 1ª passagem só sobram CVEs sem
    description (não deriváveis), que o WHERE já exclui.
    """

    SOURCE_NAME = "title-backfill"

    def run(self, db: "databaseSQLite", batch_size: int = 5000) -> None:
        db.createTable()

        started = datetime.now(timezone.utc).isoformat()

        rows = db.cursor.execute(
            """
            SELECT cve_id, description
            FROM cves
            WHERE (title IS NULL OR title = '' OR title = 'No Title Found')
              AND description IS NOT NULL
              AND TRIM(description) <> ''
            """
        ).fetchall()

        total = len(rows)
        updated = 0
        print(f"[INFO] title-backfill: {total} CVEs candidatas a re-derivação de título")

        for cve_id, description in rows:
            new_title = derive_cve_title(None, description)
            if new_title == "No Title Found":
                continue
            db.cursor.execute(
                "UPDATE cves SET title = ? WHERE cve_id = ?",
                (new_title, cve_id),
            )
            updated += 1
            if updated % batch_size == 0:
                db.conn.commit()
                print(f"  [INFO] title-backfill: {updated}/{total} títulos atualizados")

        db.conn.commit()
        print(f"[INFO] title-backfill: {updated} títulos derivados da description")
        db.updateSource(
            self.SOURCE_NAME,
            started,
            started,
            datetime.now(timezone.utc).isoformat(),
        )


class RepoManifestScanner:
    """
    Descobre o NOME canônico do pacote de cada repositório lendo o manifesto raiz
    na branch default: package.json -> name (npm), composer.json -> name (Packagist).

    Por que existir: o nome do pacote não pode ser inferido de "quem aponta para o
    repo" (qualquer pacote pode declarar `repository` de um repo que não é o dele,
    ex.: sub-pacotes de monorepo com `repository.directory`). A única fonte de
    verdade é o próprio repositório. O resultado é gravado em repo_manifests, que
    funciona como cache idempotente: cada repo é varrido UMA vez; repos novos
    (futuros) entram em runs seguintes; falhas transitórias (rate limit/rede) não
    são cacheadas e portanto re-tentadas depois.

    Estratégia de busca:
    - Primário (com token): GraphQL em lote (aliases r0..rN), uma expressão `HEAD:`
      por arquivo resolve a branch default em uma só chamada.
    - Fallback (sem token, ou repository=null por rename/privado): raw.githubusercontent
      em main/master (o raw segue redirect de rename).
    """

    SOURCE_NAME = "repo-manifests"
    GRAPHQL_URL = "https://api.github.com/graphql"
    RAW_URL = "https://raw.githubusercontent.com/{fullpath}/{branch}/{file}"

    # Lote do GraphQL: 30 repos x 2 blobs pequenos cabe bem no limite de nós/custo.
    GRAPHQL_BATCH_SIZE = 30
    RATE_LIMIT_MAX_RETRIES = 3
    RATE_LIMIT_DEFAULT_DELAY = 60
    RAW_BRANCHES = ("main", "master")

    def __init__(self, token: str | None = None):
        self.token = token or os.environ.get("GITHUB_TOKEN")

    @staticmethod
    def _parseManifestName(blob_text: str | None) -> str | None:
        """Extrai um 'name' string e não-vazio de um package.json/composer.json."""
        if not blob_text:
            return None
        try:
            data = json.loads(blob_text)
        except (json.JSONDecodeError, ValueError):
            return None
        if isinstance(data, dict):
            name = data.get("name")
            if isinstance(name, str) and name.strip():
                return name.strip()
        return None

    def _buildQuery(self, batch: list[str]) -> str:
        """Monta um GraphQL com um alias rN por repo, lendo os dois manifestos."""
        parts = []
        for i, fullpath in enumerate(batch):
            owner, name = fullpath.split("/", 1)
            parts.append(
                f"r{i}: repository(owner: {json.dumps(owner)}, name: {json.dumps(name)}) {{\n"
                f"  defaultBranchRef {{ name }}\n"
                f'  pkg: object(expression: "HEAD:package.json") {{ ... on Blob {{ text }} }}\n'
                f'  cmp: object(expression: "HEAD:composer.json") {{ ... on Blob {{ text }} }}\n'
                f"}}"
            )
        return "query {\n" + "\n".join(parts) + "\n}"

    def _fetchRaw(
        self, fullpath: str
    ) -> tuple[str | None, str | None, str | None, bool]:
        """
        Fallback via raw.githubusercontent. Retorna
        (npm_name, composer_name, branch, reachable). reachable=True quando o
        servidor respondeu (200 ou 404) ao menos uma vez — base para gravar
        resultado definitivo "sem manifesto"; False = só erros transitórios.
        """
        reachable = False
        for branch in self.RAW_BRANCHES:
            npm_name = composer_name = None
            got_200 = False
            for file, setter in (
                ("package.json", "npm"),
                ("composer.json", "composer"),
            ):
                url = self.RAW_URL.format(fullpath=fullpath, branch=branch, file=file)
                try:
                    resp = http_get(url, timeout=20)
                except REQUEST_EXCEPTION:
                    continue  # transitório: não marca reachable
                if resp.status_code == 200:
                    reachable = True
                    got_200 = True
                    name = self._parseManifestName(resp.text)
                    if setter == "npm":
                        npm_name = name
                    else:
                        composer_name = name
                elif resp.status_code == 404:
                    reachable = (
                        True  # servidor respondeu; arquivo só não existe nessa branch
                    )
            if got_200:
                return npm_name, composer_name, branch, True
        return None, None, None, reachable

    def _fetchBatchGraphQL(self, batch: list[str]):
        """
        Busca um lote via GraphQL. Retorna (results, fallback, rate_limited):
        - results: {fullpath: (npm_name, composer_name, branch)} definitivos
        - fallback: [fullpath] cujo nó veio null (rename/privado) -> tentar raw
        - rate_limited: True se esgotou retries de rate limit (parar o run)
        """
        headers = _github_api_headers(self.token)
        headers["Content-Type"] = "application/json"
        payload = {"query": self._buildQuery(batch)}

        for attempt in range(self.RATE_LIMIT_MAX_RETRIES + 1):
            try:
                resp = http_post(
                    self.GRAPHQL_URL, headers=headers, json=payload, timeout=60
                )
            except REQUEST_EXCEPTION as e:
                print(f"[WARN] scan-manifests: GraphQL request failed: {e}")
                return {}, list(batch), False  # transitório: cai no raw

            if resp.status_code == 429:
                if attempt < self.RATE_LIMIT_MAX_RETRIES:
                    delay = int(
                        resp.headers.get("Retry-After", self.RATE_LIMIT_DEFAULT_DELAY)
                    )
                    print(
                        f"[WARN] scan-manifests: rate limited (429), waiting {delay}s..."
                    )
                    time.sleep(delay)
                    continue
                return {}, [], True

            try:
                data = resp.json()
            except ValueError:
                return {}, list(batch), False

            errors = data.get("errors") or []
            if errors:
                msg = errors[0].get("message", "")
                if "rate limit" in msg.lower() or "secondarily" in msg.lower():
                    if attempt < self.RATE_LIMIT_MAX_RETRIES:
                        print(
                            f"[WARN] scan-manifests: GraphQL rate limit, waiting "
                            f"{self.RATE_LIMIT_DEFAULT_DELAY}s..."
                        )
                        time.sleep(self.RATE_LIMIT_DEFAULT_DELAY)
                        continue
                    return {}, [], True
                # Erros não-fatais (ex.: nó específico) seguem com data parcial abaixo.

            payload_data = data.get("data") or {}
            results: dict[str, tuple] = {}
            fallback: list[str] = []
            for i, fullpath in enumerate(batch):
                node = payload_data.get(f"r{i}")
                if not node:
                    fallback.append(fullpath)  # null: rename/privado/deletado -> raw
                    continue
                branch_ref = node.get("defaultBranchRef") or {}
                branch = branch_ref.get("name")
                npm_name = self._parseManifestName((node.get("pkg") or {}).get("text"))
                composer_name = self._parseManifestName(
                    (node.get("cmp") or {}).get("text")
                )
                results[fullpath] = (npm_name, composer_name, branch)
            return results, fallback, False

        return {}, [], True

    def run(self, db: "databaseSQLite") -> None:
        db.createTable()

        # Carrega a lista de pendentes UMA vez e itera em um único passe: garante
        # terminação (repos com falha transitória não são re-selecionados no mesmo
        # run; voltam só no próximo, pois continuam fora do cache).
        pending = db.getReposNeedingManifestScan(limit=10_000_000)
        if not pending:
            print(
                "[INFO] scan-manifests: no repositories pending a manifest scan; skipping"
            )
            return
        print(
            f"[INFO] scan-manifests: {len(pending)} repositories to scan "
            f"({'GraphQL+raw' if self.token else 'raw-only (no token)'})"
        )

        scanned = found_npm = found_composer = 0
        rate_limited = False

        for start in range(0, len(pending), self.GRAPHQL_BATCH_SIZE):
            batch = [
                fp
                for fp in pending[start : start + self.GRAPHQL_BATCH_SIZE]
                if fp.count("/") == 1
            ]

            if self.token:
                results, fallback, rl = self._fetchBatchGraphQL(batch)
                if rl:
                    rate_limited = True
                    break
            else:
                results, fallback = {}, list(batch)

            # Raw para os que vieram null no GraphQL (ou todos, sem token).
            for fullpath in fallback:
                npm_name, composer_name, branch, reachable = self._fetchRaw(fullpath)
                if npm_name or composer_name or reachable:
                    results[fullpath] = (npm_name, composer_name, branch)
                # !reachable => só erros transitórios: não grava, re-tenta no próximo run.

            for fullpath, (npm_name, composer_name, branch) in results.items():
                db.saveRepoManifest(fullpath, npm_name, composer_name, branch)
                scanned += 1
                found_npm += bool(npm_name)
                found_composer += bool(composer_name)

            if scanned and scanned % 300 == 0:
                db.conn.commit()
                print(
                    f"[INFO] scan-manifests: {scanned} scanned "
                    f"({found_npm} npm, {found_composer} composer)"
                )

        db.conn.commit()
        started = datetime.now(timezone.utc).isoformat()
        db.updateSource(self.SOURCE_NAME, started, started, str(scanned))

        if rate_limited:
            print(
                f"[WARN] scan-manifests: stopped on rate limit after {scanned} repos. "
                f"Run again later to continue."
            )
        print(
            f"[INFO] scan-manifests: scanned {scanned} repositories "
            f"({found_npm} with package.json name, {found_composer} with composer.json name)"
        )


class NpmPackages:
    """
    Enriquece repositórios com o pacote npm correspondente usando como NOME a
    fonte de verdade descoberta por RepoManifestScanner (repo_manifests.npm_name,
    lido do package.json raiz na branch default).

    Existência/contagens: download-counts. O nome é um pacote npm publicado sse
    estiver no mapa nome -> downloads, que também fornece o número de downloads. O
    NOME em si vem sempre do manifesto (repo_manifests.npm_name); o download-counts
    só responde "esse nome existe no npm?" e "quantos downloads?". Grava
    ecosystem='npm', package_url (npmjs/<npm_name>) e downloads.
    """

    PROJECT_ROOT = Path(__file__).parent.parent.absolute()
    DATA_DIR = PROJECT_ROOT / "data"
    SOURCE_NAME = "npm-packages"

    DOWNLOAD_COUNTS_GIT = "https://github.com/nice-registry/download-counts.git"

    # Registro do npm: fonte autoritativa do repositório de cada pacote (campo
    # .repository). Usado só para VALIDAR (rejeitar) atribuições nome->repo erradas,
    # nunca para escolher o nome. Consulta pequena por pacote, com retry e cache
    # persistente (npm_repo_cache) — sem download massivo que possa falhar e desligar
    # o guard em silêncio.
    REGISTRY_URL = "https://registry.npmjs.org/{name}/latest"

    @staticmethod
    def _pkgNameFromUrl(package_url: str | None) -> str | None:
        """Extrai o slug npm de um package_url (preserva escopo @org/pkg)."""
        if not package_url or "/package/" not in package_url:
            return None
        name = package_url.rsplit("/package/", 1)[-1].strip()
        return name or None

    def _resolvePackageRepo(self, db: "databaseSQLite", name: str) -> str | None:
        """
        Repositório GitHub canônico do pacote `name`, com cache persistente.

        Consulta registry.npmjs.org/<nome>/latest e lê .repository. 404 => grava NULL
        (publicado-não, sem repo) no cache. Erro transitório (rede/5xx) => devolve
        None SEM cachear (não rejeita; re-tenta no próximo run). Sucesso => grava o
        fullpath resolvido (ou NULL) no cache.
        """
        cached, fullpath = db.getNpmRepoFromCache(name)
        if cached:
            return fullpath

        url = self.REGISTRY_URL.format(name=name.replace("/", "%2F"))
        try:
            resp = http_get(url, timeout=20)
        except REQUEST_EXCEPTION:
            return None  # transitório: não cacheia, não rejeita
        if resp.status_code == 404:
            db.setNpmRepoCache(name, None)
            return None
        if resp.status_code != 200:
            return None  # transitório (5xx/429)
        try:
            repository = resp.json().get("repository")
        except ValueError:
            return None
        repo_url = None
        if isinstance(repository, dict):
            repo_url = repository.get("url")
        elif isinstance(repository, str):
            repo_url = repository
        fullpath = db._fullpathFromUrl(repo_url) if repo_url else None
        db.setNpmRepoCache(name, fullpath)
        return fullpath

    def _buildKnownRepoMap(self, db: "databaseSQLite", names: set[str]) -> dict:
        """Resolve cada nome distinto uma vez -> {name: fullpath|None} (com cache)."""
        known_repo: dict[str, str | None] = {}
        resolved = 0
        for name in names:
            if not name:
                continue
            known_repo[name] = self._resolvePackageRepo(db, name)
            resolved += 1
            if resolved % 200 == 0:
                db.conn.commit()  # preserva o cache mesmo se o run for interrompido
                print(f"[INFO] npm: resolved {resolved}/{len(names)} package repos")
            time.sleep(0.02)  # educado com o registry público
        db.conn.commit()
        return known_repo

    def _resolveLatestBuildBranch(self) -> str | None:
        """Última branch 'build-*' via git ls-remote (uma chamada, sem clonar tudo)."""
        import subprocess

        try:
            out = subprocess.run(
                ["git", "ls-remote", "--heads", self.DOWNLOAD_COUNTS_GIT, "build-*"],
                capture_output=True,
                text=True,
                timeout=120,
                check=True,
            ).stdout
        except (subprocess.SubprocessError, OSError, FileNotFoundError) as e:
            print(f"[WARN] npm: could not list download-counts branches: {e}")
            return None
        branches = [
            line.split("refs/heads/", 1)[1].strip()
            for line in out.splitlines()
            if "refs/heads/build-" in line
        ]
        # Nomes 'build-2.YYYYMMDD.N' ordenam lexicograficamente == cronologicamente.
        return max(branches) if branches else None

    @staticmethod
    def _loadDownloadCounts(clone_dir: Path) -> dict:
        """
        Lê o mapa nome -> downloads do branch clonado. O download-counts FRAGMENTA os
        dados em vários shards (counts0.json, counts1.json, ...; ~3,6M pacotes no
        total) mais um state.json de metadados — então o mapa só fica completo quando
        TODOS os counts*.json são mesclados (ler um único shard, como antes, perdia a
        imensa maioria dos pacotes, p.ex. 'openclaw').
        """
        merged: dict = {}
        shards = sorted(clone_dir.glob("counts*.json"))
        if not shards:
            # Fallback defensivo (se o esquema de nomes mudar): qualquer .json de
            # contagens, menos o metadado conhecido.
            shards = [p for p in clone_dir.glob("*.json") if p.name != "state.json"]
        for path in shards:
            try:
                data = json.loads(path.read_text(encoding="utf-8"))
            except (json.JSONDecodeError, OSError):
                continue
            if isinstance(data, dict):
                merged.update(data)
        return merged

    def run(self, db: "databaseSQLite") -> None:
        import subprocess
        import tempfile

        db.createTable()

        # 1. Nomes npm descobertos do manifesto raiz (fonte de verdade).
        db.cursor.execute(
            "SELECT fullpath, npm_name FROM repo_manifests WHERE npm_name IS NOT NULL"
        )
        candidates = [
            (row[0], row[1]) for row in db.cursor.fetchall() if row[0] and row[1]
        ]
        if not candidates:
            print(
                "[INFO] npm: no repositories with a package.json name in cache; "
                "run 'scan-manifests' first. Skipping"
            )
            return
        print(
            f"[INFO] npm: {len(candidates)} repositories have a package.json name to validate"
        )

        # 2. Contagens de download da última branch build-* (clone shallow). O mapa é a
        #    prova de existência no npm e a fonte dos números — daí ler TODOS os shards.
        counts: dict = {}
        branch = self._resolveLatestBuildBranch()
        if branch:
            with tempfile.TemporaryDirectory() as tmp:
                clone_dir = Path(tmp) / "download-counts"
                try:
                    subprocess.run(
                        [
                            "git",
                            "clone",
                            "--depth=1",
                            "--single-branch",
                            "--branch",
                            branch,
                            self.DOWNLOAD_COUNTS_GIT,
                            str(clone_dir),
                        ],
                        capture_output=True,
                        text=True,
                        timeout=600,
                        check=True,
                    )
                    counts = self._loadDownloadCounts(clone_dir)
                    print(
                        f"[INFO] npm: loaded {len(counts)} download counts from {branch}"
                    )
                except (subprocess.SubprocessError, OSError) as e:
                    print(f"[WARN] npm: failed to clone download-counts@{branch}: {e}")
        if not counts:
            print(
                "[WARN] npm: no download-counts available to validate names; skipping"
            )
            return

        # 3. Mapa autoritativo pacote -> repositório (registry.npmjs.org), restrito aos
        #    nomes que precisamos checar: os candidates + os que já estão como npm (para
        #    o scrub retroativo). Serve só para REJEITAR atribuições erradas.
        # (fullpath, name) dos repos atualmente npm, para o scrub. O nome vem PRIMEIRO
        # do package_url (o que está REALMENTE taggeado) e só então do repo_manifests.
        existing_npm = [
            (row[0], self._pkgNameFromUrl(row[1]) or row[2])
            for row in db.cursor.execute(
                "SELECT r.fullpath, r.package_url, m.npm_name "
                "FROM repositories r LEFT JOIN repo_manifests m ON m.fullpath = r.fullpath "
                "WHERE r.ecosystem = 'npm'"
            ).fetchall()
        ]
        needed_names = {npm_name for _, npm_name in candidates}
        needed_names.update(name for _, name in existing_npm if name)
        print(
            f"[INFO] npm: resolving canonical repo for {len(needed_names)} package names "
            f"(npm registry, cached)"
        )
        known_repo = self._buildKnownRepoMap(db, needed_names)

        # 4. Reset retroativo: limpa o enriquecimento npm de repos já varridos. Os
        #    repos válidos são reconfirmados no loop abaixo; falsos-positivos da lógica
        #    antiga voltam a 'github'. Repos ainda não varridos não são tocados.
        reset = db.resetScannedPackageEnrichment("npm")
        if reset:
            print(
                f"[INFO] npm: reset {reset} previously-enriched repos (will reconfirm valid ones)"
            )

        # 5. Scrub retroativo: repos ainda marcados npm cujo pacote pertence, segundo o
        #    registry, a OUTRO repositório (ex.: grafana/grafana-image-renderer com
        #    'minimatch', que é de isaacs/minimatch) voltam a 'github'. Pega também os
        #    obsoletos fora de repo_manifests, que o reset acima não toca.
        scrubbed = 0
        if known_repo:
            for fullpath, name in existing_npm:
                if not name:
                    continue
                owner = known_repo.get(name)
                if (
                    owner
                    and owner != fullpath
                    and db.resetRepoToGithub(fullpath, "npm")
                ):
                    scrubbed += 1
            if scrubbed:
                db.conn.commit()
                print(
                    f"[INFO] npm: scrubbed {scrubbed} repos mis-tagged with another repo's package"
                )

        # 6. Enriquecimento: só nomes presentes no download-counts (publicados no npm) e
        #    cujo repositório conhecido (se houver) seja este mesmo repo.
        enriched = rejected = 0
        for fullpath, npm_name in candidates:
            if known_repo:
                owner = known_repo.get(npm_name)
                if owner and owner != fullpath:
                    rejected += 1
                    continue  # pacote pertence a outro repositório: não é deste repo
            downloads = counts.get(npm_name)
            if downloads is None:
                downloads = counts.get(npm_name.lower())
            if downloads is None:
                continue  # nome não é pacote npm publicado
            downloads = int(downloads) if isinstance(downloads, (int, float)) else None
            package_url = f"https://www.npmjs.com/package/{npm_name}"
            if db.enrichPackage(fullpath, "npm", package_url, downloads):
                enriched += 1
            if enriched % 500 == 0:
                db.conn.commit()
        db.conn.commit()

        started = datetime.now(timezone.utc).isoformat()
        db.updateSource(
            self.SOURCE_NAME,
            started,
            started,
            branch or "",
            base_release_file=branch or "",
        )
        print(
            f"[INFO] npm: enriched {enriched} repositories with npm package metadata "
            f"({rejected} rejected by package->repo guard, {scrubbed} scrubbed retroactively)"
        )


class PackagistPackages:
    """
    Enriquece repositórios com o pacote Packagist correspondente usando como NOME a
    fonte de verdade descoberta por RepoManifestScanner (repo_manifests.composer_name,
    lido do composer.json raiz na branch default).

    Fluxo:
    1. Para cada repo com composer_name no cache (que ainda não virou npm), consulta
       a API do Packagist (packagist.org/packages/<name>.json) para VALIDAR que o
       pacote existe e obter .package.downloads.total.
    2. Em um 200, grava ecosystem='packagist', package_url e downloads.
    """

    PROJECT_ROOT = Path(__file__).parent.parent.absolute()
    DATA_DIR = PROJECT_ROOT / "data"
    SOURCE_NAME = "packagist"

    API_URL = "https://packagist.org/packages/{name}.json"

    def run(self, db: "databaseSQLite") -> None:
        db.createTable()

        # Nomes Packagist descobertos do composer.json raiz. Exclui repos que já
        # viraram npm neste pipeline (npm roda antes), evitando sobrescrever.
        db.cursor.execute(
            """
            SELECT m.fullpath, m.composer_name
            FROM repo_manifests m
            JOIN repositories r ON r.fullpath = m.fullpath
            WHERE m.composer_name IS NOT NULL
              AND COALESCE(r.ecosystem, 'github') != 'npm'
            """
        )
        candidates = [
            (row[0], row[1]) for row in db.cursor.fetchall() if row[0] and row[1]
        ]

        # Reset retroativo (sem rede): repos já varridos marcados 'packagist' pela lógica
        # antiga mas SEM composer.json raiz não são pacotes Packagist -> voltam a 'github'.
        # (Os que falham a validação na API são revertidos por-repo no 404, abaixo.)
        reset = db.resetScannedPackageEnrichment(
            "packagist", missing_name_column="composer_name"
        )
        if reset:
            print(
                f"[INFO] packagist: reset {reset} previously-enriched repos without composer.json"
            )

        if not candidates:
            print(
                "[INFO] packagist: no repositories with a composer.json name in cache; "
                "run 'scan-manifests' first. Skipping"
            )
            db.conn.commit()
            return
        print(
            f"[INFO] packagist: {len(candidates)} repositories have a composer.json name to validate"
        )

        enriched = 0
        for i, (fullpath, name) in enumerate(candidates, 1):
            try:
                resp = http_get(self.API_URL.format(name=name))
                if resp.status_code == 404:
                    # Nome não existe (mais) no Packagist: definitivo -> reverte se era packagist.
                    db.resetRepoToGithub(fullpath, "packagist")
                    continue
                if resp.status_code != 200:
                    continue  # transitório (5xx/429): não mexe
                pkg = resp.json().get("package", {})
            except (REQUEST_EXCEPTION, ValueError) as e:
                print(f"[WARN] packagist: failed to fetch {name}: {e}")
                continue

            total = (pkg.get("downloads") or {}).get("total")
            total = int(total) if isinstance(total, (int, float)) else None
            package_url = f"https://packagist.org/packages/{name}"
            if db.enrichPackage(fullpath, "packagist", package_url, total):
                enriched += 1

            if i % 200 == 0:
                db.conn.commit()
                print(
                    f"[INFO] packagist: processed {i}/{len(candidates)} packages ({enriched} enriched)"
                )
            time.sleep(0.05)  # educado com a API pública do Packagist
        db.conn.commit()

        started = datetime.now(timezone.utc).isoformat()
        db.updateSource(self.SOURCE_NAME, started, started, str(len(candidates)))
        print(
            f"[INFO] packagist: enriched {enriched} repositories with Packagist metadata"
        )


class OsvNpmPackages:
    """
    Fonte OSV (npm): storage.googleapis.com/osv-vulnerabilities/npm/all.zip.

    Lê APENAS os advisories GHSA-*.json do snapshot e usa o mapeamento autoritativo
    CVE -> nome do pacote npm (aliases + affected[].package.name) para fixar o pacote
    dos repositórios já relacionados àquela CVE no banco (cve_repositories). Como vem
    do feed OSV do npm, o nome é uma fonte de verdade mais confiável que o manifesto
    raiz, então SOBRESCREVE repo_manifests.npm_name. O enriquecimento final
    (ecosystem='npm', package_url, downloads) é feito pelo comando 'npm' a seguir.

    Retroativo: varre o snapshot completo a cada execução e casa por aliases com os
    CVEs já existentes (cveExists); CVEs ausentes ou sem repositório relacionado são
    ignoradas, e nenhuma CVE nova é criada.
    """

    PROJECT_ROOT = Path(__file__).parent.parent.absolute()
    DATA_DIR = PROJECT_ROOT / "data"
    SOURCE_NAME = "osv-npm"

    SOURCE_URL = "https://storage.googleapis.com/osv-vulnerabilities/npm/all.zip"

    @staticmethod
    def _cveAliases(data: dict) -> list[str]:
        """Aliases que são CVEs (uppercased), ex.: ['CVE-2025-25289']."""
        return [
            a.upper()
            for a in (data.get("aliases") or [])
            if isinstance(a, str) and a.upper().startswith("CVE-")
        ]

    @staticmethod
    def _npmNamesFromAffected(data: dict) -> list[str]:
        """Nomes de pacote npm DISTINTOS em affected[] (package.ecosystem == 'npm')."""
        names: list[str] = []
        for aff in data.get("affected", []):
            if not isinstance(aff, dict):
                continue
            pkg = aff.get("package") or {}
            if (pkg.get("ecosystem") or "").lower() != "npm":
                continue
            name = pkg.get("name")
            if isinstance(name, str) and name.strip():
                clean = name.strip()
                if clean not in names:
                    names.append(clean)
        return names

    def run(self, db: "databaseSQLite") -> None:
        db.createTable()

        dest = self.DATA_DIR / "osv-npm-all.zip"
        print(f"[INFO] osv-npm: downloading {self.SOURCE_URL} ...")
        download_to(self.SOURCE_URL, dest)

        scanned = ambiguous = matched = overridden = 0
        with zipfile.ZipFile(dest, "r") as zf:
            for name in zf.namelist():
                base = name.rsplit("/", 1)[-1]
                # Só os advisories GHSA-*.json; ignora os demais ids do feed.
                if not (base.startswith("GHSA-") and base.endswith(".json")):
                    continue
                try:
                    data = json.loads(zf.read(name))
                except (json.JSONDecodeError, OSError):
                    continue
                if not isinstance(data, dict):
                    continue

                scanned += 1

                npm_names = self._npmNamesFromAffected(data)
                # Só atribuímos quando o pacote é inequívoco: 0 = sem pacote npm;
                # >1 = não dá para saber qual nome mapeia a qual repo -> pula.
                if len(npm_names) != 1:
                    if len(npm_names) > 1:
                        ambiguous += 1
                    continue
                npm_name = npm_names[0]

                cve_ids = self._cveAliases(data)
                if not cve_ids:
                    continue

                for cve_id in cve_ids:
                    if not db.cveExists(cve_id):
                        continue
                    repos = db.getCveGithubRepos(cve_id)
                    if not repos:
                        continue
                    matched += 1
                    # Atribuição ampla: aplica o nome a todos os repos relacionados.
                    for fullpath in repos:
                        if db.overrideManifestNpmName(fullpath, npm_name):
                            overridden += 1

                if scanned % 2000 == 0:
                    db.conn.commit()
                    print(
                        f"[INFO] osv-npm: scanned {scanned} GHSA advisories "
                        f"({matched} CVE matches, {overridden} repo names overridden)"
                    )

        db.conn.commit()
        dest.unlink(missing_ok=True)

        started = datetime.now(timezone.utc).isoformat()
        db.updateSource(self.SOURCE_NAME, started, started, "")
        print(
            f"[INFO] osv-npm: read {scanned} GHSA advisories "
            f"({ambiguous} skipped as ambiguous), {matched} CVE matches, "
            f"{overridden} repository npm names overridden. "
            f"Run 'npm' next to enrich them."
        )


def main() -> None:
    import argparse
    import os

    parser = argparse.ArgumentParser(
        description="CVE Database Tool (ingest CVEs, verify repos, and generate DB manifest)"
    )
    parser.add_argument(
        "command",
        choices=[
            "cves",
            "cves-ids",
            "repos",
            "advisories",
            "pocs",
            "nuclei",
            "wordpress",
            "scan-manifests",
            "osv-npm",
            "npm",
            "packagist",
            "kev",
            "wordfence-nuclei",
            "missing-templates",
            "backfill-titles",
            "update-fixes",
            "manifest",
            "all",
        ],
        nargs="?",
        default="cves",
        help=(
            "Command: 'cves' (download CVEs), 'repos' (verify repos), "
            "'cves-ids' (import specific CVE IDs), "
            "'advisories' (enrich CVEs from GitHub Advisory Database), "
            "'pocs' (enrich exploit fields from PoC-in-GitHub), "
            "'nuclei' (enrich exists_nuclei/list_nuclei from projectdiscovery/nuclei-templates), "
            "'wordpress' (enrich WordPress plugins with install/download metrics), "
            "'scan-manifests' (read package.json/composer.json name from each repo's default branch), "
            "'osv-npm' (override repo npm names from the OSV npm feed, CVE->package), "
            "'npm' (enrich repos with npm package metadata using the scanned name), "
            "'packagist' (enrich repos with Packagist package metadata using the scanned name), "
            "'backfill-titles' (re-derive 'No Title Found' titles from description, retroactive), "
            "'update-fixes' (recalculate commits_fix), "
            "'manifest' (generate public/db/manifest.json), "
            "'all' (cves+repos+advisories+pocs+nuclei+wordpress+scan-manifests+osv-npm+npm+packagist+manifest)"
        ),
    )
    parser.add_argument(
        "--cve-ids", default="", help="Comma-separated CVE IDs for cves-ids command"
    )
    parser.add_argument(
        "--github-token",
        default=os.environ.get("GITHUB_TOKEN"),
        help="GitHub token for GraphQL verification (prefer GITHUB_TOKEN env var in CI)",
    )
    parser.add_argument(
        "--batch-size",
        type=int,
        default=100,
        help="Batch size for repository verification (default: 100)",
    )
    parser.add_argument(
        "--max-cves",
        type=int,
        default=None,
        help="Limit number of CVEs imported in cves/all mode (useful for smoke tests)",
    )
    parser.add_argument(
        "--min-pending-repos",
        type=int,
        default=0,
        help="Stop CVE import early after discovering this many pending GitHub repositories",
    )
    parser.add_argument(
        "--require-complete-cve",
        action="store_true",
        help="Only import CVEs that have score, CWE, affected product, repository, commit and exploit",
    )
    parser.add_argument(
        "--target-complete-cves",
        type=int,
        default=1,
        help="How many complete CVEs to import when --require-complete-cve is enabled (default: 1)",
    )
    parser.add_argument(
        "--max-deltas",
        type=int,
        default=5,
        help="Maximum number of recent delta releases to scan in force-delta complete mode",
    )
    parser.add_argument(
        "--force-delta",
        action="store_true",
        help="Use latest delta package on first cves run instead of full package",
    )
    parser.add_argument(
        "--year",
        type=int,
        default=None,
        help="Import only CVEs from a specific year in first full run (e.g. 1999)",
    )
    parser.add_argument(
        "--year-auto",
        action="store_true",
        help="On first full run, import only one year per execution and persist progress to next year",
    )
    parser.add_argument(
        "--db-dir",
        default="public/db",
        help="Directory containing DB files for manifest generation (default: public/db)",
    )
    parser.add_argument(
        "--db-file",
        default="source_com_repositorios.sqlite",
        help="Base sqlite filename used by manifest generator (default: source_com_repositorios.sqlite)",
    )
    parser.add_argument(
        "--manifest-output",
        default=None,
        help="Optional explicit output path for manifest.json",
    )
    parser.add_argument(
        "--manifest-base-url",
        default="/db",
        help="Base URL prefix in manifest source URLs (default: /db)",
    )
    parser.add_argument(
        "--manifest-version", default=None, help="Optional explicit manifest version"
    )
    parser.add_argument(
        "--compress-gzip",
        action="store_true",
        help="Generate .gz from base sqlite file if missing",
    )
    parser.add_argument(
        "--full",
        action="store_true",
        help="Force a full re-scan for the advisories command (backfill: create advisory-only CVEs missing from the DB instead of incremental)",
    )

    args = parser.parse_args()
    if args.batch_size <= 0:
        raise SystemExit("[ERROR] --batch-size must be greater than zero")
    if args.max_cves is not None and args.max_cves <= 0:
        raise SystemExit("[ERROR] --max-cves must be greater than zero")
    if args.min_pending_repos < 0:
        raise SystemExit("[ERROR] --min-pending-repos cannot be negative")
    if args.target_complete_cves <= 0:
        raise SystemExit("[ERROR] --target-complete-cves must be greater than zero")
    if args.max_deltas <= 0:
        raise SystemExit("[ERROR] --max-deltas must be greater than zero")
    if args.year is not None and args.year <= 0:
        raise SystemExit("[ERROR] --year must be greater than zero")
    if args.year is not None and args.year_auto:
        raise SystemExit("[ERROR] --year and --year-auto cannot be used together")

    if args.github_token and args.github_token != os.environ.get("GITHUB_TOKEN"):
        print("[WARN] Avoid passing token by CLI in CI. Prefer GITHUB_TOKEN env var.")

    if args.command in ["cves", "all"]:
        print("[INFO] Getting CVES database https://github.com/CVEProject/cvelistV5")
        CVElistV5().run(
            max_cves=args.max_cves,
            force_delta=args.force_delta,
            min_pending_repos=args.min_pending_repos,
            require_complete_cve=args.require_complete_cve,
            target_complete_cves=args.target_complete_cves,
            max_deltas=args.max_deltas,
            year=args.year,
            year_auto=args.year_auto,
        )

    if args.command == "cves-ids":
        if not args.cve_ids.strip():
            raise SystemExit("[ERROR] --cve-ids is required for cves-ids command")
        cve_ids = [item.strip() for item in args.cve_ids.split(",") if item.strip()]
        CVElistV5().runByIds(cve_ids)

    if args.command in ["repos", "all"]:
        if not args.github_token:
            print("[ERROR] GitHub token required for repository verification.")
            print("        Set GITHUB_TOKEN env var or use --github-token argument")
            return

        print("[INFO] Verifying GitHub repositories...")
        db_path = CVElistV5.DATA_DIR / "source.sqlite"
        db = databaseSQLite(db_path)

        verifier = GitHubRepositoryVerifier(args.github_token)
        verifier.run(db, batch_size=args.batch_size)

        db.conn.close()

    if args.command in ["advisories", "all"]:
        print(
            "[INFO] Enriching CVEs from GitHub Advisory Database (github/advisory-database)..."
        )
        db_path = CVElistV5.DATA_DIR / "source.sqlite"
        db = databaseSQLite(db_path)
        GitHubAdvisory().run(db, force_full=args.full)
        db.conn.close()

    if args.command in ["pocs", "all"]:
        print(
            "[INFO] Enriching exploit fields from PoC-in-GitHub (nomi-sec/PoC-in-GitHub)..."
        )
        db_path = CVElistV5.DATA_DIR / "source.sqlite"
        db = databaseSQLite(db_path)
        PoCInGitHub().run(db)
        db.conn.close()

    if args.command in ["nuclei", "all"]:
        print(
            "[INFO] Enriching Nuclei templates (projectdiscovery/nuclei-templates)..."
        )
        db_path = CVElistV5.DATA_DIR / "source.sqlite"
        db = databaseSQLite(db_path)
        NucleiTemplates().run(db, force_full=args.full)
        db.conn.close()

    if args.command in ["kev", "all"]:
        print("[INFO] Enriching with CISA KEV catalog...")
        db_path = CVElistV5.DATA_DIR / "source.sqlite"
        db = databaseSQLite(db_path)
        KevEnrichment().run(db)
        db.conn.close()

    if args.command in ["wordfence-nuclei", "all"]:
        print(
            "[INFO] Enriching with Wordfence Nuclei templates (topscoder/nuclei-wordfence-cve)..."
        )
        db_path = CVElistV5.DATA_DIR / "source.sqlite"
        db = databaseSQLite(db_path)
        WordfenceNucleiTemplates().run(db)
        db.conn.close()

    if args.command in ["missing-templates", "all"]:
        print("[INFO] Enriching with missing nuclei template indicator...")
        db_path = CVElistV5.DATA_DIR / "source.sqlite"
        db = databaseSQLite(db_path)
        MissingNucleiTemplates().run(db)
        db.conn.close()

    if args.command in ["backfill-titles", "all"]:
        print("[INFO] Backfilling CVE titles from description (retroactive)...")
        db_path = CVElistV5.DATA_DIR / "source.sqlite"
        db = databaseSQLite(db_path)
        TitleBackfill().run(db)
        db.conn.close()

    if args.command in ["wordpress", "all"]:
        print(
            "[INFO] Enriching WordPress plugins with install/download metrics (rix4uni/wordpress-plugins)..."
        )
        db_path = CVElistV5.DATA_DIR / "source.sqlite"
        db = databaseSQLite(db_path)
        WordPressMetadata().run(db)
        db.conn.close()

    if args.command in ["scan-manifests", "all"]:
        print(
            "[INFO] Scanning repositories' default-branch manifests (package.json/composer.json)..."
        )
        db_path = CVElistV5.DATA_DIR / "source.sqlite"
        db = databaseSQLite(db_path)
        RepoManifestScanner(token=args.github_token).run(db)
        db.conn.close()

    if args.command in ["osv-npm", "all"]:
        print(
            "[INFO] Overriding repository npm names from the OSV npm feed (CVE->package)..."
        )
        db_path = CVElistV5.DATA_DIR / "source.sqlite"
        db = databaseSQLite(db_path)
        OsvNpmPackages().run(db)
        db.conn.close()

    if args.command in ["npm", "all"]:
        print(
            "[INFO] Enriching repositories with npm package metadata (nice-registry)..."
        )
        db_path = CVElistV5.DATA_DIR / "source.sqlite"
        db = databaseSQLite(db_path)
        NpmPackages().run(db)
        db.conn.close()

    if args.command in ["packagist", "all"]:
        print(
            "[INFO] Enriching repositories with Packagist package metadata (OSV + Packagist API)..."
        )
        db_path = CVElistV5.DATA_DIR / "source.sqlite"
        db = databaseSQLite(db_path)
        PackagistPackages().run(db)
        db.conn.close()

    if args.command == "update-fixes":
        print("[INFO] Updating commits_fix for all repositories...")
        db_path = CVElistV5.DATA_DIR / "source.sqlite"
        db = databaseSQLite(db_path)

        db.updateAllRepositoriesCommitsFix()

        db.conn.close()

    if args.command in ["manifest", "all"]:
        db_dir = Path(args.db_dir)
        output = Path(args.manifest_output) if args.manifest_output else None
        generate_db_manifest(
            db_dir=db_dir,
            base_url=args.manifest_base_url,
            version=args.manifest_version,
            output_path=output,
            compress_gzip=args.compress_gzip,
            db_file_name=args.db_file,
        )


if __name__ == "__main__":
    main()
