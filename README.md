# SunCVE

Dashboard para pesquisa e análise de CVEs (Common Vulnerabilities and Exposures).

## Tech Stack

- **Framework** - [Next.js 16](https://nextjs.org)
- **Language** - [TypeScript](https://www.typescriptlang.org)
- **Styling** - [Tailwind CSS v4](https://tailwindcss.com)
- **Components** - [Shadcn UI](https://ui.shadcn.com)
- **Database** - SQLite (sql.js) para dados de CVEs
- **Internationalization** - [next-intl](https://next-intl.dev) (PT-BR / EN)
- **State Management** - [Zustand](https://zustand-demo.pmnd.rs)
- **Tables** - [Tanstack Data Tables](https://tanstack.com/table)

## Features

- 🔍 **Pesquisa de CVEs** - Busca textual e filtros avançados (severidade, CVSS, CWE, ecossistema, exploit, KEV, Nuclei e mais)
- 📦 **Busca de repositórios** - Repositórios GitHub vinculados a CVEs, com stars, downloads, ecossistema e commits de correção; modal de detalhes
- 📊 **Dashboard** - Estatísticas, gráficos e CVEs críticas com tags de origem (exploit, commit, Nuclei, KEV) ao lado do CVSS
- 🧩 **Enriquecimento multi-fonte** - Cada CVE cruzada com Nuclei, Wordfence, CISA KEV, PoCs, commits de correção e pacotes (npm/Packagist/WordPress)
- 🎯 **Templates Nuclei** - Cada CVE mapeada para os templates do [Nuclei](https://github.com/projectdiscovery/nuclei-templates) que a detectam (filtro, badge e link)
- 🤖 **API & MCP local** - Interface read-only "de máquina" sobre o SQLite (HTTP + [MCP](https://modelcontextprotocol.io)), para rodar localmente
- 🌐 **Internacionalização** - Suporte para Português e Inglês
- 🎨 **Temas** - Múltiplos temas de cores
- 📱 **Responsivo** - Funciona em desktop e mobile
- 🚀 **Static Export** - Deploy em GitHub Pages

## Fontes de dados

As CVEs são construídas e enriquecidas cruzando múltiplas fontes públicas:

| Fonte | O que agrega |
|-------|--------------|
| [CVE List V5](https://github.com/CVEProject/cvelistV5) | Base de CVEs — metadados, descrição, CVSS, CWE e produtos afetados |
| [GitHub Advisory Database](https://github.com/github/advisory-database) | Enriquece (e cria) CVEs — referências, CVSS, CWE e pacotes afetados |
| [PoC-in-GitHub](https://github.com/nomi-sec/PoC-in-GitHub) | Provas de conceito / exploits públicos |
| [Nuclei Templates](https://github.com/projectdiscovery/nuclei-templates) | Templates de detecção que cobrem a CVE |
| [Wordfence Nuclei CVE](https://github.com/topscoder/nuclei-wordfence-cve) | Templates Nuclei da Wordfence (identificados pela fonte) |
| [Missing CVE Nuclei Templates](https://github.com/edoardottt/missing-cve-nuclei-templates) | Indicador de "template pendente" (CVE sem template oficial) |
| [CISA KEV](https://www.cisa.gov/known-exploited-vulnerabilities-catalog) | Vulnerabilidades exploradas conhecidas — data de inclusão, prazo e uso em ransomware |
| [npm](https://www.npmjs.com) · [Packagist](https://packagist.org) · [WordPress](https://wordpress.org/plugins/) | Ecossistema do pacote, downloads e instalações ativas |

## Filtros disponíveis

**Busca de CVEs:** texto (CVE, fornecedor, produto, descrição), faixa de CVSS, severidade, CWE (e categoria de vulnerabilidade), período de publicação, ecossistema (GitHub/WordPress/npm/Packagist), stars e tamanho do repositório, faixa de downloads, linguagem, e flags: tem exploit, tem repositório, tem commit de correção, tem template Nuclei, está no KEV (CISA) e template pendente (comunidade).

**Busca de repositórios:** texto, ecossistema, linguagem, stars, tamanho, downloads, instalações ativas (WordPress) e flags: tem CVEs e tem commit de correção.

## Getting Started

**Pré-requisitos**: Node.js >=20.9.0 (preferir 22, ver `.nvmrc`), [gh CLI](https://cli.github.com) autenticado.

```bash
# Instalar dependências
npm install

# Provisionar banco de dados de CVEs (~141 MB)
bash scripts/setup-db.sh

# Rodar em desenvolvimento
npm run dev

# Build para produção
npm run build

# Build para GitHub Pages
npm run build:gh-pages
```

Sem o banco de dados, a UI renderiza mas não exibe dados de CVEs ou repositórios.

Acesse http://localhost:3000 para ver a aplicação.

## API & MCP local

Além da UI web, o projeto inclui um pacote **isolado e read-only** em [`local-api/`](local-api/README.md)
que expõe os mesmos dados como **API HTTP** e **servidor [MCP](https://modelcontextprotocol.io)**.
É opcional e não afeta o site: basta baixar o último snapshot do SQLite e rodar localmente
para consumir as CVEs de forma "de máquina" (scripts, integrações, agentes de IA).

```bash
cd local-api
npm install
npm run db:download        # baixa o último snapshot -> ./data/source.sqlite
npm run start:api          # HTTP em http://localhost:8787
npm run start:mcp          # servidor MCP (stdio)
```

Consulte [`local-api/README.md`](local-api/README.md) para a lista completa de
endpoints, as 15 tools MCP e a configuração do cliente (ex.: Claude Desktop).

## Pipeline de dados & enriquecimento

O banco é construído/enriquecido por `scripts/create-manifest.py` (executado
diariamente pelo workflow `db-snapshots.yml`). O comando aceita subcomandos por
fonte, por exemplo:

```bash
python scripts/create-manifest.py cves              # base de CVEs (cvelistV5)
python scripts/create-manifest.py advisories        # GitHub Advisory Database
python scripts/create-manifest.py pocs              # PoC-in-GitHub
python scripts/create-manifest.py nuclei            # templates Nuclei
python scripts/create-manifest.py wordfence-nuclei  # templates Nuclei da Wordfence
python scripts/create-manifest.py missing-templates # indicador de template pendente
python scripts/create-manifest.py kev               # catálogo CISA KEV
python scripts/create-manifest.py npm               # metadados npm (downloads)
python scripts/create-manifest.py packagist         # metadados Packagist
```

O enriquecimento **Nuclei** mapeia cada CVE aos seus templates via uma única
chamada à **Git Trees API** do repositório `projectdiscovery/nuclei-templates`
(sem clonar/baixar templates), guardando o link em `cves.list_nuclei`. Templates
da **Wordfence** entram na mesma lista, marcados com `source: "wordfence"`.

## Estrutura do Projeto

```
src/
├── app/              # Next.js App Router
├── components/       # Componentes compartilhados
├── features/         # Módulos por feature
│   ├── search/       # Pesquisa de CVEs
│   ├── repositories/ # Pesquisa de repositórios
│   └── overview/     # Dashboard (estatísticas e gráficos)
├── i18n/             # Internacionalização
├── lib/              # Utilitários e configurações
│   └── sqlite/       # Integração com SQLite
└── hooks/            # Custom hooks

local-api/            # API HTTP + servidor MCP local (read-only, opcional)
scripts/              # Pipeline de dados (create-manifest.py) e utilitários de DB
```

## License

MIT
