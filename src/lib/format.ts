/**
 * Entidades nomeadas aceitas. É uma allowlist de propósito: só o que aparece de
 * fato nos nomes vindos das fontes (wordpress.org & cia). Qualquer `&palavra;`
 * fora daqui é devolvida literal.
 */
const NAMED_ENTITIES: Record<string, string> = {
  amp: '&',
  lt: '<',
  gt: '>',
  quot: '"',
  apos: "'",
  nbsp: ' ',
  ndash: '–',
  mdash: '—',
  hellip: '…',
  lsquo: '‘',
  rsquo: '’',
  ldquo: '“',
  rdquo: '”',
  laquo: '«',
  raquo: '»',
  times: '×',
  middot: '·',
  bull: '•',
  trade: '™',
  reg: '®',
  copy: '©',
  deg: '°'
};

const ENTITY_RE = /&(?:#(\d{1,7})|#[xX]([0-9a-fA-F]{1,6})|([a-zA-Z][a-zA-Z0-9]{1,31}));/g;

/**
 * Um code point só é aceito se não puder ser usado para atacar quem lê a tela:
 * fora do range Unicode, surrogates soltos, NUL/controles C0-C1 e os overrides
 * de direção (que reordenam visualmente o texto e permitem disfarçar um nome).
 */
function isSafeCodePoint(cp: number): boolean {
  if (!Number.isFinite(cp) || cp <= 0 || cp > 0x10ffff) return false;
  if (cp >= 0xd800 && cp <= 0xdfff) return false; // surrogates
  if (cp < 0x20 || (cp >= 0x7f && cp <= 0x9f)) return false; // controles C0/C1
  if (cp >= 0x202a && cp <= 0x202e) return false; // bidi embedding/override
  if (cp >= 0x2066 && cp <= 0x2069) return false; // bidi isolates
  return true;
}

/**
 * Decodifica entidades HTML de texto vindo do banco (ex.: `WPForms &#8211; AI`)
 * para exibição. Seguro por construção:
 *
 * - sem DOM (nada de innerHTML/DOMParser), então não existe caminho de execução;
 * - UMA passada só, nunca em laço até estabilizar — é isso que faz
 *   `&amp;lt;script&amp;gt;` virar o texto `&lt;script&gt;` e nunca `<script>`;
 * - code points validados por `isSafeCodePoint`, match inválido volta literal;
 * - entidades nomeadas por allowlist.
 *
 * O resultado é sempre renderizado como text node do React (que escapa por
 * conta própria) — não passe isso para dangerouslySetInnerHTML nem para href.
 */
export function decodeHtmlEntities<T extends string | null | undefined>(
  text: T
): T {
  if (!text || !text.includes('&')) return text;

  return text.replace(
    ENTITY_RE,
    (match, dec: string | undefined, hex: string | undefined, name) => {
      if (dec !== undefined || hex !== undefined) {
        const cp =
          dec !== undefined ? Number.parseInt(dec, 10) : Number.parseInt(hex!, 16);
        return isSafeCodePoint(cp) ? String.fromCodePoint(cp) : match;
      }
      return NAMED_ENTITIES[name] ?? match;
    }
  ) as T;
}

export function formatDate(
  date: Date | string | number | undefined,
  opts: Intl.DateTimeFormatOptions = {}
) {
  if (!date) return '';

  try {
    return new Intl.DateTimeFormat('en-US', {
      month: opts.month ?? 'long',
      day: opts.day ?? 'numeric',
      year: opts.year ?? 'numeric',
      ...opts
    }).format(new Date(date));
  } catch (_err) {
    return '';
  }
}

/**
 * Formata uma data de acordo com o idioma atual da UI: dd/MM/aaaa em português
 * e MM/dd/aaaa em inglês. Centraliza a exibição de datas para manter o padrão
 * brasileiro quando o locale for pt-BR. Retorna `fallback` para datas inválidas.
 */
export function formatDateLocalized(
  date: Date | string | number | null | undefined,
  locale: string,
  fallback = '—'
): string {
  if (date == null || date === '') return fallback;
  const parsed = new Date(date);
  if (Number.isNaN(parsed.getTime())) {
    return typeof date === 'string' ? date : fallback;
  }
  return new Intl.DateTimeFormat(locale, {
    year: 'numeric',
    month: '2-digit',
    day: '2-digit'
  }).format(parsed);
}
