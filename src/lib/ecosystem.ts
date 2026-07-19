import {
  IconBrandGithub,
  IconBrandNpm,
  IconBrandPhp,
  IconBrandWordpress,
  type Icon
} from '@tabler/icons-react';

export interface EcosystemMeta {
  label: string;
  Icon: Icon;
  /** Tailwind text-color class for the ecosystem accent. */
  textClass: string;
  /** Tailwind border + text classes for outline badges. */
  borderClass: string;
}

/**
 * Maps a repository `ecosystem` value ('github' | 'wordpress' | 'npm' |
 * 'packagist') to its brand icon, label and accent colors.
 *
 * Fonte única compartilhada entre a busca de repositórios (results-table,
 * detail-drawer) e a busca de CVEs (cve-detail-drawer). Ecossistema
 * desconhecido/nulo cai no default de GitHub.
 */
export function getEcosystemMeta(ecosystem: string | null): EcosystemMeta {
  switch (ecosystem) {
    case 'wordpress':
      return {
        label: 'WordPress',
        Icon: IconBrandWordpress,
        textClass: 'text-[#21759b]',
        borderClass: 'border-[#21759b]/50 text-[#21759b]'
      };
    case 'npm':
      return {
        label: 'npm',
        Icon: IconBrandNpm,
        textClass: 'text-[#cb3837]',
        borderClass: 'border-[#cb3837]/50 text-[#cb3837]'
      };
    case 'packagist':
      return {
        label: 'Packagist',
        Icon: IconBrandPhp,
        textClass: 'text-[#6082bc]',
        borderClass: 'border-[#6082bc]/50 text-[#6082bc]'
      };
    default:
      return {
        label: 'GitHub',
        Icon: IconBrandGithub,
        textClass: 'text-muted-foreground',
        borderClass: 'text-muted-foreground'
      };
  }
}
