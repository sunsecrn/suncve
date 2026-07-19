import { NavItem } from '@/types';

/**
 * Navigation configuration
 */
export const navItems: NavItem[] = [
  {
    title: 'Dashboard',
    url: '/dashboard/overview',
    icon: 'dashboard',
    isActive: false,
    shortcut: ['d', 'd'],
    items: []
  },
  {
    title: 'CVE Search',
    url: '/dashboard/search',
    icon: 'search',
    isActive: false,
    shortcut: ['c', 's'],
    items: []
  },
  {
    title: 'Repository Search',
    url: '/dashboard/repositories',
    icon: 'github',
    isActive: false,
    shortcut: ['r', 's'],
    items: []
  },
  {
    title: 'My Studies',
    url: '/dashboard/studies',
    icon: 'studies',
    isActive: false,
    shortcut: ['m', 'e'],
    items: []
  },
  {
    title: 'README',
    url: '/dashboard/readme',
    icon: 'readme',
    isActive: false,
    shortcut: ['r', 'm'],
    items: []
  }
];
