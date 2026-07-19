import { create } from 'zustand';

interface ContentReadyState {
  /** Whether the current dashboard page's main content has finished loading. */
  ready: boolean;
  setReady: (ready: boolean) => void;
}

/**
 * Global flag shared between the dashboard pages and the layout Footer.
 *
 * The Footer lives in the dashboard layout (outside each page's SQLiteProvider),
 * so it can't read a page's loading state directly. Each page sets this flag when
 * its content is ready (DB loaded / static page mounted) and resets it on unmount;
 * the Footer only renders once it's true, so it never floats under a loader.
 */
export const useContentReady = create<ContentReadyState>((set) => ({
  ready: false,
  setReady: (ready) => set({ ready })
}));
