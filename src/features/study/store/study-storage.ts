// Adapter de persistência para o Zustand `persist` gravando no IndexedDB (via `idb`).
// Mesmo espírito de src/lib/sqlite/db-cache.ts, mas num banco próprio `suncve-study`
// (separado do cache read-only do SQLite). Sem o teto de ~5MB do localStorage.

import { openDB, type IDBPDatabase } from 'idb';
import type { StateStorage } from 'zustand/middleware';

const DB_NAME = 'suncve-study';
const STORE_NAME = 'keyval';

interface StudyKVDB {
  keyval: {
    key: string;
    value: string;
  };
}

let dbPromise: Promise<IDBPDatabase<StudyKVDB>> | null = null;

function getDB() {
  // Lazy: só abre no client, quando o persist realmente lê/escreve.
  if (!dbPromise) {
    dbPromise = openDB<StudyKVDB>(DB_NAME, 1, {
      upgrade(db) {
        if (!db.objectStoreNames.contains(STORE_NAME)) {
          db.createObjectStore(STORE_NAME);
        }
      }
    });
  }
  return dbPromise;
}

export const idbStorage: StateStorage = {
  async getItem(name) {
    try {
      const db = await getDB();
      return (await db.get(STORE_NAME, name)) ?? null;
    } catch (error) {
      console.error('[study] erro lendo IndexedDB:', error);
      return null;
    }
  },
  async setItem(name, value) {
    try {
      const db = await getDB();
      await db.put(STORE_NAME, value, name);
    } catch (error) {
      console.error('[study] erro gravando IndexedDB:', error);
    }
  },
  async removeItem(name) {
    try {
      const db = await getDB();
      await db.delete(STORE_NAME, name);
    } catch (error) {
      console.error('[study] erro removendo do IndexedDB:', error);
    }
  }
};
