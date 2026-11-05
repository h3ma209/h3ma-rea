import { existsSync, mkdirSync } from "node:fs";
import { homedir } from "node:os";
import { join } from "node:path";
import { DatabaseSync } from "node:sqlite";

export class DecompilationDiskCache {
  readonly #db: DatabaseSync | null = null;

  constructor() {
    try {
      const cacheDir = join(homedir(), ".cache", "rea");
      if (!existsSync(cacheDir)) {
        mkdirSync(cacheDir, { recursive: true });
      }
      const dbPath = join(cacheDir, "decompilation_cache.sqlite3");
      this.#db = new DatabaseSync(dbPath);
      this.#db.exec(`
        CREATE TABLE IF NOT EXISTS procedure_cache (
          cache_key TEXT PRIMARY KEY,
          pseudocode TEXT NOT NULL,
          created_at INTEGER NOT NULL
        );
      `);
    } catch {
      this.#db = null;
    }
  }

  get(cacheKey: string): string | null {
    if (!this.#db) return null;
    try {
      const stmt = this.#db.prepare(
        "SELECT pseudocode FROM procedure_cache WHERE cache_key = ?",
      );
      const row = stmt.get(cacheKey) as { pseudocode: string } | undefined;
      return row ? row.pseudocode : null;
    } catch {
      return null;
    }
  }

  set(cacheKey: string, pseudocode: string): void {
    if (!this.#db) return;
    try {
      const stmt = this.#db.prepare(`
        INSERT OR REPLACE INTO procedure_cache (cache_key, pseudocode, created_at)
        VALUES (?, ?, ?)
      `);
      stmt.run(cacheKey, pseudocode, Date.now());
    } catch {
      // silently ignore cache write errors
    }
  }
}
