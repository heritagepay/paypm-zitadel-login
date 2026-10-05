// @vitest-environment node
import { createHash } from "node:crypto";
import { readFile, readdir } from "node:fs/promises";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

const database = vi.hoisted(() => ({
  applied: new Map<string, string>(),
  executed: [] as string[],
  inserted: [] as unknown[][],
  begin: vi.fn(),
  end: vi.fn(),
}));

vi.mock("postgres", () => ({
  default: () => {
    const sql = async (strings: TemplateStringsArray, ...values: unknown[]) => {
      if (strings[0].startsWith("SELECT checksum FROM login_workforce_migrations")) {
        const checksum = database.applied.get(String(values[0]));
        return checksum ? [{ checksum }] : [];
      }
      if (strings[0].startsWith("INSERT INTO login_workforce_migrations")) database.inserted.push(values);
      return [];
    };
    sql.begin = async (callback: (transaction: typeof sql) => Promise<void>) => {
      database.begin();
      await callback(sql);
    };
    sql.unsafe = async (source: string) => {
      database.executed.push(source);
    };
    sql.end = database.end;
    return sql;
  },
}));

async function checkedInMigrations() {
  const directory = new URL("../../migrations/", import.meta.url);
  const names = (await readdir(directory)).filter((name) => /^\d{3}_[a-z_]+\.sql$/.test(name)).sort();
  return Promise.all(
    names.map(async (name) => {
      const source = await readFile(new URL(name, directory), "utf8");
      return { version: name.slice(0, -4), source, checksum: createHash("sha256").update(source).digest("hex") };
    }),
  );
}

describe("workforce migration entrypoint", () => {
  beforeEach(() => {
    vi.resetModules();
    vi.stubEnv("PAYPM_WORKFORCE_MIGRATION_DATABASE_URL", "postgres://migration-test@127.0.0.1/never-connect");
    database.applied.clear();
    database.executed.length = 0;
    database.inserted.length = 0;
    database.begin.mockClear();
    database.end.mockClear();
    vi.spyOn(console, "log").mockImplementation(() => {});
  });
  afterEach(() => {
    vi.unstubAllEnvs();
    vi.restoreAllMocks();
  });

  it("runs every checked-in forward migration exactly once in filename order, including the Identity logout journal", async () => {
    const migrations = await checkedInMigrations();
    expect(migrations.some(({ version }) => version === "006_identity_logouts")).toBe(true);
    await import("../../scripts/migrate-workforce.mjs");
    expect(database.executed).toEqual(migrations.map(({ source }) => source));
    expect(database.inserted).toEqual(migrations.map(({ version, checksum }) => [version, checksum]));
    expect(database.begin).toHaveBeenCalledOnce();
    expect(database.end).toHaveBeenCalledOnce();
  });

  it("checks all previously applied migrations without reapplying them on an identical retry", async () => {
    for (const { version, checksum } of await checkedInMigrations()) database.applied.set(version, checksum);
    await import("../../scripts/migrate-workforce.mjs");
    expect(database.executed).toEqual([]);
    expect(database.inserted).toEqual([]);
    expect(database.end).toHaveBeenCalledOnce();
  });

  it("rejects a changed Identity logout checksum and closes the connection", async () => {
    for (const { version, checksum } of await checkedInMigrations()) database.applied.set(version, checksum);
    database.applied.set("006_identity_logouts", "changed-checksum");
    await expect(import("../../scripts/migrate-workforce.mjs")).rejects.toThrow(
      "Applied workforce migration checksum changed",
    );
    expect(database.executed).toEqual([]);
    expect(database.inserted).toEqual([]);
    expect(database.end).toHaveBeenCalledOnce();
  });
});
