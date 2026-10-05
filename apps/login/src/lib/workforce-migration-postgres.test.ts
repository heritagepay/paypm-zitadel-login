// @vitest-environment node
import { spawn } from "node:child_process";
import { createHash, randomUUID } from "node:crypto";
import { readFile } from "node:fs/promises";
import { fileURLToPath } from "node:url";
import postgres, { type Sql } from "postgres";
import { afterEach, beforeEach, describe, expect, it } from "vitest";

const url = process.env.PAYPM_WORKFORCE_TEST_DATABASE_URL;
const suite = url ? describe : describe.skip;
const application = fileURLToPath(new URL("../../", import.meta.url));
const versions = [
  "001_workforce_auth",
  "002_legacy_recovery_retirements",
  "003_workforce_action_intents",
  "004_operations_action_requests",
  "005_operations_logouts",
  "006_identity_logouts",
  "007_identity_action_requests",
];
async function run(connection: string) {
  return new Promise<{ status: number | null; stdout: string; stderr: string }>((resolve, reject) => {
    const child = spawn("bun", ["scripts/migrate-workforce.mjs"], {
      cwd: application,
      // Server-only ambient fields do not apply to this deliberately isolated child environment.
      env: Object.assign(Object.create(null) as NodeJS.ProcessEnv, {
        PATH: process.env.PATH,
        PAYPM_WORKFORCE_MIGRATION_DATABASE_URL: connection,
      }),
      stdio: ["ignore", "pipe", "pipe"],
    });
    let stdout = "",
      stderr = "";
    child.stdout.on("data", (chunk) => {
      stdout += chunk;
    });
    child.stderr.on("data", (chunk) => {
      stderr += chunk;
    });
    child.on("error", reject);
    child.on("close", (status) => resolve({ status, stdout, stderr }));
  });
}
async function source(version: string) {
  const body = await readFile(new URL(`../../migrations/${version}.sql`, import.meta.url), "utf8");
  return { body, checksum: createHash("sha256").update(body).digest("hex") };
}

suite("workforce migration runner (disposable PostgreSQL)", () => {
  let admin: Sql, sql: Sql, database: string, connection: string;
  beforeEach(async () => {
    admin = postgres(url!, { max: 1, onnotice: () => {} });
    database = "paypm_core_runner_" + randomUUID().replaceAll("-", "");
    await admin.unsafe(`CREATE DATABASE ${database}`);
    const parsed = new URL(url!);
    parsed.pathname = "/" + database;
    connection = parsed.href;
    sql = postgres(connection, { max: 1, onnotice: () => {} });
  });
  afterEach(async () => {
    await sql?.end();
    if (admin) {
      if (database) await admin.unsafe(`DROP DATABASE ${database}`);
      await admin.end();
    }
  });
  async function ledger() {
    return sql<{ version: string; checksum: string; applied_at: string }[]>`
      SELECT version,checksum,applied_at::text AS applied_at FROM login_workforce_migrations ORDER BY version`;
  }

  it("serializes concurrent initial runs, applies all seven checksums once and keeps replay timestamps", async () => {
    const results = await Promise.all([run(connection), run(connection)]);
    expect(results.map((result) => result.status)).toEqual([0, 0]);
    const initial = await ledger();
    expect(initial.map((row) => row.version)).toEqual(versions);
    expect(initial.map((row) => row.checksum)).toEqual(
      await Promise.all(versions.map(async (version) => (await source(version)).checksum)),
    );
    expect(await sql`SELECT request_hash FROM login_identity_logouts`).toHaveLength(0);
    expect((await run(connection)).status).toBe(0);
    expect(await ledger()).toEqual(initial);
  });

  it("expands populated 001–006 without rewriting prior rows or ledger entries", async () => {
    await sql.begin(async (tx) => {
      await tx`CREATE TABLE login_workforce_migrations(version text PRIMARY KEY,checksum char(64) NOT NULL,applied_at timestamptz NOT NULL DEFAULT clock_timestamp())`;
      for (const version of versions.slice(0, 6)) {
        const migration = await source(version);
        await tx.unsafe(migration.body);
        await tx`INSERT INTO login_workforce_migrations(version,checksum) VALUES(${version},${migration.checksum})`;
      }
      await tx`INSERT INTO login_workforce_epochs(issuer,provider_subject,epoch) VALUES('https://auth.fixture.invalid','fixture-subject',42)`;
    });
    const initial = await ledger();
    const previous = await sql`SELECT * FROM login_workforce_epochs`;
    expect((await run(connection)).status).toBe(0);
    expect((await ledger()).slice(0, 6)).toEqual(initial);
    expect(await sql`SELECT * FROM login_workforce_epochs`).toEqual(previous);
    expect(await sql`SELECT request_hash FROM login_identity_logouts`).toHaveLength(0);
  });

  it("rejects a changed applied006 checksum and leaves committed rows and ledger unchanged", async () => {
    expect((await run(connection)).status).toBe(0);
    await sql`INSERT INTO login_identity_logouts(request_hash,admission,provider_session_ids) VALUES(${"a".repeat(64)},'{"fixture":true}',ARRAY['fixture-session'])`;
    await sql`UPDATE login_workforce_migrations SET checksum=${"b".repeat(64)} WHERE version='006_identity_logouts'`;
    const initial = await ledger();
    const previous = await sql`SELECT * FROM login_identity_logouts`;
    const result = await run(connection);
    expect(result.status).toBe(1);
    expect(result.stderr).toContain("Applied workforce migration checksum changed");
    expect(await ledger()).toEqual(initial);
    expect(await sql`SELECT * FROM login_identity_logouts`).toEqual(previous);
  });
});
