import { createHash } from "node:crypto";
import { readFile } from "node:fs/promises";
import postgres from "postgres";
const url = process.env.PAYPM_WORKFORCE_MIGRATION_DATABASE_URL;
if (!url) throw new Error("Workforce migration credentials unavailable");
const sql = postgres(url, {
  max: 1,
  connect_timeout: 5,
  ssl: process.env.NODE_ENV === "production" ? { rejectUnauthorized: true } : false,
});
try {
  await sql.begin(async (tx) => {
    await tx`SELECT pg_advisory_xact_lock(hashtextextended('paypm-login-workforce-migrations-v1',0))`;
    await tx`CREATE TABLE IF NOT EXISTS login_workforce_migrations(version text PRIMARY KEY,checksum char(64) NOT NULL,applied_at timestamptz NOT NULL DEFAULT clock_timestamp())`;
    for (const version of [
      "001_workforce_auth",
      "002_legacy_recovery_retirements",
      "003_workforce_action_intents",
      "004_operations_action_requests",
      "005_operations_logouts",
      "006_identity_logouts",
      "007_identity_action_requests",
      "008_reviewed_workforce_enrollment",
      "009_reviewed_workforce_profile_delivery",
      "010_reviewed_workforce_restart",
      "011_identity_membership_actions",
    ]) {
      const source = await readFile(new URL(`../migrations/${version}.sql`, import.meta.url), "utf8"),
        checksum = createHash("sha256").update(source).digest("hex");
      const [old] = await tx`SELECT checksum FROM login_workforce_migrations WHERE version=${version}`;
      if (old) {
        if (old.checksum !== checksum) throw new Error("Applied workforce migration checksum changed");
        continue;
      }
      await tx.unsafe(source);
      await tx`INSERT INTO login_workforce_migrations(version,checksum) VALUES(${version},${checksum})`;
    }
  });
  console.log("Workforce authentication migration verified");
} finally {
  await sql.end();
}
