// @vitest-environment node
import { randomUUID } from "node:crypto";
import { readFileSync, readdirSync } from "node:fs";
import postgres, { type Sql } from "postgres";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { WorkforceEnrollmentStore } from "./workforce-enrollment-store";
import { WorkforceStore } from "./workforce-store";
const url = process.env.PAYPM_WORKFORCE_TEST_DATABASE_URL;
(url ? describe : describe.skip)("reviewed workforce original custody (isolated PostgreSQL)", () => {
  let admin: Sql, sql: Sql, base: WorkforceStore, store: WorkforceEnrollmentStore, schema: string;
  beforeEach(async () => {
    schema = "login_reviewed_" + randomUUID().replaceAll("-", "");
    admin = postgres(url!, { max: 1 });
    await admin.unsafe(`CREATE SCHEMA ${schema}`);
    sql = postgres(url!, { max: 10, connection: { search_path: schema } });
    const dir = new URL("../../migrations/", import.meta.url);
    for (const name of readdirSync(dir)
      .filter((s) => /^\d{3}_.*\.sql$/.test(s))
      .sort())
      await sql.unsafe(readFileSync(new URL(name, dir), "utf8"));
    base = new WorkforceStore(sql, Buffer.alloc(32, 3));
    store = new WorkforceEnrollmentStore(base, Buffer.alloc(32, 3));
  });
  afterEach(async () => {
    await sql?.end();
    if (admin) {
      await admin.unsafe(`DROP SCHEMA ${schema} CASCADE`);
      await admin.end();
    }
  });
  const projection = () => ({
    enrollmentId: randomUUID(),
    personId: randomUUID(),
    policyId: randomUUID(),
    issuer: "https://auth.paypm.test",
    organizationId: "300",
    clientId: "staff-client",
    providerSubject: "700",
    email: randomUUID() + "@example.test",
    emailVerified: false,
    sourceRevision: "a".repeat(40),
    imageDigest: "b".repeat(64),
    configurationSha256: "c".repeat(64),
    expiresAt: new Date(Date.now() + 180000).toISOString(),
    state: "qualified_enrollment" as const,
  });
  async function ready() {
    const p = projection();
    await store.begin(p, "oidc_owned", randomUUID());
    let row = await base.reserve({
      operationKey: randomUUID(),
      issuer: p.issuer,
      userId: p.providerSubject,
      clientId: p.clientId,
      requestId: "oidc_owned",
      contact: p.email,
      purpose: "reviewed_enrollment",
    });
    row = await base.session(row.id, "800", "synthetic-token");
    const ceremony = await store.attach(p.enrollmentId, row);
    await base.issued(row.id);
    return { p, row, ceremony };
  }
  it("concurrent start holds one exact appointment, no email plaintext or provider tokens", async () => {
    const p = projection(),
      key = randomUUID(),
      results = await Promise.all(Array.from({ length: 5 }, () => store.begin(p, "oidc_owned", key)));
    expect(new Set(results.map((r) => r.enrollment_id)).size).toBe(1);
    expect(JSON.stringify(results)).not.toContain(p.email);
    await expect(store.begin({ ...p, personId: randomUUID() }, "oidc_owned", key)).rejects.toMatchObject({
      code: "enrollment_binding_changed",
    });
    await expect(
      sql`UPDATE login_reviewed_workforce_enrollments SET provider_subject='701' WHERE enrollment_id=${p.enrollmentId}`,
    ).rejects.toThrow("retained");
  });
  it("five durable profile attempts maximum across concurrent calls; uncertain same attempt cannot consume again", async () => {
    const p = projection();
    await store.begin(p, "oidc_owned", randomUUID());
    const key = randomUUID();
    expect(await store.profileAttempt(p.enrollmentId, key, "A7K9Q2")).toBe(true);
    expect(await store.profileAttempt(p.enrollmentId, key, "A7K9Q2")).toBe(false);
    await expect(store.profileAttempt(p.enrollmentId, key, "B7K9Q2")).rejects.toMatchObject({
      code: "idempotency_conflict",
    });
    const results = await Promise.allSettled(
      Array.from({ length: 8 }, () => store.profileAttempt(p.enrollmentId, randomUUID(), "A7K9Q2")),
    );
    expect(results.filter((r) => r.status === "fulfilled")).toHaveLength(4);
    expect(JSON.stringify(await sql`SELECT * FROM login_reviewed_workforce_profile_attempts`)).not.toContain("A7K9Q2");
  });
  it("fresh accepted OTP creates ceremony but zero ordinary admissions; DB rejects direct bypass", async () => {
    const { p, row, ceremony } = await ready();
    const attempt = await base.attempt(row.id, randomUUID(), "12345678");
    await expect(base.verified(attempt.id, new Date(), new Date(Date.now() + 100000))).rejects.toMatchObject({
      code: "verification_purpose_mismatch",
    });
    await base.verifiedEnrollment(attempt.id, new Date(), row.expires_at);
    expect(await store.ceremony(p.enrollmentId)).toEqual(ceremony);
    expect(await sql`SELECT * FROM login_workforce_admissions`).toHaveLength(0);
    await expect(
      sql`INSERT INTO login_workforce_admissions(provider_session_id,issuer,provider_subject,client_id,request_id,challenge_id,epoch,verified_at,absolute_expires_at) VALUES('800',${p.issuer},${p.providerSubject},${p.clientId},'oidc_owned',${row.id},0,clock_timestamp(),clock_timestamp()+interval '2 minutes')`,
    ).rejects.toThrow("cannot grant");
  });
  it("cancellation revokes original challenge and blocks late accepted response; repeated retirement preserves decision", async () => {
    const { p, row } = await ready();
    const attempt = await base.attempt(row.id, randomUUID(), "12345678");
    await store.retire(p.enrollmentId, "cancelled");
    await store.retire(p.enrollmentId, "cancelled");
    await expect(base.verifiedEnrollment(attempt.id, new Date(), row.expires_at)).rejects.toThrow();
    await expect(store.ceremony(p.enrollmentId)).rejects.toMatchObject({ code: "enrollment_not_current" });
    expect(await base.pendingRevocations()).toEqual([{ provider_session_id: "800" }]);
    expect(await sql`SELECT * FROM login_workforce_admissions`).toHaveLength(0);
  });
  it("logout epoch invalidates enrollment and completion reader immediately", async () => {
    const { p, row } = await ready();
    const attempt = await base.attempt(row.id, randomUUID(), "12345678");
    await base.verifiedEnrollment(attempt.id, new Date(), row.expires_at);
    await base.revokeUser(p.issuer, p.providerSubject);
    await expect(store.original(p.enrollmentId)).rejects.toMatchObject({ code: "enrollment_not_current" });
    await expect(store.ceremony(p.enrollmentId)).rejects.toThrow();
  });
  it("completed association may read exact historical original but cannot act as active ceremony", async () => {
    const { p, row } = await ready();
    await store.retire(p.enrollmentId, "completed");
    expect((await store.original(p.enrollmentId, true)).enrollment_id).toBe(p.enrollmentId);
    await expect(store.ceremony(p.enrollmentId)).rejects.toThrow();
    await expect(store.retire(p.enrollmentId, "cancelled")).rejects.toMatchObject({ code: "enrollment_retirement_changed" });
    expect(await sql`SELECT * FROM login_workforce_admissions`).toHaveLength(0);
    expect(row.purpose).toBe("reviewed_enrollment");
  });
});
