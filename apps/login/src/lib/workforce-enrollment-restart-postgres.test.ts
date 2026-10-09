// @vitest-environment node
import { randomUUID } from "node:crypto";
import { readFileSync, readdirSync } from "node:fs";
import postgres, { type Sql } from "postgres";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { workforceAssertionHash } from "./workforce-assertion";
import type { EnrollmentProjection } from "./workforce-enrollment-identity-client";
import { WorkforceEnrollmentRestart } from "./workforce-enrollment-restart";
import { WorkforceEnrollmentStore } from "./workforce-enrollment-store";
import type { WorkforceProvider } from "./workforce-provider";
import { WorkforceStore, WorkforceStoreError } from "./workforce-store";
const url = process.env.PAYPM_WORKFORCE_TEST_DATABASE_URL;
(url ? describe : describe.skip)("durable expired enrollment replacement (isolated PostgreSQL)", () => {
  let admin: Sql,
    sql: Sql,
    schema: string,
    base: WorkforceStore,
    store: WorkforceEnrollmentStore,
    restart: WorkforceEnrollmentRestart,
    p: EnrollmentProjection;
  beforeEach(async () => {
    schema = "login_restart_" + randomUUID().replaceAll("-", "");
    admin = postgres(url!, { max: 1, onnotice: () => {} });
    await admin.unsafe(`CREATE SCHEMA ${schema}`);
    sql = postgres(url!, { max: 10, connection: { search_path: schema }, onnotice: () => {} });
    const dir = new URL("../../migrations/", import.meta.url);
    for (const name of readdirSync(dir)
      .filter((n) => /^\d{3}_.*\.sql$/.test(n))
      .sort())
      await sql.unsafe(readFileSync(new URL(name, dir), "utf8"));
    base = new WorkforceStore(sql, Buffer.alloc(32, 3));
    store = new WorkforceEnrollmentStore(base, Buffer.alloc(32, 3));
    restart = new WorkforceEnrollmentRestart(store);
    p = {
      enrollmentId: randomUUID(),
      personId: randomUUID(),
      policyId: randomUUID(),
      issuer: "https://auth.paypm.test",
      organizationId: "300",
      clientId: "staff-client",
      providerSubject: "700",
      email: randomUUID() + "@example.test",
      emailVerified: true,
      sourceRevision: "a".repeat(40),
      imageDigest: "b".repeat(64),
      configurationSha256: "c".repeat(64),
      expiresAt: new Date(Date.now() + 3600000).toISOString(),
      state: "qualified_enrollment",
    };
    await store.begin(p, "oidc_old", randomUUID());
  });
  afterEach(async () => {
    await sql?.end();
    if (admin) {
      await admin.unsafe(`DROP SCHEMA ${schema} CASCADE`);
      await admin.end();
    }
  });
  const provider = () =>
    ({
      inspectActionIntent: vi.fn(async () => ({ id: "800" })),
      retireEnrollmentChallenge: vi.fn(async () => true),
    }) as unknown as WorkforceProvider;
  async function oldChallenge(claim = false, bind = false) {
    let row = await store.reserveChallenge(p, randomUUID(), "oidc_old");
    if (claim) await base.claimSession(row.id);
    if (bind) {
      row = await base.session(row.id, "800", "synthetic-only");
      await base.issued(row.id);
      await store.attach(p.enrollmentId, row);
    }
    return row;
  }
  async function expire() {
    // Fixture setup only: no existing database/source or live record is altered.
    await sql.begin(async (tx) => {
      await tx.unsafe("ALTER TABLE login_reviewed_workforce_enrollments DISABLE TRIGGER immutable_reviewed_enrollment");
      await tx`UPDATE login_reviewed_workforce_enrollments SET created_at=created_at-interval '10 minutes',expires_at=expires_at-interval '10 minutes' WHERE enrollment_id=${p.enrollmentId}`;
      await tx.unsafe("ALTER TABLE login_reviewed_workforce_enrollments ENABLE TRIGGER immutable_reviewed_enrollment");
      await tx.unsafe("ALTER TABLE login_workforce_challenges DISABLE TRIGGER protected_workforce_challenge");
      await tx`UPDATE login_workforce_challenges SET created_at=created_at-interval '10 minutes',expires_at=expires_at-interval '10 minutes',issued_at=issued_at-interval '10 minutes'`;
      await tx.unsafe("ALTER TABLE login_workforce_challenges ENABLE TRIGGER protected_workforce_challenge");
    });
  }
  const successor = () => ({
    ...p,
    sourceRevision: "d".repeat(40),
    imageDigest: "e".repeat(64),
    configurationSha256: "f".repeat(64),
  });
  async function rowCounts() {
    const tables = (await sql<{ tablename: string }[]>`SELECT tablename FROM pg_tables WHERE schemaname=${schema}`)
      .map((r) => r.tablename)
      .sort();
    const counts: Record<string, number> = {};
    for (const table of tables) {
      const [row] = await sql.unsafe(`SELECT count(*)::int count FROM ${table}`);
      counts[table] = row.count;
    }
    return counts;
  }
  it("classifies missing custody without creating an epoch, enrollment or delivery", async () => {
    const before = await rowCounts();
    expect(await restart.inspectEntry({ ...p, enrollmentId: randomUUID() }, "oidc_new")).toBe("ready_to_start");
    expect(await rowCounts()).toEqual(before);
  });
  it("reads current original request without renewal and denies another request while current", async () => {
    const before = await rowCounts();
    expect(await restart.inspectEntry(p, "oidc_old")).toBe("ready_to_start");
    await expect(restart.inspectEntry(p, "oidc_new")).rejects.toMatchObject({ code: "enrollment_binding_changed" });
    await expect(restart.inspectEntry(successor(), "oidc_old")).rejects.toMatchObject({
      code: "enrollment_binding_changed",
    });
    expect(await rowCounts()).toEqual(before);
  });
  it("classifies expired original versus fresh request while preserving every journal", async () => {
    await oldChallenge(true, true);
    await expire();
    const before = await rowCounts();
    expect(await restart.inspectEntry(successor(), "oidc_old")).toBe("oidc_request_required");
    expect(await restart.inspectEntry(successor(), "oidc_new")).toBe("ready_to_start");
    expect(await rowCounts()).toEqual(before);
    await expect(restart.prepare(successor(), "oidc_old", randomUUID())).rejects.toMatchObject({
      code: "fresh_enrollment_request_required",
    });
  });
  it.each(["personId", "policyId", "issuer", "organizationId", "clientId", "providerSubject", "email"] as const)(
    "denies expired-request readback when canonical %s changes",
    async (key) => {
      await expire();
      await expect(restart.inspectEntry({ ...successor(), [key]: randomUUID() }, "oidc_new")).rejects.toMatchObject({
        code: "enrollment_binding_changed",
      });
    },
  );
  it.each(["extended", "expired"])("denies an %s invitation during readback", async (kind) => {
    await expire();
    const expiresAt = new Date(Date.parse(p.expiresAt) + (kind === "extended" ? 1000 : -7200000)).toISOString();
    await expect(restart.inspectEntry({ ...successor(), expiresAt }, "oidc_new")).rejects.toMatchObject({
      code: "enrollment_invitation_changed",
    });
  });
  it("denies readback after logout-all advances the provider epoch", async () => {
    await expire();
    await sql`UPDATE login_workforce_epochs SET epoch=epoch+1 WHERE issuer=${p.issuer} AND provider_subject=${p.providerSubject}`;
    await expect(restart.inspectEntry(successor(), "oidc_new")).rejects.toMatchObject({ code: "enrollment_not_current" });
  });
  it.each(["completed", "cancelled"] as const)("denies readback of a %s enrollment", async (reason) => {
    await store.retire(p.enrollmentId, reason);
    await expire();
    await expect(restart.inspectEntry(successor(), "oidc_new")).rejects.toMatchObject({ code: "enrollment_not_current" });
  });
  it("detects altered root custody even when the requested profile matches", async () => {
    await expire();
    await sql.begin(async (tx) => {
      await tx.unsafe("ALTER TABLE login_reviewed_workforce_enrollments DISABLE TRIGGER immutable_reviewed_enrollment");
      await tx`UPDATE login_reviewed_workforce_enrollments SET binding_hash=${"0".repeat(64)} WHERE enrollment_id=${p.enrollmentId}`;
      await tx.unsafe("ALTER TABLE login_reviewed_workforce_enrollments ENABLE TRIGGER immutable_reviewed_enrollment");
    });
    await expect(restart.inspectEntry(successor(), "oidc_new")).rejects.toMatchObject({
      code: "enrollment_binding_changed",
    });
  });
  it.each(["exact", "changed-person", "changed-session", "changed-hash"])(
    "legacy metadata recovery requires %s immutable ceremony and parent bindings",
    async (kind) => {
      const row = await oldChallenge(true, true);
      await expire();
      // Keep this isolated time-shift fixture's ceremony consistent with its
      // shifted original/challenge. This never touches a live database.
      const [challenge] = await sql`SELECT created_at,expires_at FROM login_workforce_challenges WHERE id=${row.id}`,
        [original] =
          await sql`SELECT expires_at FROM login_reviewed_workforce_enrollments WHERE enrollment_id=${p.enrollmentId}`,
        [sealed] =
          await sql`SELECT ceremony FROM login_reviewed_workforce_enrollment_challenges WHERE challenge_id=${row.id}`;
      const ceremony = {
        ...sealed.ceremony,
        issuedAt: challenge.created_at.toISOString(),
        expiresAt: new Date(Math.min(challenge.expires_at.getTime(), original.expires_at.getTime())).toISOString(),
      };
      if (kind === "changed-person") ceremony.personId = randomUUID();
      if (kind === "changed-session") ceremony.sessionId = "900";
      const hash = kind === "changed-hash" ? "a".repeat(64) : workforceAssertionHash(ceremony);
      await sql.begin(async (tx) => {
        await tx.unsafe(
          "ALTER TABLE login_reviewed_workforce_enrollment_challenges DISABLE TRIGGER immutable_reviewed_enrollment_challenge",
        );
        await tx`UPDATE login_reviewed_workforce_enrollment_challenges SET ceremony=${tx.json(ceremony)},ceremony_hash=${hash} WHERE challenge_id=${row.id}`;
        await tx.unsafe(
          "ALTER TABLE login_reviewed_workforce_enrollment_challenges ENABLE TRIGGER immutable_reviewed_enrollment_challenge",
        );
      });
      const intent = await restart.prepare(successor(), "oidc_new", randomUUID()),
        native = provider();
      vi.mocked(native.retireEnrollmentChallenge).mockRejectedValueOnce(
        new WorkforceStoreError("retirement_provider_binding_changed"),
      );
      if (kind === "exact") {
        await restart.retireSessions(intent, native);
        expect(native.retireEnrollmentChallenge).toHaveBeenLastCalledWith(
          "800",
          expect.objectContaining({ id: row.id }),
          hash,
        );
        await restart.activate(intent, successor(), "oidc_new");
      } else {
        await expect(restart.retireSessions(intent, native)).rejects.toThrow("retirement_unconfirmed");
        expect(native.retireEnrollmentChallenge).toHaveBeenCalledOnce();
        expect(await sql`SELECT * FROM login_reviewed_workforce_restart_session_evidence`).toHaveLength(0);
        expect(await sql`SELECT * FROM login_reviewed_workforce_enrollment_attempts`).toHaveLength(0);
      }
    },
  );
  it("five concurrent retries preserve original records and append one bounded successor", async () => {
    const row = await oldChallenge(true, true);
    await expire();
    const original = await sql`SELECT row_to_json(o) row FROM login_reviewed_workforce_enrollments o`,
      ceremony = await sql`SELECT row_to_json(o) row FROM login_reviewed_workforce_enrollment_challenges o`;
    const next = successor(),
      key = randomUUID(),
      intents = await Promise.all(Array.from({ length: 5 }, () => restart.prepare(next, "oidc_new", key)));
    expect(new Set(intents.map((i) => i.operation_key)).size).toBe(1);
    const native = provider();
    await restart.retireSessions(intents[0], native);
    const rows = await Promise.all(intents.map((i) => restart.activate(i, next, "oidc_new")));
    expect(new Set(rows.map((r) => r.attempt_id))).toEqual(new Set([key]));
    expect(rows[0].expires_at.getTime() - rows[0].created_at.getTime()).toBeLessThanOrEqual(300000);
    expect(await sql`SELECT row_to_json(o) row FROM login_reviewed_workforce_enrollments o`).toEqual(original);
    expect(await sql`SELECT row_to_json(o) row FROM login_reviewed_workforce_enrollment_challenges o`).toEqual(ceremony);
    expect((await store.original(p.enrollmentId)).binding.personId).toBe(p.personId);
    expect((await base.challenge(row.id)).state).toBe("retired");
    expect(await sql`SELECT * FROM login_workforce_admissions`).toHaveLength(0);
    await expect(store.attach(p.enrollmentId, row)).rejects.toThrow("challenge_changed");
    await expect(sql`UPDATE login_reviewed_workforce_enrollment_attempts SET request_id='forged'`).rejects.toThrow(
      "retained",
    );
    await expect(sql`DELETE FROM login_reviewed_workforce_restart_session_evidence`).rejects.toThrow("retained");
  });
  it("unknown create absence holds replacement; discovered orphan is retired before activation", async () => {
    const row = await oldChallenge(true, false);
    await expire();
    const next = successor(),
      intent = await restart.prepare(next, "oidc_new", randomUUID()),
      native = provider();
    vi.mocked(native.inspectActionIntent).mockResolvedValueOnce(undefined);
    await expect(restart.retireSessions(intent, native)).rejects.toThrow("create_unconfirmed");
    await expect(restart.activate(intent, next, "oidc_new")).rejects.toThrow("retirement_unconfirmed");
    expect(await sql`SELECT * FROM login_reviewed_workforce_enrollment_attempts`).toHaveLength(0);
    expect(await sql`SELECT * FROM login_reviewed_workforce_restart_session_evidence`).toHaveLength(0);
    await restart.retireSessions(intent, native);
    expect(native.inspectActionIntent).toHaveBeenCalledWith(row.id, "700", "paypm_workforce_challenge");
    expect(native.retireEnrollmentChallenge).toHaveBeenCalledWith("800", expect.objectContaining({ id: row.id }));
    await restart.activate(intent, next, "oidc_new");
    await expect(base.session(row.id, "800", "late-token")).rejects.toThrow();
    await base.orphanedSession(row.id, "800");
    expect(await base.pendingRevocations()).toContainEqual({ provider_session_id: "800" });
  });
  it("lost delete response keeps its observed Session ID; retries never recreate or assume absent creation", async () => {
    await oldChallenge(true, false);
    await expire();
    const intent = await restart.prepare(p, "oidc_new", randomUUID()),
      native = provider();
    vi.mocked(native.retireEnrollmentChallenge).mockRejectedValueOnce(new Error("delete response lost"));
    await expect(restart.retireSessions(intent, native)).rejects.toThrow("lost");
    expect(await sql`SELECT * FROM login_reviewed_workforce_restart_session_observations`).toHaveLength(1);
    expect(await sql`SELECT * FROM login_reviewed_workforce_restart_session_evidence`).toHaveLength(0);
    await restart.retireSessions(intent, native);
    expect(native.inspectActionIntent).toHaveBeenCalledTimes(1);
    await restart.activate(intent, p, "oidc_new");
  });
  it.each(["personId", "policyId", "providerSubject", "clientId", "organizationId", "email"] as const)(
    "denies changed %s",
    async (key) => {
      await expire();
      const next = { ...p, [key]: key.endsWith("Id") ? randomUUID() : key === "email" ? "other@example.test" : "701" };
      await expect(restart.prepare(next, "oidc_new", randomUUID())).rejects.toThrow("binding_changed");
      expect(await sql`SELECT * FROM login_reviewed_workforce_restart_intents`).toHaveLength(0);
    },
  );
  it("denies same request, widened invitation, live attempt, cancelled/completed and logout epoch", async () => {
    await expect(restart.prepare(p, "oidc_new", randomUUID())).rejects.toThrow("still_current");
    await expire();
    await expect(restart.prepare(p, "oidc_old", randomUUID())).rejects.toThrow("fresh_enrollment_request");
    await expect(
      restart.prepare({ ...p, expiresAt: new Date(Date.parse(p.expiresAt) + 1000).toISOString() }, "oidc_new", randomUUID()),
    ).rejects.toThrow("invitation_changed");
    await base.revokeUser(p.issuer, p.providerSubject);
    await expect(restart.prepare(p, "oidc_new", randomUUID())).rejects.toThrow("not_current");
  });
  it.each(["cancelled", "completed"])("denies %s root", async (reason) => {
    await store.retire(p.enrollmentId, reason as "cancelled" | "completed");
    await expire();
    await expect(restart.prepare(p, "oidc_new", randomUUID())).rejects.toThrow("not_current");
  });
  it("withdrawal/logout after exact provider retirement prevents activation", async () => {
    await oldChallenge(true, true);
    await expire();
    const intent = await restart.prepare(p, "oidc_new", randomUUID());
    await restart.retireSessions(intent, provider());
    await base.revokeUser(p.issuer, p.providerSubject);
    await expect(restart.activate(intent, p, "oidc_new")).rejects.toThrow("not_current");
  });
  it("five verification attempts survive restart without resetting; sends share contact limits", async () => {
    const row = await oldChallenge(true, true);
    for (let i = 0; i < 5; i++) await store.attempt(p.enrollmentId, row.id, randomUUID(), "12345678");
    await expire();
    const intent = await restart.prepare(p, "oidc_new", randomUUID());
    await restart.retireSessions(intent, provider());
    await restart.activate(intent, p, "oidc_new");
    let next = await store.reserveChallenge(p, randomUUID(), "oidc_new");
    next = await base.session(next.id, "801", "synthetic-only");
    await base.issued(next.id);
    await expect(store.attempt(p.enrollmentId, next.id, randomUUID(), "12345678")).rejects.toThrow("attempts_exhausted");
    await expect(store.reserveChallenge(p, randomUUID(), "oidc_new")).rejects.toThrow("rate_limited");
  });
  it("accepted profile delivery requires explicit replacement; unknown claims remain held", async () => {
    p.emailVerified = false;
    const delivery = await store.reserveProfileDelivery(p, randomUUID(), "native-template");
    await store.claimProfileDelivery(p.enrollmentId, delivery.id);
    await store.recordProfileDelivery(p.enrollmentId, delivery.id, {
      sequence: "42",
      changeAt: new Date().toISOString(),
      resourceOwner: "300",
    });
    await expire();
    const intent = await restart.prepare(p, "oidc_new", randomUUID());
    await restart.retireSessions(intent, provider());
    await restart.activate(intent, p, "oidc_new");
    expect(await store.profileReplacementForAttempt(p.enrollmentId)).toBe(delivery.id);
    await expect(store.currentProfileDelivery(p.enrollmentId)).rejects.toThrow("changed");
    // Preserve the same shared60-second quota, despite a new browser attempt.
    await expect(store.reserveProfileDelivery(p, randomUUID(), "new-template", delivery.id)).rejects.toThrow("rate_limited");
    expect(await sql`SELECT * FROM login_reviewed_workforce_profile_deliveries`).toHaveLength(1);
  });
  it("unknown profile-send claims cannot be reset or silently sent again by restart", async () => {
    p.emailVerified = false;
    const delivery = await store.reserveProfileDelivery(p, randomUUID(), "native-template");
    await store.claimProfileDelivery(p.enrollmentId, delivery.id);
    await store.recordProfileDelivery(p.enrollmentId, delivery.id);
    const snapshot = await sql`SELECT row_to_json(o) row FROM login_reviewed_workforce_profile_delivery_outcomes o`;
    await expire();
    const intent = await restart.prepare(p, "oidc_new", randomUUID());
    await restart.retireSessions(intent, provider());
    await restart.activate(intent, p, "oidc_new");
    await expect(store.profileReplacementForAttempt(p.enrollmentId)).rejects.toThrow("delivery_unknown");
    await expect(store.reserveProfileDelivery(p, randomUUID(), "new-template", delivery.id)).rejects.toThrow(
      "delivery_unknown",
    );
    expect(await sql`SELECT row_to_json(o) row FROM login_reviewed_workforce_profile_delivery_outcomes o`).toEqual(snapshot);
    expect(await sql`SELECT * FROM login_reviewed_workforce_profile_deliveries`).toHaveLength(1);
  });
  it("profile verification budget cannot reset under a fresh bounded attempt", async () => {
    for (let i = 0; i < 5; i++) await store.profileAttempt(p.enrollmentId, randomUUID(), "A7K9Q2");
    await expire();
    const intent = await restart.prepare(p, "oidc_new", randomUUID());
    await restart.retireSessions(intent, provider());
    await restart.activate(intent, p, "oidc_new");
    await expect(store.profileAttempt(p.enrollmentId, randomUUID(), "A7K9Q2")).rejects.toThrow("attempts_exhausted");
    expect(await sql`SELECT * FROM login_reviewed_workforce_profile_attempts`).toHaveLength(5);
  });
});
