// @vitest-environment node
import { randomUUID } from "node:crypto";
import { readFileSync } from "node:fs";
import postgres, { type Sql } from "postgres";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { WorkforceStore, type WorkforceChallenge } from "./workforce-store";
const url = process.env.PAYPM_WORKFORCE_TEST_DATABASE_URL;
const suite = url ? describe : describe.skip;
suite("Login-owned durable workforce authentication (real PostgreSQL)", () => {
  let admin: Sql, sql: Sql, store: WorkforceStore, schema: string;
  beforeEach(async () => {
    schema = "login_workforce_" + randomUUID().replaceAll("-", "");
    admin = postgres(url!, { max: 1 });
    await admin.unsafe(`CREATE SCHEMA ${schema}`);
    sql = postgres(url!, { max: 10, connection: { search_path: schema } });
    await sql.unsafe(readFileSync(new URL("../../migrations/001_workforce_auth.sql", import.meta.url), "utf8"));
    await sql.unsafe(readFileSync(new URL("../../migrations/002_legacy_recovery_retirements.sql", import.meta.url), "utf8"));
    await sql.unsafe(readFileSync(new URL("../../migrations/003_workforce_action_intents.sql", import.meta.url), "utf8"));
    await sql.unsafe(readFileSync(new URL("../../migrations/007_identity_action_requests.sql", import.meta.url), "utf8"));
    await sql.unsafe(
      readFileSync(new URL("../../migrations/008_reviewed_workforce_enrollment.sql", import.meta.url), "utf8"),
    );
    await sql.unsafe(
      readFileSync(new URL("../../migrations/009_reviewed_workforce_profile_delivery.sql", import.meta.url), "utf8"),
    );
    store = new WorkforceStore(sql, Buffer.alloc(32, 19));
  });
  afterEach(async () => {
    await sql?.end();
    if (admin) {
      await admin.unsafe(`DROP SCHEMA ${schema} CASCADE`);
      await admin.end();
    }
  });
  const input = (contact = "staff@example.test") => ({
    operationKey: randomUUID(),
    issuer: "https://auth.paypm.test",
    userId: "12345",
    clientId: "identity-staff",
    requestId: "oidc_owned_request",
    contact,
  });
  async function ready(contact = "staff@example.test") {
    const row = await store.reserve(input(contact));
    expect(await store.claimSession(row.id)).toBe(true);
    await store.session(row.id, randomUUID(), "synthetic-provider-token");
    expect(await store.claimDelivery(row.id)).toBe(true);
    await store.issued(row.id);
    return store.challenge(row.id);
  }
  async function ageFixture(row: WorkforceChallenge, seconds: number) {
    await sql.begin(async (tx) => {
      await tx.unsafe("ALTER TABLE login_workforce_challenges DISABLE TRIGGER protected_workforce_challenge");
      await tx`WITH stamp AS MATERIALIZED (SELECT clock_timestamp() AS value) UPDATE login_workforce_challenges SET created_at=stamp.value-${seconds}*interval '1 second',expires_at=stamp.value+(300-${seconds})*interval '1 second' FROM stamp WHERE id=${row.id}`;
      await tx.unsafe("ALTER TABLE login_workforce_challenges ENABLE TRIGGER protected_workforce_challenge");
    });
    return store.challenge(row.id);
  }
  it("concurrent issuance reserves one immutable operation, hides contact and encrypts provider tokens", async () => {
    const request = input(),
      rows = await Promise.all(Array.from({ length: 5 }, () => store.reserve(request)));
    expect(new Set(rows.map((r) => r.id)).size).toBe(1);
    const claims = await Promise.all(rows.map((r) => store.claimSession(r.id)));
    expect(claims.filter(Boolean)).toHaveLength(1);
    const row = await store.session(rows[0].id, "actual-provider-id", "synthetic-provider-token");
    expect(store.token(row)).toBe("synthetic-provider-token");
    expect(JSON.stringify(row)).not.toContain(request.contact);
    expect(row.provider_token_sealed).not.toContain("synthetic-provider-token");
    await expect(store.reserve({ ...request, clientId: "operations" })).rejects.toMatchObject({
      code: "idempotency_conflict",
    });
    await expect(
      sql`UPDATE login_workforce_challenges SET provider_subject='another-user' WHERE id=${row.id}`,
    ).rejects.toThrow("immutable");
  });
  it("shares send quota across clients and retries, with durable prior-attempt retirement", async () => {
    const row = await ready();
    await expect(store.reserve({ ...input(), clientId: "operations" })).rejects.toMatchObject({
      code: "workforce_delivery_rate_limited",
    });
    await ageFixture(row, 61);
    const next = await store.reserve(input(), row.id);
    expect((await store.challenge(row.id)).state).toBe("retired");
    expect(await store.pendingRevocations()).toEqual([{ provider_session_id: row.provider_session_id }]);
    await expect(store.session(row.id, row.provider_session_id!, "late-token")).rejects.toMatchObject({
      code: "challenge_not_active",
    });
    await store.claimSession(next.id);
    await store.session(next.id, "provider-next", "token");
    await store.claimDelivery(next.id);
    await store.issued(next.id);
    await ageFixture(await store.challenge(next.id), 61);
    const third = await store.reserve(input(), next.id);
    await ageFixture(third, 61);
    await expect(store.reserve({ ...input(), clientId: "other-client" })).rejects.toMatchObject({
      code: "workforce_delivery_rate_limited",
    });
  });
  it("reserves exactly five verification attempts concurrently and prevents changed-code retry", async () => {
    const row = await ready(),
      key = randomUUID();
    const a = await store.attempt(row.id, key, "123456");
    expect(a.first).toBe(true);
    expect((await store.attempt(row.id, key, "123456")).first).toBe(false);
    await expect(store.attempt(row.id, key, "999999")).rejects.toMatchObject({ code: "idempotency_conflict" });
    const races = await Promise.allSettled(Array.from({ length: 10 }, () => store.attempt(row.id, randomUUID(), "123456")));
    expect(races.filter((r) => r.status === "fulfilled")).toHaveLength(4);
    expect(JSON.stringify(await sql`SELECT * FROM login_workforce_attempts`)).not.toContain("123456");
    await store.failed(a.id);
    await expect(store.verified(a.id, new Date(), new Date(Date.now() + 100000))).rejects.toMatchObject({
      code: "provider_verification_mismatch",
    });
  });
  it("reads the exact old session for an identical resend retry and denies a new send on a retired challenge", async () => {
    const previous = await ready();
    await ageFixture(previous, 61);
    const command = input();
    const next = await store.reserve(command, previous.id);
    await store.session(next.id, "resend-session", "token");
    await store.issued(next.id);
    const found = await store.challengeBySession({
      issuer: previous.issuer,
      userId: previous.provider_subject,
      clientId: previous.client_id,
      requestId: previous.request_id,
      sessionId: previous.provider_session_id!,
    });
    expect(found.id).toBe(previous.id);
    expect((await store.reserve(command, found.id)).id).toBe(next.id);
    await ageFixture(await store.challenge(next.id), 61);
    await expect(store.reserve(input(), found.id)).rejects.toMatchObject({ code: "challenge_not_active" });
    await expect(
      store.challengeBySession({
        issuer: previous.issuer,
        userId: "other",
        clientId: previous.client_id,
        requestId: previous.request_id,
        sessionId: previous.provider_session_id!,
      }),
    ).rejects.toMatchObject({ code: "challenge_not_found" });
  });
  it("cancellation denies late verification and queues a provider session created after cancellation", async () => {
    const row = await ready(),
      attempt = await store.attempt(row.id, randomUUID(), "123456");
    await store.cancelChallenge(row.id);
    await expect(store.verified(attempt.id, new Date(), new Date(Date.now() + 100000))).rejects.toMatchObject({
      code: "challenge_not_active",
    });
    expect(await store.admission(row.provider_session_id!, row.provider_subject, row.client_id, row.request_id)).toBe(false);
    const pending = await store.reserve(input("other@example.test"));
    await store.cancelChallenge(pending.id);
    await expect(store.session(pending.id, "late-provider", "token")).rejects.toMatchObject({
      code: "challenge_not_active",
    });
    await store.orphanedSession(pending.id, "late-provider");
    expect(await store.pendingRevocations()).toEqual(
      expect.arrayContaining([{ provider_session_id: row.provider_session_id }, { provider_session_id: "late-provider" }]),
    );
  });
  it("creates only exact limited admission with accepted fresh factor and enforces session binding", async () => {
    const row = await ready(),
      attempt = await store.attempt(row.id, randomUUID(), "123456");
    await expect(
      store.verified(attempt.id, new Date(Date.now() - 600000), new Date(Date.now() + 100000)),
    ).rejects.toMatchObject({ code: "provider_verification_mismatch" });
    await store.verified(attempt.id, new Date(), new Date(row.created_at.getTime() + 8 * 3600000));
    expect(await store.admission(row.provider_session_id!, row.provider_subject, row.client_id, row.request_id)).toBe(true);
    expect(await store.admission(row.provider_session_id!, "different-user", row.client_id, row.request_id)).toBe(false);
    expect(await store.admission(row.provider_session_id!, row.provider_subject, "other-client", row.request_id)).toBe(
      false,
    );
    expect(await store.admission(row.provider_session_id!, row.provider_subject, row.client_id, "oidc_other")).toBe(false);
    await expect(sql`UPDATE login_workforce_challenges SET state='issued' WHERE id=${row.id}`).rejects.toThrow("immutable");
    await expect(
      sql`UPDATE login_workforce_admissions SET authentication_class='workforce_privileged' WHERE provider_session_id=${row.provider_session_id}`,
    ).rejects.toThrow();
  });
  it("denies 30-minute idle and eight-hour expiry without sliding absolute lifetime", async () => {
    const row = await ready(),
      attempt = await store.attempt(row.id, randomUUID(), "123456");
    await store.verified(attempt.id, new Date(), new Date(Date.now() + 100000));
    await sql`UPDATE login_workforce_admissions SET last_seen_at=clock_timestamp()-interval '31 minutes' WHERE provider_session_id=${row.provider_session_id}`;
    expect(await store.admission(row.provider_session_id!, row.provider_subject, row.client_id, row.request_id)).toBe(false);
    await expect(
      sql`UPDATE login_workforce_admissions SET absolute_expires_at=clock_timestamp()+interval '8 hours' WHERE provider_session_id=${row.provider_session_id}`,
    ).rejects.toThrow("immutable");
    const other = await ready("other@example.test"),
      otherAttempt = await store.attempt(other.id, randomUUID(), "234567");
    await store.verified(otherAttempt.id, new Date(), new Date(Date.now() + 25));
    await new Promise((resolve) => setTimeout(resolve, 50));
    expect(
      await store.admission(other.provider_session_id!, other.provider_subject, other.client_id, other.request_id),
    ).toBe(false);
  });
  it("logout-all epochs block late verification and old operation restoration, preserving revocation evidence", async () => {
    const row = await ready(),
      attempt = await store.attempt(row.id, randomUUID(), "123456");
    await store.revokeUser(row.issuer, row.provider_subject);
    await expect(store.verified(attempt.id, new Date(), new Date(Date.now() + 100000))).rejects.toMatchObject({
      code: "challenge_not_active",
    });
    await expect(store.session(row.id, row.provider_session_id!, "late-response")).rejects.toMatchObject({
      code: "challenge_not_active",
    });
    expect(await store.admission(row.provider_session_id!, row.provider_subject, row.client_id, row.request_id)).toBe(false);
    expect(await store.pendingRevocations()).toHaveLength(1);
    await store.revocationCompleted(row.provider_session_id!);
    expect(await store.pendingRevocations()).toHaveLength(0);
    await expect(sql`DELETE FROM login_workforce_challenges WHERE id=${row.id}`).rejects.toThrow("retained");
  });
  it("persists one immutable passkey attempt before provider verification and never retries a failed assertion", async () => {
    const requestId = randomUUID(),
      hash = "e".repeat(64);
    const races = await Promise.all(
      Array.from({ length: 5 }, () => store.passkeyAttempt(requestId, "actual-step-session", hash)),
    );
    expect(races.filter((r) => r.first)).toHaveLength(1);
    await expect(store.passkeyAttempt(requestId, "other-session", hash)).rejects.toMatchObject({
      code: "passkey_attempt_conflict",
    });
    await expect(store.passkeyAttempt(requestId, "actual-step-session", "f".repeat(64))).rejects.toMatchObject({
      code: "passkey_attempt_conflict",
    });
    await store.passkeyAttemptFailed(requestId);
    await expect(store.passkeyAttempt(requestId, "actual-step-session", hash)).rejects.toMatchObject({
      code: "passkey_attempt_conflict",
    });
    await expect(sql`DELETE FROM login_workforce_passkey_attempts WHERE request_id=${requestId}`).rejects.toThrow(
      "retained",
    );
  });
  it("reserves one immutable initial passkey intent, encrypts provider material and denies late logout restoration", async () => {
    const base = await ready(),
      attempt = await store.attempt(base.id, randomUUID(), "123456");
    await store.verified(attempt.id, new Date(), new Date(Date.now() + 100000));
    const input = {
      operationKey: randomUUID(),
      issuer: base.issuer,
      providerSubject: base.provider_subject,
      baseSessionId: base.provider_session_id!,
      clientId: base.client_id,
      requestId: base.request_id,
      contextId: "300",
      appId: "identity-admin",
      deploymentId: "heritagepay",
      environment: "production" as const,
      action: "identity.recovery.review",
      payloadHash: "a".repeat(64),
    };
    const rows = await Promise.all(Array.from({ length: 5 }, () => store.reserveAction(input)));
    expect(new Set(rows.map((r) => r.operation_key)).size).toBe(1);
    expect((await Promise.all(rows.map((r) => store.claimAction(r.operation_key)))).filter(Boolean)).toHaveLength(1);
    await expect(store.reserveAction({ ...input, payloadHash: "b".repeat(64) })).rejects.toMatchObject({
      code: "action_intent_conflict",
    });
    const material = {
      sessionId: "actual-provider-step",
      sessionToken: "protected-actual-step-token",
      publicKey: { challenge: "actual-provider-challenge", userVerification: "required" },
    };
    const created = await store.actionCreated(input.operationKey, material);
    expect(JSON.stringify(created)).not.toContain(material.sessionToken);
    expect(store.actionMaterial(created)).toEqual(material);
    expect(await store.actionCreated(input.operationKey, material)).toEqual(created);
    const requestId = randomUUID();
    const registered = await store.actionRegistered(input.operationKey, requestId);
    expect(await store.actionRegistered(input.operationKey, requestId)).toEqual(registered);
    await expect(store.actionRegistered(input.operationKey, randomUUID())).rejects.toMatchObject({
      code: "action_intent_conflict",
    });
    await expect(
      sql`UPDATE login_workforce_action_intents SET request_hash=${"c".repeat(64)} WHERE operation_key=${input.operationKey}`,
    ).rejects.toThrow("immutable");
    await store.revokeUser(base.issuer, base.provider_subject);
    await expect(store.reserveAction(input)).rejects.toMatchObject({ code: "action_intent_not_active" });
    await expect(
      store.actionCreated(input.operationKey, { ...material, sessionId: "late-actual-provider-step" }),
    ).rejects.toMatchObject({ code: "action_intent_not_active" });
    expect(await store.pendingRevocations()).toEqual(
      expect.arrayContaining([
        { provider_session_id: material.sessionId },
        { provider_session_id: "late-actual-provider-step" },
      ]),
    );
    expect(await sql`SELECT state FROM login_workforce_action_intents WHERE operation_key=${input.operationKey}`).toEqual([
      { state: "retired" },
    ]);
  });
  it("durably reserves a single exact reviewed legacy retirement and preserves confirmed evidence", async () => {
    const caseId = randomUUID(),
      decisionId = randomUUID(),
      hash = "a".repeat(64),
      binding = { caseId, decisionId, personId: randomUUID() };
    const rows = await Promise.all(
      Array.from({ length: 5 }, () => store.reserveLegacyRetirement(caseId, decisionId, hash, binding, "12345", "200")),
    );
    expect(new Set(rows.map((r) => r.id)).size).toBe(1);
    expect((await Promise.all(rows.map((r) => store.claimLegacyRetirement(r.id)))).filter(Boolean)).toHaveLength(1);
    await expect(store.reserveLegacyRetirement(caseId, randomUUID(), hash, binding, "12345", "200")).rejects.toMatchObject({
      code: "legacy_retirement_binding_changed",
    });
    await expect(
      store.reserveLegacyRetirement(caseId, decisionId, "b".repeat(64), binding, "12345", "200"),
    ).rejects.toMatchObject({ code: "legacy_retirement_binding_changed" });
    await expect(store.reserveLegacyRetirement(caseId, decisionId, hash, binding, "12345", "300")).rejects.toMatchObject({
      code: "legacy_retirement_binding_changed",
    });
    await store.legacyRetirementConfirmed(rows[0].id);
    await store.legacyRetirementConfirmed(rows[0].id);
    expect((await store.reserveLegacyRetirement(caseId, decisionId, hash, binding, "12345", "200")).state).toBe("retired");
    expect(await store.claimLegacyRetirement(rows[0].id)).toBe(false);
    await expect(sql`UPDATE login_legacy_recovery_retirements SET state='pending' WHERE id=${rows[0].id}`).rejects.toThrow(
      "immutable",
    );
    await expect(sql`DELETE FROM login_legacy_recovery_retirements WHERE id=${rows[0].id}`).rejects.toThrow("retained");
  });
  it("private current admission observes exact bindings and immediate logout before provider deletion", async () => {
    const row = await ready(),
      attempt = await store.attempt(row.id, randomUUID(), "123456"),
      verifiedAt = new Date();
    await store.verified(attempt.id, verifiedAt, new Date(Date.now() + 100000));
    const binding = {
      issuer: row.issuer,
      providerSubject: row.provider_subject,
      baseSessionId: row.provider_session_id!,
      clientId: row.client_id,
    };
    expect(await store.currentAdmission(binding)).toMatchObject({
      challenge_id: row.id,
      request_id: row.request_id,
      verified_at: verifiedAt,
    });
    expect(await store.currentAdmission({ ...binding, issuer: "https://other.test" })).toBeUndefined();
    expect(await store.currentAdmission({ ...binding, clientId: "another-client" })).toBeUndefined();
    // An OIDC access-token jti is not the signed ID-token sid / actual provider session.
    expect(await store.currentAdmission({ ...binding, baseSessionId: "aggregate-access-token-id" })).toBeUndefined();
    await store.revoke(row.provider_session_id!);
    expect(await store.currentAdmission(binding)).toBeUndefined();
    expect(await store.pendingRevocations()).toEqual([{ provider_session_id: row.provider_session_id }]);
  });
  it("enrollment verification cannot enter ordinary login admission", async () => {
    const row = await store.reserve({ ...input(), purpose: "reviewed_enrollment" });
    await store.session(row.id, "888", "synthetic-token");
    await store.issued(row.id);
    const attempt = await store.attempt(row.id, randomUUID(), "12345678");
    await expect(store.verified(attempt.id, new Date(), new Date(Date.now() + 100000))).rejects.toMatchObject({
      code: "verification_purpose_mismatch",
    });
    await store.verifiedEnrollment(attempt.id, new Date(), new Date(Date.now() + 100000));
    expect(await store.admission("888", row.provider_subject, row.client_id, row.request_id)).toBe(false);
    expect(await sql`SELECT * FROM login_workforce_admissions WHERE challenge_id=${row.id}`).toHaveLength(0);
  });
});
