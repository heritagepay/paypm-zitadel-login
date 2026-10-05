// @vitest-environment node
import { randomBytes, randomUUID } from "node:crypto";
import { readFile } from "node:fs/promises";
import postgres, { type Sql } from "postgres";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import fixture from "../../test-fixtures/identity-wallet-linkage.json";
import type { IdentityActionBinding } from "./identity-action-contract";
import { IdentityActionStore, type IdentityActionRow } from "./identity-action-store";
import { WorkforceStore } from "./workforce-store";
const raw = process.env.TEST_IDENTITY_ACTION_DATABASE_URL;
// Only ROOT may supply this explicitly generated, empty local fixture; no other URL/env fallback.
if (raw) {
  const u = new URL(raw);
  if (
    !["postgres:", "postgresql:"].includes(u.protocol) ||
    !["127.0.0.1", "localhost", "[::1]"].includes(u.hostname) ||
    u.pathname !== "/login_identity_action_tests" ||
    u.search ||
    u.hash
  )
    throw new Error("Synthetic Identity action fixture required");
}
const suite = raw ? describe : describe.skip;
suite("Identity ceremony immutable007/max1 PostgreSQL (ROOT opt-in, synthetic admissions)", () => {
  let admin: Sql, sql: Sql, store: IdentityActionStore, base: WorkforceStore, schema: string;
  beforeEach(async () => {
    schema = "login_identity_action_" + randomUUID().replaceAll("-", "");
    admin = postgres(raw!, { max: 1, onnotice: () => {} });
    await admin.unsafe(`CREATE SCHEMA ${schema}`);
    sql = postgres(raw!, { max: 1, onnotice: () => {}, connection: { search_path: schema } });
    expect((await sql`SELECT current_schema() AS s`)[0].s).toBe(schema);
    for (const version of [
      "001_workforce_auth",
      "002_legacy_recovery_retirements",
      "003_workforce_action_intents",
      "004_operations_action_requests",
      "005_operations_logouts",
      "006_identity_logouts",
      "007_identity_action_requests",
    ])
      await sql.unsafe(await readFile(new URL(`../../migrations/${version}.sql`, import.meta.url), "utf8"));
    store = new IdentityActionStore(sql, Buffer.alloc(32, 18));
    base = new WorkforceStore(sql, Buffer.alloc(32, 17));
  });
  afterEach(async () => {
    await sql?.end();
    if (admin) {
      if (schema) {
        expect(await admin`SELECT schema_name FROM information_schema.schemata WHERE schema_name=${schema}`).toHaveLength(1);
        await admin.unsafe(`DROP SCHEMA ${schema} CASCADE`);
      }
      await admin.end();
    }
  });
  async function ready(sessionId = "800") {
    const challenge = await base.reserve({
      operationKey: randomUUID(),
      issuer: fixture.expected.issuer,
      userId: fixture.expected.providerSubject,
      clientId: fixture.expected.clientId,
      requestId: randomUUID(),
      contact: "staff@example.test",
    });
    await base.claimSession(challenge.id);
    await base.session(challenge.id, sessionId, "synthetic-base-token");
    await base.claimDelivery(challenge.id);
    await base.issued(challenge.id);
    const a = await base.attempt(challenge.id, randomUUID(), "123456");
    await base.verified(a.id, new Date(Math.max(Date.now(), a.created_at.getTime())), new Date(Date.now() + 100000));
    return {
      id: randomUUID(),
      binding: {
        ...fixture,
        expected: { ...fixture.expected, baseSessionId: sessionId },
        caseId: fixture.command.operationKey,
      } as IdentityActionBinding,
      requestId: challenge.request_id,
      material: {
        idToken: "synthetic-id-token",
        accessToken: "synthetic-access-token",
        nonce: "synthetic-nonce",
        clientId: fixture.expected.clientId,
        capability: randomBytes(32).toString("base64url"),
        callbackState: randomBytes(48).toString("base64url"),
        callbackUrl: "https://identity.fixture.test/api/v1/auth/browser/actions/callback",
      },
    };
  }
  async function registered() {
    const input = await ready(),
      row = await store.reserve(input);
    await store.claimCreation(row.id);
    await store.created(row.id, {
      sessionId: "901",
      sessionToken: "synthetic-step-token",
      publicKey: { challenge: "issued-challenge", userVerification: "required" },
    });
    return { input, row: await store.registered(row.id, randomUUID(), new Date(row.expires_at.getTime() + 1000)) };
  }
  it("serializes concurrent originals and retains exact hash/encrypted custody without a second effect", async () => {
    const input = await ready(),
      rows = await Promise.all(Array.from({ length: 4 }, () => store.reserve(input)));
    expect(new Set(rows.map((r) => r.id)).size).toBe(1);
    expect((await Promise.all(rows.map((r) => store.claimCreation(r.id)))).filter(Boolean)).toHaveLength(1);
    expect(store.caller(rows[0])).toEqual(input.material);
    expect(JSON.stringify(rows)).not.toContain(input.material.accessToken);
    expect(JSON.stringify(rows)).not.toContain(input.material.capability);
    await expect(store.reserve({ ...input, id: randomUUID() })).rejects.toMatchObject({
      code: "identity_action_original_required",
    });
    await expect(
      store.reserve({ ...input, material: { ...input.material, accessToken: "changed-proof" } }),
    ).rejects.toMatchObject({ code: "identity_action_conflict" });
  });
  it("stores actual owner proof expiry but never extends original ceremony; one assertion and immutable receipt", async () => {
    const { row } = await registered();
    expect(row.proof_expires_at!.getTime()).toBeGreaterThan(row.expires_at.getTime());
    const body = { id: "credential", response: { synthetic: "assertion" } };
    const attempts = await Promise.all([store.attempt(row.id, body), store.attempt(row.id, body)]);
    expect(attempts.map((a) => a.first).sort()).toEqual([false, true]);
    await expect(store.attempt(row.id, { ...body, id: "foreign" })).rejects.toMatchObject({
      code: "identity_action_conflict",
    });
    const at = new Date(Math.max(Date.now(), attempts[0].row.verification_started_at!.getTime()));
    const receipt = "paypm-wf1.synthetic.original";
    const expiry = new Date(at.getTime() + 59000);
    const done = await store.verified(row.id, at, receipt, expiry);
    expect(done.expires_at).toEqual(row.expires_at);
    expect(store.receipt(done)).toBe(receipt);
    expect((await store.verified(row.id, at, receipt, expiry)).receipt_hash).toBe(done.receipt_hash);
    await expect(sql`UPDATE login_identity_action_requests SET base_session_id='999' WHERE id=${row.id}`).rejects.toThrow(
      "immutable",
    );
    await expect(sql`DELETE FROM login_identity_action_requests WHERE id=${row.id}`).rejects.toThrow("retained");
    await expect(sql`TRUNCATE login_identity_action_requests`).rejects.toThrow("retained");
  });
  it("old SID cannot authorize renewed completion; same-owner renewal respects actual quota and preserves original", async () => {
    const { row, input } = await registered();
    await sql`UPDATE login_workforce_admissions SET revoked_at=clock_timestamp() WHERE provider_session_id='800'`;
    await expect(ready("999")).rejects.toMatchObject({ code: "workforce_delivery_rate_limited" });
    // Real elapsed quota: no fake clock, contact substitution or database timestamp writes.
    const waitingAt = performance.now();
    await new Promise((resolve) => setTimeout(resolve, 61000));
    expect(performance.now() - waitingAt).toBeGreaterThanOrEqual(60000);
    const renewed = await ready("999");
    const admissions =
      await sql`SELECT provider_session_id,challenge_id FROM login_workforce_admissions ORDER BY provider_session_id`;
    expect(admissions).toHaveLength(2);
    expect(admissions[0].challenge_id).not.toBe(admissions[1].challenge_id);
    const binding = { ...input.binding, expected: { ...input.binding.expected, baseSessionId: "999" } };
    const observed = await store.observe(row.id, binding, renewed.requestId);
    expect(observed?.base_session_id).toBe("800");
    await expect(store.row(row.id)).rejects.toMatchObject({ code: "identity_action_not_active" });
    await expect(
      store.observe(row.id, { ...binding, expected: { ...binding.expected, personId: randomUUID() } }, renewed.requestId),
    ).rejects.toMatchObject({ code: "identity_action_conflict" });
  }, 100000);
  it("logout/epoch retirement queues exact provider session and destroys capabilities while preserving audit", async () => {
    const { row } = await registered(),
      before =
        await sql`SELECT id,operation_key,request_hash,base_session_id,binding,created_at::text FROM login_identity_action_requests`;
    await base.revokeUser(row.issuer, row.provider_subject);
    const [after] = await sql`SELECT * FROM login_identity_action_requests`;
    expect(after.state).toBe("retired");
    expect(after.caller_material_sealed).toBeNull();
    expect(after.provider_material_sealed).toBeNull();
    expect(
      await sql`SELECT id,operation_key,request_hash,base_session_id,binding,created_at::text FROM login_identity_action_requests`,
    ).toEqual(before);
    expect(
      await sql`SELECT provider_session_id FROM login_workforce_revocations WHERE provider_session_id='901'`,
    ).toHaveLength(1);
    await expect(store.capability(row.id, randomBytes(32).toString("base64url"))).rejects.toThrow();
  });
  it("late create after cancellation retains only immutable named SID audit and revocation custody", async () => {
    const input = await ready(),
      row = await store.reserve(input);
    await store.claimCreation(row.id);
    await store.cancel(row.id);
    const before =
      await sql`SELECT id,operation_key,request_hash,base_session_id,binding,created_at::text,expires_at::text FROM login_identity_action_requests`;
    expect(
      await store.created(row.id, {
        sessionId: "901",
        sessionToken: "late-private-token",
        publicKey: { challenge: "late-challenge" },
      }),
    ).toBeUndefined();
    const [after] = await sql`SELECT * FROM login_identity_action_requests`;
    expect(after).toMatchObject({
      state: "cancelled",
      provider_session_id: "901",
      provider_material_sealed: null,
      assertion_sealed: null,
      receipt_sealed: null,
      proof_id: null,
    });
    expect(
      await sql`SELECT id,operation_key,request_hash,base_session_id,binding,created_at::text,expires_at::text FROM login_identity_action_requests`,
    ).toEqual(before);
    expect(
      await sql`SELECT provider_session_id FROM login_workforce_revocations WHERE provider_session_id='901'`,
    ).toHaveLength(1);
    await expect(
      sql`UPDATE login_identity_action_requests SET provider_session_id='902' WHERE id=${row.id}`,
    ).rejects.toThrow("immutable");
    await expect(
      sql`UPDATE login_identity_action_requests SET state='created',provider_material_sealed='resurrected' WHERE id=${row.id}`,
    ).rejects.toThrow("immutable");
    await expect(store.row(row.id)).rejects.toMatchObject({ code: "identity_action_not_active" });
  });
  it("an exact metadata-discovered orphan fills audit-only SID once, without extending deadline or reviving material", async () => {
    const input = await ready(),
      row = await store.reserve(input);
    await store.claimCreation(row.id);
    await store.retire(row.id, "901");
    const [after] = await sql`SELECT * FROM login_identity_action_requests`;
    expect(after).toMatchObject({
      state: "retired",
      provider_session_id: "901",
      caller_material_sealed: null,
      provider_material_sealed: null,
      assertion_sealed: null,
      receipt_sealed: null,
    });
    expect(after.expires_at).toEqual(row.expires_at);
    await store.retire(row.id, "901");
    expect((await sql`SELECT * FROM login_identity_action_requests`)[0]).toEqual(after);
    await expect(store.capability(row.id, input.material.capability, true)).rejects.toThrow();
    // Real external ownership is faked in this SQL suite; the production service
    // independently qualifies these SIDs before passing them into this owner.
    await expect(
      store.created(row.id, {
        sessionId: "902",
        sessionToken: "conflicting-private-token",
        publicKey: { challenge: "conflict" },
      }),
    ).rejects.toMatchObject({ code: "identity_action_conflict" });
    const [held] = await sql<IdentityActionRow[]>`SELECT * FROM login_identity_action_requests`;
    expect(held).toMatchObject({
      state: "retired",
      provider_conflicted: true,
      provider_session_id: "901",
      caller_material_sealed: null,
      provider_material_sealed: null,
      assertion_sealed: null,
      receipt_sealed: null,
    });
    expect(
      (await sql`SELECT provider_session_id FROM login_workforce_revocations ORDER BY provider_session_id`).map(
        (r) => r.provider_session_id,
      ),
    ).toEqual(["901", "902"]);
    await expect(store.reserve({ ...input, id: randomUUID(), predecessor: held })).rejects.toMatchObject({
      code: "identity_action_continuation_denied",
    });
    await expect(
      sql`UPDATE login_identity_action_requests SET provider_conflicted=false WHERE id=${row.id}`,
    ).rejects.toThrow("immutable");
    await expect(store.retire(row.id, "903")).rejects.toMatchObject({ code: "identity_action_conflict" });
    expect(
      (await sql`SELECT provider_session_id FROM login_workforce_revocations ORDER BY provider_session_id`).map(
        (r) => r.provider_session_id,
      ),
    ).toEqual(["901", "902", "903"]);
    expect((await sql`SELECT * FROM login_identity_action_requests`)[0].provider_session_id).toBe("901");
  });
  it("intake/review may share case UUID without colliding, but direct statement cannot fabricate proof transition", async () => {
    const { row, input } = await registered();
    const review = {
      ...input,
      id: randomUUID(),
      binding: {
        ...input.binding,
        expected: {
          ...input.binding.expected,
          action: "identity.wallet.legacy.linkage.review" as const,
          payloadHash: "c".repeat(64),
        },
        command: {
          purpose: "wallet_legacy_linkage" as const,
          operationKey: row.operation_key,
          caseId: row.operation_key,
          revision: 1 as const,
          decision: "approve" as const,
        },
      },
    };
    expect((await store.reserve(review)).operation_key).toBe(row.operation_key);
    await expect(
      sql`UPDATE login_identity_action_requests SET proof_id=${randomUUID()},proof_expires_at=expires_at WHERE id=${review.id}`,
    ).rejects.toThrow("immutable");
    await expect(sql`UPDATE login_identity_action_requests SET binding='{}' WHERE id=${row.id}`).rejects.toThrow();
  });
});
