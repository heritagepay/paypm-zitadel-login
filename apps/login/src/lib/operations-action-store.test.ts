// @vitest-environment node
import { randomBytes, randomUUID } from "node:crypto";
import { readFileSync } from "node:fs";
import postgres, { type Sql } from "postgres";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import deploymentGrantFixture from "../../test-fixtures/operations-deployment-grant.json";
import grantFixture from "../../test-fixtures/operations-governed-grant.json";
import kycGrantFixture from "../../test-fixtures/operations-kyc-grant.json";
import { OperationsActionStore, type OperationsActionBinding } from "./operations-action-store";
import { WorkforceStore } from "./workforce-store";
const url = process.env.PAYPM_WORKFORCE_TEST_DATABASE_URL,
  suite = url ? describe : describe.skip;
suite("Operations purpose action evidence (real PostgreSQL)", () => {
  let admin: Sql, sql: Sql, store: OperationsActionStore, base: WorkforceStore, schema: string;
  beforeEach(async () => {
    schema = "login_ops_" + randomUUID().replaceAll("-", "");
    admin = postgres(url!, { max: 1 });
    await admin.unsafe(`CREATE SCHEMA ${schema}`);
    sql = postgres(url!, { max: 10, connection: { search_path: schema } });
    await sql.unsafe(readFileSync(new URL("../../migrations/001_workforce_auth.sql", import.meta.url), "utf8"));
    await sql.unsafe(readFileSync(new URL("../../migrations/003_workforce_action_intents.sql", import.meta.url), "utf8"));
    await sql.unsafe(readFileSync(new URL("../../migrations/004_operations_action_requests.sql", import.meta.url), "utf8"));
    base = new WorkforceStore(sql, Buffer.alloc(32, 19));
    store = new OperationsActionStore(sql, Buffer.alloc(32, 20));
  });
  afterEach(async () => {
    await sql?.end();
    if (admin) {
      await admin.unsafe(`DROP SCHEMA ${schema} CASCADE`);
      await admin.end();
    }
  });
  async function ready() {
    const challenge = await base.reserve({
      operationKey: randomUUID(),
      issuer: "https://auth.paypm.test",
      userId: "12345",
      clientId: "ops-client",
      requestId: "original-oidc-request",
      contact: "staff@example.test",
    });
    await base.claimSession(challenge.id);
    await base.session(challenge.id, "5566", "synthetic-base-token");
    await base.claimDelivery(challenge.id);
    await base.issued(challenge.id);
    const attempt = await base.attempt(challenge.id, randomUUID(), "123456");
    await base.verified(
      attempt.id,
      new Date(Math.max(Date.now(), attempt.created_at.getTime())),
      new Date(Date.now() + 100000),
    );
    const binding: OperationsActionBinding = {
      expected: {
        personId: randomUUID(),
        issuer: challenge.issuer,
        providerSubject: challenge.provider_subject,
        baseSessionId: "5566",
        clientId: challenge.client_id,
        contextId: "300",
        appId: "paypm-operations",
        deploymentId: "heritagepay",
        environment: "production",
        action: "operations.merchant.settlement.review",
        payloadHash: "a".repeat(64),
      },
      command: { operationKey: randomUUID(), merchantBusinessId: randomUUID(), organizationId: randomUUID() },
      capabilityDecisionId: randomUUID(),
      resource: { merchantBusinessId: "", organizationId: "", currency: "XOF" },
    };
    binding.resource.merchantBusinessId = binding.command.merchantBusinessId;
    binding.resource.organizationId = binding.command.organizationId;
    return {
      id: randomUUID(),
      binding,
      requestId: challenge.request_id,
      material: {
        idToken: "synthetic-id-token",
        accessToken: "synthetic-access-token",
        nonce: "synthetic-original-nonce",
        clientId: challenge.client_id,
        capability: randomBytes(32).toString("base64url"),
        callbackState: randomBytes(48).toString("base64url"),
        callbackUrl: "https://ops.paypm.test/auth/workforce/actions/callback",
      },
    };
  }
  async function created() {
    const input = await ready(),
      row = await store.reserve(input);
    await store.claimCreation(row.id);
    const material = {
      sessionId: "7788",
      sessionToken: "synthetic-step-token",
      publicKey: { challenge: "issued-challenge", userVerification: "required" },
    };
    return { input, row: await store.created(row.id, material), material };
  }
  async function verified() {
    const result = await created();
    const attempt = await store.attempt(result.row.id, {
      id: "credential",
      response: { signed: "synthetic-exact-assertion" },
    });
    return {
      ...result,
      row: await store.verified(
        result.row.id,
        new Date(Math.max(Date.now(), attempt.row.verification_started_at!.getTime())),
      ),
    };
  }
  it("concurrent start retains caller IDs and immutable owner binding with one creation claim", async () => {
    const input = await ready(),
      rows = await Promise.all(Array.from({ length: 5 }, () => store.reserve(input)));
    expect(new Set(rows.map((r) => r.id))).toEqual(new Set([input.id]));
    expect((await Promise.all(rows.map((r) => store.claimCreation(r.id)))).filter(Boolean)).toHaveLength(1);
    expect(JSON.stringify(rows)).not.toContain(input.material.accessToken);
    expect(JSON.stringify(rows)).not.toContain(input.material.capability);
    expect(store.caller(rows[0])).toEqual(input.material);
    await expect(store.reserve({ ...input, id: randomUUID() })).rejects.toMatchObject({
      code: "operations_action_conflict",
    });
    await expect(
      store.reserve({
        ...input,
        binding: { ...input.binding, expected: { ...input.binding.expected, payloadHash: "b".repeat(64) } },
      }),
    ).rejects.toMatchObject({ code: "operations_action_conflict" });
    await expect(sql`UPDATE login_operations_action_requests SET binding='{}'::jsonb WHERE id=${input.id}`).rejects.toThrow(
      "immutable",
    );
    await expect(
      store.reserve({
        ...input,
        binding: { ...input.binding, expected: { ...input.binding.expected, environment: "sandbox" } },
      }),
    ).rejects.toMatchObject({ code: "operations_action_conflict" });
  });
  it.each([grantFixture, deploymentGrantFixture, kycGrantFixture])(
    "persists an exact grant discriminator/policy/target across races and uncertain consumption",
    async (fixture) => {
      const input = await ready();
      input.binding = {
        expected: {
          ...input.binding.expected,
          action: fixture.request.expected.action as OperationsActionBinding["expected"]["action"],
          payloadHash: fixture.request.expected.payloadHash,
        },
        command: fixture.request.command as any,
        resource: fixture.response.resource as any,
        capabilityDecisionId: fixture.request.command.policyId,
      };
      const rows = await Promise.all(Array.from({ length: 5 }, () => store.reserve(input)));
      expect(new Set(rows.map((r) => r.id)).size).toBe(1);
      expect(rows[0].binding).toEqual(input.binding);
      await expect(
        store.reserve({
          ...input,
          binding: { ...input.binding, command: { ...input.binding.command, targetPersonId: randomUUID() } as any },
        }),
      ).rejects.toMatchObject({ code: "operations_action_conflict" });
      await store.claimCreation(input.id);
      await store.created(input.id, {
        sessionId: "8899",
        sessionToken: "synthetic-grant-step-token",
        publicKey: { challenge: "actual-grant-challenge", userVerification: "required" },
      });
      const attempt = await store.attempt(input.id, {
        id: "credential",
        response: { signed: "synthetic-signed-assertion" },
      });
      const verified = await store.verified(
        input.id,
        new Date(Math.max(Date.now(), attempt.row.verification_started_at!.getTime())),
      );
      const receipt = store.receipt(verified);
      const consumed = await Promise.allSettled(Array.from({ length: 5 }, () => store.consume(receipt, input.binding)));
      expect(consumed.filter((r) => r.status === "fulfilled")).toHaveLength(1);
      expect((await store.consume(receipt, input.binding, true)).binding).toEqual(input.binding);
      await expect(
        store.consume(
          receipt,
          { ...input.binding, resource: { ...input.binding.resource, policyHash: "b".repeat(64) } as any },
          true,
        ),
      ).rejects.toMatchObject({ code: "operations_receipt_not_active" });
      await base.revoke("5566");
      await expect(store.consume(receipt, input.binding, true)).rejects.toMatchObject({
        code: "operations_receipt_not_active",
      });
    },
  );
  it("retains only the exact opaque public capability and original provider challenge", async () => {
    const { input, row, material } = await created();
    expect((await store.capability(row.id, input.material.capability)).id).toBe(row.id);
    await expect(store.capability(row.id, randomBytes(32).toString("base64url"))).rejects.toThrow();
    expect(await store.created(row.id, material)).toEqual(row);
    await expect(store.created(row.id, { ...material, sessionId: "another" })).rejects.toMatchObject({
      code: "operations_action_conflict",
    });
    expect(store.provider(row)).toEqual(material);
    expect(JSON.stringify(row)).not.toContain(material.sessionToken);
    expect(await store.claimCreation(row.id)).toBe(false);
  });
  it("retains the owning operation across separate action phases without colliding maker and checker evidence", async () => {
    const input = await ready();
    const review = await store.reserve(input);
    const approve = await store.reserve({
      ...input,
      id: randomUUID(),
      binding: {
        ...input.binding,
        expected: {
          ...input.binding.expected,
          action: "operations.merchant.settlement.approve",
          personId: randomUUID(),
          payloadHash: "b".repeat(64),
        },
      },
    });
    const execute = await store.reserve({
      ...input,
      id: randomUUID(),
      binding: {
        ...input.binding,
        expected: {
          ...input.binding.expected,
          action: "operations.merchant.settlement.execute",
          payloadHash: "c".repeat(64),
        },
      },
    });
    expect(new Set([review.id, approve.id, execute.id]).size).toBe(3);
    expect([review.operation_key, approve.operation_key, execute.operation_key]).toEqual(
      Array(3).fill(input.binding.command.operationKey),
    );
  });
  it("reserves one exact assertion before effects and denies a changed or stale assertion", async () => {
    const { row } = await created(),
      assertion = { id: "credential", response: { signed: "synthetic-assertion" } };
    const attempts = await Promise.all(Array.from({ length: 5 }, () => store.attempt(row.id, assertion)));
    expect(attempts.filter((a) => a.first)).toHaveLength(1);
    await expect(store.attempt(row.id, { id: "changed" })).rejects.toMatchObject({ code: "operations_assertion_conflict" });
    expect(JSON.stringify(attempts)).not.toContain("synthetic-assertion");
    expect(store.assertion(attempts[0].row)).toEqual(assertion);
    await expect(store.verified(row.id, new Date(Date.now() - 61000))).rejects.toMatchObject({
      code: "operations_verification_mismatch",
    });
    await expect(store.verified(row.id, new Date(Date.now() + 60000))).rejects.toMatchObject({
      code: "operations_verification_mismatch",
    });
  });
  it("single-use sixty-second receipt has exact consumed readback and immutable evidence", async () => {
    const { row, input } = await verified(),
      receipt = store.receipt(row);
    expect(row.receipt_expires_at!.getTime() - row.verified_at!.getTime()).toBe(60000);
    expect(JSON.stringify(row)).not.toContain(receipt);
    const races = await Promise.allSettled(Array.from({ length: 5 }, () => store.consume(receipt, input.binding)));
    expect(races.filter((r) => r.status === "fulfilled")).toHaveLength(1);
    const readback = await store.consume(receipt, input.binding, true);
    expect(readback.state).toBe("consumed");
    expect(readback.consumed_at).toBeInstanceOf(Date);
    await expect(
      store.consume(
        receipt,
        { ...input.binding, expected: { ...input.binding.expected, payloadHash: "b".repeat(64) } },
        true,
      ),
    ).rejects.toMatchObject({ code: "operations_receipt_not_active" });
    await expect(sql`UPDATE login_operations_action_requests SET state='verified' WHERE id=${row.id}`).rejects.toThrow(
      "immutable",
    );
    await expect(sql`DELETE FROM login_operations_action_requests WHERE id=${row.id}`).rejects.toThrow("retained");
  });
  it("logout denies receipt/capability immediately and cleans sealed material while queuing actual provider retirement", async () => {
    const { row, input } = await verified(),
      receipt = store.receipt(row);
    await base.revoke("5566");
    await expect(store.consume(receipt, input.binding)).rejects.toMatchObject({ code: "operations_receipt_not_active" });
    await expect(store.capability(row.id, input.material.capability)).rejects.toMatchObject({
      code: "operations_action_not_active",
    });
    await store.clearExpired();
    const [retired] = await sql`SELECT * FROM login_operations_action_requests WHERE id=${row.id}`;
    expect(retired).toMatchObject({
      state: "retired",
      caller_material_sealed: null,
      provider_material_sealed: null,
      assertion_sealed: null,
      receipt_sealed: null,
    });
    expect(await base.pendingRevocations()).toEqual(expect.arrayContaining([{ provider_session_id: "7788" }]));
  });
  it("late provider create after logout queues the real orphan without restoring admission", async () => {
    const input = await ready(),
      row = await store.reserve(input);
    await store.claimCreation(row.id);
    await base.revokeUser(input.binding.expected.issuer, input.binding.expected.providerSubject);
    await expect(
      store.created(row.id, { sessionId: "late-7788", sessionToken: "late-secret", publicKey: { challenge: "late" } }),
    ).rejects.toMatchObject({ code: "operations_action_not_active" });
    expect(await base.pendingRevocations()).toEqual(expect.arrayContaining([{ provider_session_id: "late-7788" }]));
    await expect(store.reserve(input)).rejects.toMatchObject({ code: "operations_action_not_active" });
  });
  it("durable cancellation prevents late verification and preserves exact terminal readback only", async () => {
    const { row, input } = await created();
    await store.attempt(row.id, { id: "credential" });
    const cancelled = await store.cancel(row.id);
    expect(cancelled.state).toBe("cancelled");
    expect((await store.cancel(row.id)).state).toBe("cancelled");
    expect((await store.row(row.id, true)).binding).toEqual(input.binding);
    await expect(store.verified(row.id, new Date())).rejects.toMatchObject({ code: "operations_verification_mismatch" });
    await expect(store.capability(row.id, input.material.capability)).rejects.toMatchObject({
      code: "operations_action_not_active",
    });
    await expect(
      sql`UPDATE login_operations_action_requests SET provider_material_sealed='resurrected-secret' WHERE id=${row.id}`,
    ).rejects.toThrow("immutable");
    expect(await base.pendingRevocations()).toEqual(expect.arrayContaining([{ provider_session_id: "7788" }]));
    const explicitRestart = await store.reserve({ ...input, id: randomUUID() });
    expect(explicitRestart.operation_key).toBe(input.binding.command.operationKey);
    expect(explicitRestart.id).not.toBe(row.id);
    expect((await store.row(row.id, true)).state).toBe("cancelled");
  });
  it("original status reads never reserve an absent request or claim its provider creation", async () => {
    const input = await ready();
    expect(await store.observe(input.id, input.binding, input.requestId)).toBeUndefined();
    expect((await sql`SELECT id FROM login_operations_action_requests`).length).toBe(0);
    await store.reserve(input);
    expect((await store.observe(input.id, input.binding, input.requestId))?.provider_started_at).toBeNull();
    expect(await store.claimCreation(input.id)).toBe(true);
    await expect(store.observe(randomUUID(), input.binding, input.requestId)).rejects.toMatchObject({
      code: "operations_action_conflict",
    });
  });
  it.each([grantFixture, deploymentGrantFixture, kycGrantFixture])(
    "a retired family request retains its exact original status without sealed credentials or permission resurrection",
    async (fixture) => {
      const input = await ready();
      input.binding = {
        expected: {
          ...input.binding.expected,
          action: fixture.request.expected.action as OperationsActionBinding["expected"]["action"],
          payloadHash: fixture.request.expected.payloadHash,
        },
        command: fixture.request.command as any,
        capabilityDecisionId: fixture.request.command.policyId,
        resource: fixture.response.resource as any,
      };
      await store.reserve(input);
      await store.claimCreation(input.id);
      await store.retire(input.id);
      const row = await store.observe(input.id, input.binding, input.requestId);
      expect(row).toMatchObject({ state: "retired", caller_material_sealed: null, provider_material_sealed: null });
      expect(row?.provider_started_at).toBeInstanceOf(Date);
      await expect(store.row(input.id)).rejects.toMatchObject({ code: "operations_action_not_active" });
      await expect(
        store.observe(
          input.id,
          { ...input.binding, command: { ...input.binding.command, targetPersonId: randomUUID() } as any },
          input.requestId,
        ),
      ).rejects.toMatchObject({ code: "operations_action_conflict" });
      await base.revoke("5566");
      await expect(store.observe(input.id, input.binding, input.requestId)).rejects.toMatchObject({
        code: "operations_action_not_active",
      });
    },
  );
  it("status cannot change the original OIDC intent/base or survive durable logout", async () => {
    const { input, row } = await created();
    await expect(store.observe(row.id, input.binding, "another-oidc-request")).rejects.toMatchObject({
      code: "operations_action_not_active",
    });
    await expect(
      store.observe(
        row.id,
        { ...input.binding, expected: { ...input.binding.expected, baseSessionId: "9999" } },
        input.requestId,
      ),
    ).rejects.toMatchObject({ code: "operations_action_not_active" });
    await base.revokeUser(input.binding.expected.issuer, input.binding.expected.providerSubject);
    await expect(store.observe(row.id, input.binding, input.requestId)).rejects.toMatchObject({
      code: "operations_action_not_active",
    });
  });
});
