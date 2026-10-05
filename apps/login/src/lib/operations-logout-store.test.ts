// @vitest-environment node
import { randomUUID } from "node:crypto";
import { readFileSync } from "node:fs";
import postgres, { type Sql } from "postgres";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { OperationsLogoutStore, type LogoutAdmission, type LogoutInput } from "./operations-logout-store";
import { WorkforceStore } from "./workforce-store";
const url = process.env.PAYPM_WORKFORCE_TEST_DATABASE_URL,
  suite = url ? describe : describe.skip;
suite("Operations exact logout persistence (real PostgreSQL)", () => {
  let admin: Sql, sql: Sql, store: OperationsLogoutStore, base: WorkforceStore, schema: string;
  beforeEach(async () => {
    schema = "login_logout_" + randomUUID().replaceAll("-", "");
    admin = postgres(url!, { max: 1, onnotice: () => {} });
    await admin.unsafe(`CREATE SCHEMA ${schema}`);
    sql = postgres(url!, { max: 10, connection: { search_path: schema } });
    for (const v of [
      "001_workforce_auth",
      "003_workforce_action_intents",
      "007_identity_action_requests",
      "004_operations_action_requests",
      "005_operations_logouts",
    ])
      await sql.unsafe(readFileSync(new URL("../../migrations/" + v + ".sql", import.meta.url), "utf8"));
    store = new OperationsLogoutStore(sql);
    base = new WorkforceStore(sql, Buffer.alloc(32, 19));
  });
  afterEach(async () => {
    await sql?.end();
    if (admin) {
      await admin.unsafe(`DROP SCHEMA ${schema} CASCADE`);
      await admin.end();
    }
  });
  async function ready(expired = false) {
    const t = new Date(Date.now() - (expired ? 500000 : 10000)),
      challenge = randomUUID(),
      session = String(Math.floor(Math.random() * 1e8) + 1000);
    await sql`INSERT INTO login_workforce_epochs(issuer,provider_subject,epoch) VALUES('https://auth.paypm.test','700',3) ON CONFLICT DO NOTHING`;
    await sql`INSERT INTO login_workforce_challenges(id,operation_key,issuer,provider_subject,client_id,request_id,contact_hash,request_hash,epoch,state,provider_session_id,provider_token_sealed,created_at,expires_at,verified_at) VALUES(${challenge},${randomUUID()},'https://auth.paypm.test','700','ops@paypm',${"oidc-" + session},${"a".repeat(64)},${"b".repeat(64)},3,'verified',${session},'sealed-base',${t},${new Date(t.getTime() + 300000)},${new Date(t.getTime() + 1000)})`;
    await sql`INSERT INTO login_workforce_admissions(provider_session_id,challenge_id,issuer,provider_subject,client_id,request_id,epoch,authentication_class,verified_at,absolute_expires_at,last_seen_at) VALUES(${session},${challenge},'https://auth.paypm.test','700','ops@paypm',${"oidc-" + session},3,'workforce_limited',${new Date(t.getTime() + 1000)},${new Date(t.getTime() + (expired ? 100000 : 28800000))},${t})`;
    const a: LogoutAdmission = {
      personId: randomUUID(),
      issuer: "https://auth.paypm.test",
      providerSubject: "700",
      baseSessionId: session,
      clientId: "ops@paypm",
      appId: "paypm-operations",
      deploymentId: "heritagepay",
      environment: "sandbox",
      contextId: "300",
      requestId: "oidc-" + session,
      challengeId: challenge,
      revocationVersion: "3",
    };
    const input: LogoutInput = {
      requestId: randomUUID(),
      operationKey: randomUUID(),
      idToken: "original-signed-ID",
      accessToken: "original-access-token",
      nonce: "original-nonce",
      clientId: a.clientId,
      retirementProof: "synthetic-retirement-only-capture",
    };
    return { a, input };
  }
  it("single current-base revocation is durable and does not log out other staff sessions or change global epoch", async () => {
    const one = await ready(),
      other = await ready();
    const row = await store.revoke(one.input, one.a);
    expect(row.person_id).toBe(one.a.personId);
    expect(
      await base.currentAdmission({
        issuer: one.a.issuer,
        providerSubject: "700",
        baseSessionId: one.a.baseSessionId,
        clientId: one.a.clientId,
      }),
    ).toBeUndefined();
    expect(
      await base.currentAdmission({
        issuer: other.a.issuer,
        providerSubject: "700",
        baseSessionId: other.a.baseSessionId,
        clientId: other.a.clientId,
      }),
    ).toBeDefined();
    const [e] = await sql`SELECT epoch FROM login_workforce_epochs`;
    expect(String(e.epoch)).toBe("3");
    expect(await store.pending(row)).toEqual([{ provider_session_id: one.a.baseSessionId }]);
    expect(JSON.stringify(row)).not.toContain("original-access-token");
  });
  it("never-accepted queued logout can retire its historically admitted exact base after token/idle expiry and newer epoch", async () => {
    const { a, input } = await ready(true);
    await sql`UPDATE login_workforce_epochs SET epoch=4`;
    expect(
      await base.currentAdmission({
        issuer: a.issuer,
        providerSubject: "700",
        baseSessionId: a.baseSessionId,
        clientId: a.clientId,
      }),
    ).toBeUndefined();
    const row = await store.revoke(input, a);
    expect(row.epoch).toBe("3");
    expect(row.base_session_id).toBe(a.baseSessionId);
    const [current] =
      await sql`SELECT revoked_at FROM login_workforce_admissions WHERE provider_session_id=${a.baseSessionId}`;
    expect(current.revoked_at).toBeInstanceOf(Date);
  });
  it("concurrent retries persist one immutable canonical audit and read accepted outcome without reauthentication", async () => {
    const { a, input } = await ready();
    const rows = await Promise.all(Array.from({ length: 6 }, () => store.revoke(input, a)));
    expect(new Set(rows.map((r) => r.request_id))).toEqual(new Set([input.requestId]));
    expect(await store.read(input)).toEqual(rows[0]);
    expect(await sql`SELECT * FROM login_operations_logouts`).toHaveLength(1);
    await expect(store.read({ ...input, nonce: "altered" })).rejects.toMatchObject({ code: "operations_logout_conflict" });
    await expect(store.revoke({ ...input, requestId: randomUUID() }, a)).rejects.toMatchObject({
      code: "operations_logout_conflict",
    });
    await expect(sql`UPDATE login_operations_logouts SET person_id=${randomUUID()}`).rejects.toThrow("immutable");
    await expect(sql`DELETE FROM login_operations_logouts`).rejects.toThrow("immutable");
  });
  it.each(["subject", "client", "epoch", "request", "challenge", "base"])(
    "rejects unknown historical %s binding before revocation",
    async (kind) => {
      const { a, input } = await ready();
      const changed = { ...a };
      if (kind === "subject") changed.providerSubject = "701";
      if (kind === "client") changed.clientId = "other";
      if (kind === "epoch") changed.revocationVersion = "2";
      if (kind === "request") changed.requestId = "another";
      if (kind === "challenge") changed.challengeId = randomUUID();
      if (kind === "base") changed.baseSessionId = "999999";
      await expect(store.revoke(input, changed)).rejects.toMatchObject({ code: "operations_logout_not_admitted" });
      expect(await sql`SELECT * FROM login_workforce_revocations`).toHaveLength(0);
      const [current] = await sql`SELECT revoked_at FROM login_workforce_admissions`;
      expect(current.revoked_at).toBeNull();
    },
  );
  it("clears dependent Identity and Operations ceremony material before provider retirement and retains original evidence", async () => {
    const { a, input } = await ready();
    const ownOp = randomUUID(),
      actionId = randomUUID();
    await sql`INSERT INTO login_workforce_action_intents(operation_key,request_hash,issuer,provider_subject,base_session_id,client_id,request_id,epoch,state,binding,provider_session_id,provider_material_sealed,expires_at) VALUES(${ownOp},${"c".repeat(64)},${a.issuer},'700',${a.baseSessionId},${a.clientId},${a.requestId},3,'created','{}','owned-identity-step','sealed-identity-step',statement_timestamp()+interval '5 minutes')`;
    await sql`INSERT INTO login_operations_action_requests(id,operation_key,request_hash,issuer,provider_subject,base_session_id,client_id,request_id,epoch,binding,capability_hash,caller_material_sealed,state,provider_session_id,provider_material_sealed,expires_at) VALUES(${actionId},${randomUUID()},${"d".repeat(64)},${a.issuer},'700',${a.baseSessionId},${a.clientId},${a.requestId},3,'{}',${"e".repeat(64)},'sealed-original-pair','created','owned-operations-step','sealed-operations-step',statement_timestamp()+interval '5 minutes')`;
    const row = await store.revoke(input, a);
    expect(new Set(row.provider_session_ids)).toEqual(
      new Set([a.baseSessionId, "owned-identity-step", "owned-operations-step"]),
    );
    const [wf] = await sql`SELECT state,provider_material_sealed FROM login_workforce_action_intents`;
    expect(wf).toEqual({ state: "retired", provider_material_sealed: null });
    const [ops] =
      await sql`SELECT state,caller_material_sealed,provider_material_sealed FROM login_operations_action_requests`;
    expect(ops).toEqual({ state: "retired", caller_material_sealed: null, provider_material_sealed: null });
    await base.revocationCompleted(a.baseSessionId);
    expect(await store.pending(row)).toHaveLength(2);
  });
});
