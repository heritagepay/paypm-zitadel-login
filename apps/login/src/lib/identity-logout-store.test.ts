// @vitest-environment node
import { randomUUID } from "node:crypto";
import { readFileSync } from "node:fs";
import postgres, { type Sql } from "postgres";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { IdentityLogoutStore, type IdentityLogoutAdmission, type IdentityProofPair } from "./identity-logout-store";
import { WorkforceStore } from "./workforce-store";
const url = process.env.PAYPM_WORKFORCE_TEST_DATABASE_URL,
  suite = url ? describe : describe.skip;
suite("Identity exact logout persistence (real PostgreSQL)", () => {
  let admin: Sql, sql: Sql, store: IdentityLogoutStore, base: WorkforceStore, schema: string;
  beforeEach(async () => {
    schema = "login_identity_logout_" + randomUUID().replaceAll("-", "");
    admin = postgres(url!, { max: 1, onnotice: () => {} });
    await admin.unsafe(`CREATE SCHEMA ${schema}`);
    sql = postgres(url!, { max: 10, connection: { search_path: schema } });
    for (const v of [
      "001_workforce_auth",
      "003_workforce_action_intents",
      "004_operations_action_requests",
      "006_identity_logouts",
    ])
      await sql.unsafe(readFileSync(new URL("../../migrations/" + v + ".sql", import.meta.url), "utf8"));
    store = new IdentityLogoutStore(sql);
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
    await sql`INSERT INTO login_workforce_challenges(id,operation_key,issuer,provider_subject,client_id,request_id,contact_hash,request_hash,epoch,state,provider_session_id,provider_token_sealed,created_at,expires_at,verified_at) VALUES(${challenge},${randomUUID()},'https://auth.paypm.test','700','identity@paypm',${"oidc-" + session},${"a".repeat(64)},${"b".repeat(64)},3,'verified',${session},'sealed-base',${t},${new Date(t.getTime() + 300000)},${new Date(t.getTime() + 1000)})`;
    await sql`INSERT INTO login_workforce_admissions(provider_session_id,challenge_id,issuer,provider_subject,client_id,request_id,epoch,authentication_class,verified_at,absolute_expires_at,last_seen_at) VALUES(${session},${challenge},'https://auth.paypm.test','700','identity@paypm',${"oidc-" + session},3,'workforce_limited',${new Date(t.getTime() + 1000)},${new Date(t.getTime() + (expired ? 100000 : 28800000))},${t})`;
    const a: IdentityLogoutAdmission = {
      personId: randomUUID(),
      issuer: "https://auth.paypm.test",
      providerSubject: "700",
      baseSessionId: session,
      clientId: "identity@paypm",
      appId: "identity-administration",
      deploymentId: "heritagepay",
      environment: "sandbox",
      contextId: "300",
      requestId: "oidc-" + session,
      challengeId: challenge,
      revocationVersion: "3",
    };
    const input: IdentityProofPair = {
      idToken: "original-signed-ID",
      accessToken: "original-access-token",
      nonce: "original-nonce",
      clientId: a.clientId,
    };
    return { a, input };
  }
  it("commits exact current-base retirement and leaves other admitted sessions active", async () => {
    const one = await ready(),
      other = await ready();
    const row = await store.revoke(one.input, one.a);
    expect(row.admission.personId).toBe(one.a.personId);
    expect(
      await base.currentAdmission({
        issuer: one.a.issuer,
        providerSubject: one.a.providerSubject,
        baseSessionId: one.a.baseSessionId,
        clientId: one.a.clientId,
      }),
    ).toBeUndefined();
    expect(
      await base.currentAdmission({
        issuer: other.a.issuer,
        providerSubject: other.a.providerSubject,
        baseSessionId: other.a.baseSessionId,
        clientId: other.a.clientId,
      }),
    ).toBeDefined();
    expect(await store.pending(row)).toEqual([{ provider_session_id: one.a.baseSessionId }]);
    expect(JSON.stringify(row)).not.toContain(one.input.accessToken);
    const [epoch] = await sql`SELECT epoch FROM login_workforce_epochs`;
    expect(String(epoch.epoch)).toBe("3");
  });
  it("concurrent identical requests persist one outcome then reread it after expiry without admission restoration", async () => {
    const { input, a } = await ready();
    const rows = await Promise.all(Array.from({ length: 5 }, () => store.revoke(input, a)));
    expect(new Set(rows.map((row) => row.revoked_at.toISOString())).size).toBe(1);
    const [count] = await sql`SELECT count(*)::int AS n FROM login_identity_logouts`;
    expect(count.n).toBe(1);
    await sql`UPDATE login_workforce_epochs SET epoch=4`;
    expect((await store.read(input))?.admission.baseSessionId).toBe(a.baseSessionId);
    expect(await store.read({ ...input, nonce: "changed" })).toBeUndefined();
  });
  it.each(["expired", "epoch", "client", "challenge", "wrong-plane"])(
    "denies never-accepted %s proof before revocation",
    async (kind) => {
      const { input, a } = await ready(kind === "expired");
      if (kind === "epoch") await sql`UPDATE login_workforce_epochs SET epoch=4`;
      if (kind === "client") a.clientId = "other@paypm";
      if (kind === "challenge") a.challengeId = randomUUID();
      if (kind === "wrong-plane") a.appId = "paypm-operations";
      await expect(store.revoke(input, a)).rejects.toThrow();
      expect(await store.read(input)).toBeUndefined();
      expect(await sql`SELECT * FROM login_workforce_revocations`).toHaveLength(0);
    },
  );
});
