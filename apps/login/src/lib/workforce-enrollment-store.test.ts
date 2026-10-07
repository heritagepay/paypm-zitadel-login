// @vitest-environment node
import { randomUUID } from "node:crypto";
import { describe, expect, it, vi } from "vitest";
import { workforceAssertionHash } from "./workforce-assertion";
import { WorkforceEnrollmentStore } from "./workforce-enrollment-store";
const projection = () => ({
  enrollmentId: randomUUID(),
  personId: randomUUID(),
  policyId: randomUUID(),
  issuer: "https://auth.paypm.test",
  organizationId: "300",
  clientId: "staff-client",
  providerSubject: "700",
  email: "staff@example.test",
  emailVerified: false,
  sourceRevision: "a".repeat(40),
  imageDigest: "b".repeat(64),
  configurationSha256: "c".repeat(64),
  expiresAt: new Date(Date.now() + 120000).toISOString(),
  state: "qualified_enrollment" as const,
});
describe("enrollment association preserves canonical binding", () => {
  it("inherits the existing store key and rejects malformed custody", () => {
    expect(() => new WorkforceEnrollmentStore({} as any, Buffer.alloc(31))).toThrow();
  });
  it("stores contact only as HMAC; verified flag changes preserve original, changed Person/contact/subject do not", async () => {
    const p = projection();
    let row: any;
    const sql: any = vi.fn(async (parts: TemplateStringsArray, ...values: any[]) => {
      const q = parts.join("?");
      if (q.includes("SELECT epoch")) return [{ epoch: "0" }];
      if (q.includes("INSERT INTO login_reviewed_workforce_enrollments")) {
        row = { binding_hash: values[1], binding: values[2], request_id: "oidc_owned" };
        return [row];
      }
      return [];
    });
    sql.json = (v: any) => v;
    sql.begin = (fn: any) => fn(sql);
    const store = new WorkforceEnrollmentStore({ sql } as any, Buffer.alloc(32, 3));
    await store.begin(p, "oidc_owned", randomUUID());
    expect(JSON.stringify(row)).not.toContain(p.email);
    expect(row.binding.contactHash).toMatch(/^[a-f0-9]{64}$/);
    expect(row.binding_hash).toBe(workforceAssertionHash(row.binding));
    expect(() => store.matches(row, { ...p, emailVerified: true })).not.toThrow();
    for (const changed of [{ personId: randomUUID() }, { email: "other@example.test" }, { providerSubject: "701" }])
      expect(() => store.matches(row, { ...p, ...changed })).toThrow();
  });
  it.each(["login", "other-subject", "other-client", "other-epoch", "missing-session"])(
    "will not attach %s as enrollment proof",
    async (kind) => {
      const p = projection(),
        store = new WorkforceEnrollmentStore({} as any, Buffer.alloc(32, 3));
      vi.spyOn(store, "original").mockResolvedValue({
        binding: p,
        issuer: p.issuer,
        provider_subject: p.providerSubject,
        client_id: p.clientId,
        request_id: "oidc_owned",
        epoch: "0",
        expires_at: new Date(Date.now() + 120000),
      } as any);
      const row: any = {
        id: randomUUID(),
        purpose: "reviewed_enrollment",
        issuer: p.issuer,
        provider_subject: p.providerSubject,
        client_id: p.clientId,
        request_id: "oidc_owned",
        epoch: "0",
        provider_session_id: "800",
      };
      if (kind === "login") row.purpose = "login";
      if (kind === "other-subject") row.provider_subject = "701";
      if (kind === "other-client") row.client_id = "other";
      if (kind === "other-epoch") row.epoch = "1";
      if (kind === "missing-session") row.provider_session_id = null;
      await expect(store.attach(p.enrollmentId, row)).rejects.toMatchObject({ code: "enrollment_challenge_changed" });
    },
  );
});
