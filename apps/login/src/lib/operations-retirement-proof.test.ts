import { createHash } from "node:crypto";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import fixture from "../../test-fixtures/operations-logout.json";
import {
  mintOperationsRetirementProof,
  verifyOperationsRetirementProof,
  type OperationsRetirementAdmission,
} from "./operations-retirement-proof";
const hash = (v: string) => createHash("sha256").update(v).digest("hex");
const admission = (): OperationsRetirementAdmission => ({
  active: true,
  issuer: "https://auth.paypm.test",
  providerSubject: "700",
  baseSessionId: "900",
  clientId: "ops@paypm",
  tokenId: "v2_access",
  idTokenHash: hash("signed-ID"),
  accessTokenHash: hash("original-access"),
  nonceHash: hash("original-nonce"),
  personId: "11111111-1111-4111-8111-111111111111",
  plane: "workforce",
  appId: "paypm-operations",
  deploymentId: "heritagepay",
  environment: "sandbox",
  contextId: "300",
  requestId: "original-oidc-request",
  challengeId: "11111111-1111-4111-8111-111111111199",
  authenticationClass: "workforce_limited",
  verifiedAt: new Date(Date.now() - 1000).toISOString(),
  absoluteExpiresAt: new Date(Date.now() + 28800000).toISOString(),
  checkedAt: new Date().toISOString(),
  revocationVersion: "2",
});
beforeEach(() => vi.stubEnv("PAYPM_OPERATIONS_RETIREMENT_PROOF_KEY_BASE64", Buffer.alloc(32, 29).toString("base64")));
afterEach(() => {
  vi.unstubAllEnvs();
  vi.useRealTimers();
});
describe("Operations retirement-only capture", () => {
  it("qualifies the independent consumer fixture/header/signature and exact fifteen-field logout tuple", () => {
    vi.useFakeTimers();
    vi.setSystemTime(new Date("2026-10-03T12:00:00.000Z"));
    expect(fixture.header).toBe("X-PayPM-Operations-Retirement-Proof");
    expect(mintOperationsRetirementProof(fixture.admission as OperationsRetirementAdmission)).toBe(
      fixture.request.retirementProof,
    );
    expect(verifyOperationsRetirementProof(fixture.request.retirementProof)).toEqual(fixture.admission);
    expect(Object.keys(fixture.response)).toHaveLength(15);
  });
  it("retains exact original pair/Person/session/epoch after access expiry without minting authentication", () => {
    vi.useFakeTimers();
    const a = admission(),
      proof = mintOperationsRetirementProof(a);
    expect(proof).toMatch(/^paypm-oplogout1\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]{43}$/);
    expect(proof.length).toBeLessThanOrEqual(16384);
    vi.advanceTimersByTime(301000);
    expect(verifyOperationsRetirementProof(proof)).toEqual(a);
    expect(proof).not.toContain("original-access");
    vi.advanceTimersByTime(8 * 86400000);
    expect(() => verifyOperationsRetirementProof(proof)).toThrow();
  });
  it.each(["signature", "purpose", "namespace", "malformed", "wrong-key", "reused-key", "missing-key"])(
    "denies %s",
    (kind) => {
      const proof = mintOperationsRetirementProof(admission());
      if (kind === "wrong-key")
        vi.stubEnv("PAYPM_OPERATIONS_RETIREMENT_PROOF_KEY_BASE64", Buffer.alloc(32, 30).toString("base64"));
      if (kind === "reused-key")
        vi.stubEnv("PAYPM_WORKFORCE_STORE_KEY_BASE64", process.env.PAYPM_OPERATIONS_RETIREMENT_PROOF_KEY_BASE64!);
      if (kind === "missing-key") vi.stubEnv("PAYPM_OPERATIONS_RETIREMENT_PROOF_KEY_BASE64", "");
      let changed = proof;
      if (kind === "signature") changed = proof.slice(0, -1) + (proof.endsWith("A") ? "B" : "A");
      if (kind === "namespace") changed = proof.replace("paypm-oplogout1", "paypm-ops1");
      if (kind === "purpose") {
        const parts = proof.split(".");
        const value = JSON.parse(Buffer.from(parts[1], "base64url").toString());
        value.purpose = "operations_login";
        parts[1] = Buffer.from(JSON.stringify(value)).toString("base64url");
        changed = parts.join(".");
      }
      if (kind === "malformed") changed = "paypm-oplogout1.bad.bad";
      expect(() => verifyOperationsRetirementProof(changed)).toThrow();
    },
  );
});
