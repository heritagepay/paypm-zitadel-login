// @vitest-environment node
import { cookies } from "next/headers";
import { randomUUID } from "node:crypto";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { encryptActionState } from "./workforce-action-state";
import {
  clearEnrollmentReturn,
  enrollmentReturnTarget,
  openEnrollmentReturn,
  readEnrollmentReturn,
  sealEnrollmentReturn,
  writeEnrollmentReturn,
  type EnrollmentReturnState,
} from "./workforce-enrollment-return";
vi.mock("next/headers", () => ({ cookies: vi.fn() }));
const jar = { get: vi.fn(), set: vi.fn(), delete: vi.fn() };
const target = { clientId: "staff-client", application: "identity", url: "https://identity.paypm.test/" };
const state = (): EnrollmentReturnState => ({
  enrollmentId: randomUUID(),
  clientId: "staff-client",
  issuer: "https://auth.paypm.test",
  projectionHash: "a".repeat(64),
  custodyHash: "b".repeat(64),
  targetHash: "c".repeat(64),
  previousRequestId: "oidc_old",
  issuedAt: Date.now(),
  expiresAt: Date.now() + 300000,
});
beforeEach(() => {
  vi.resetAllMocks();
  vi.stubEnv("PAYPM_WORKFORCE_ORGANIZATION_ID", "300");
  vi.stubEnv("PAYPM_WORKFORCE_ISSUER", "https://auth.paypm.test");
  vi.stubEnv("PAYPM_WORKFORCE_OIDC_CLIENT_IDS", "staff-client");
  vi.stubEnv("PAYPM_WORKFORCE_FLOW_KEY_BASE64", Buffer.alloc(32, 3).toString("base64"));
  vi.stubEnv("PAYPM_WORKFORCE_ENROLLMENT_RETURN_TARGETS_JSON", JSON.stringify([target]));
  vi.mocked(cookies).mockResolvedValue(jar as any);
});
afterEach(() => {
  vi.unstubAllEnvs();
});
describe("registered enrollment return targets", () => {
  it("resolves only the exact registered client and no default", () => {
    expect(enrollmentReturnTarget("staff-client")).toEqual(target);
    expect(enrollmentReturnTarget("other")).toBeUndefined();
  });
  it.each([
    "http://identity.paypm.test/",
    "https://user:pass@identity.paypm.test/",
    "https://identity.paypm.test/?next=https://other.test/",
    "https://identity.paypm.test/#code=secret",
    "https://*.paypm.test/",
    "https://identity.paypm.test/\\evil",
    "https://identity.paypm.test",
  ])("rejects unsafe/noncanonical target %s", (url) => {
    vi.stubEnv("PAYPM_WORKFORCE_ENROLLMENT_RETURN_TARGETS_JSON", JSON.stringify([{ ...target, url }]));
    expect(enrollmentReturnTarget("staff-client")).toBeUndefined();
  });
  it.each([
    [target, target],
    [{ ...target, clientId: "other" }],
    [{ ...target, application: "merchant" }],
    [{ ...target, callback: "https://other.test/" }],
    null,
  ])("rejects malformed/duplicate/unregistered catalogue %j", (rows) => {
    vi.stubEnv("PAYPM_WORKFORCE_ENROLLMENT_RETURN_TARGETS_JSON", JSON.stringify(rows));
    expect(enrollmentReturnTarget("staff-client")).toBeUndefined();
  });
});
describe("protected routing hint, never authentication proof", () => {
  it("encrypts context with randomized ciphertext and exact round trip", () => {
    const s = state(),
      a = sealEnrollmentReturn(s),
      b = sealEnrollmentReturn(s);
    expect(a).not.toBe(b);
    expect(a).not.toContain(s.enrollmentId);
    expect(openEnrollmentReturn(a)).toEqual(s);
  });
  it("rejects tampering, changed key, expired boundary, future issuance and oversized input", () => {
    const s = state(),
      a = sealEnrollmentReturn(s);
    expect(openEnrollmentReturn(a.slice(0, -8) + "aaaaaaaa")).toBeUndefined();
    expect(openEnrollmentReturn(a, s.expiresAt)).toBeUndefined();
    expect(openEnrollmentReturn(a, s.issuedAt - 1)).toBeUndefined();
    expect(openEnrollmentReturn("a".repeat(4097))).toBeUndefined();
    vi.stubEnv("PAYPM_WORKFORCE_FLOW_KEY_BASE64", Buffer.alloc(32, 4).toString("base64"));
    expect(openEnrollmentReturn(a)).toBeUndefined();
  });
  it("cannot reuse an action-proof cookie as enrollment routing context", () => {
    const now = Date.now();
    expect(
      openEnrollmentReturn(
        encryptActionState({
          requestId: "oidc_old",
          baseSessionId: "1",
          stepSessionId: "2",
          stepSessionToken: "synthetic",
          userId: "3",
          clientId: "staff-client",
          challenge: "4",
          issuedAt: now,
          expiresAt: now + 60000,
        }),
      ),
    ).toBeUndefined();
  });
  it.each(["extra", "credential", "sessionId"])("rejects extra field %s before cookie issuance", (field) => {
    expect(() => sealEnrollmentReturn({ ...state(), [field]: "synthetic-only" })).toThrow();
  });
  it("sets bounded HttpOnly Secure SameSite navigation cookie in production", async () => {
    vi.stubEnv("NODE_ENV", "production");
    const s = state();
    await writeEnrollmentReturn(s);
    expect(jar.set).toHaveBeenCalledWith(
      expect.objectContaining({ httpOnly: true, secure: true, sameSite: "lax", path: "/", maxAge: 300 }),
    );
    jar.get.mockReturnValue({ value: jar.set.mock.calls[0][0].value });
    expect(await readEnrollmentReturn()).toEqual({ present: true, state: s });
    await clearEnrollmentReturn(randomUUID());
    expect(jar.delete).not.toHaveBeenCalled();
    await clearEnrollmentReturn(s.enrollmentId);
    expect(jar.delete).toHaveBeenCalledOnce();
  });
  it("distinguishes missing from invalid cookie so a forged hint cannot fall through", async () => {
    expect(await readEnrollmentReturn()).toEqual({ present: false, state: undefined });
    jar.get.mockReturnValue({ value: "forged" });
    expect(await readEnrollmentReturn()).toEqual({ present: true, state: undefined });
  });
});
