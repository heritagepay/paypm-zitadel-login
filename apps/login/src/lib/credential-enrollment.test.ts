import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { decryptEnrollmentProof, encryptEnrollmentProof } from "./credential-enrollment";
const now = 1_800_000_000_000;
const proof = {
  sessionId: "provider-session",
  userId: "expected-user",
  code: { id: "provider-code-id", code: "provider-registration-secret" },
  expiresAt: now + 300000,
};
beforeEach(() => vi.stubEnv("PAYPM_LOGIN_ENROLLMENT_KEY_BASE64", Buffer.alloc(32, 3).toString("base64")));
afterEach(() => vi.unstubAllEnvs());
describe("provider credential enrollment proof", () => {
  it("encrypts the real provider proof instead of exposing it in a redirect or hash", () => {
    const encrypted = encryptEnrollmentProof(proof);
    expect(encrypted).not.toContain(proof.code.code);
    expect(decryptEnrollmentProof(encrypted, now)).toEqual(proof);
    expect(encryptEnrollmentProof(proof)).not.toEqual(encrypted);
  });
  it("denies tampering, expired proof and swapped secret configuration", () => {
    const encrypted = encryptEnrollmentProof(proof);
    const data = Buffer.from(encrypted, "base64url");
    data[30] ^= 1;
    expect(decryptEnrollmentProof(data.toString("base64url"), now)).toBeUndefined();
    expect(decryptEnrollmentProof(encrypted, now + 300001)).toBeUndefined();
    vi.stubEnv("PAYPM_LOGIN_ENROLLMENT_KEY_BASE64", Buffer.alloc(32, 4).toString("base64"));
    expect(decryptEnrollmentProof(encrypted, now)).toBeUndefined();
  });
  it("denies absent encryption configuration and an extended proof lifetime", () => {
    expect(decryptEnrollmentProof(encryptEnrollmentProof({ ...proof, expiresAt: now + 300001 }), now)).toBeUndefined();
    vi.stubEnv("PAYPM_LOGIN_ENROLLMENT_KEY_BASE64", "");
    expect(() => encryptEnrollmentProof(proof)).toThrow();
  });
});
