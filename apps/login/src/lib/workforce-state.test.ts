import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { decodeWorkforceState, encodeWorkforceState, type WorkforceState } from "./workforce-state";

const now = 1_800_000_000_000;
const flow = (): WorkforceState => ({
  purpose: "email-challenge",
  sessionId: "provider-session",
  userId: "staff-user",
  clientId: "registered-client",
  requestId: "oidc_request",
  issuedAt: now - 1000,
  expiresAt: now + 299000,
});
beforeEach(() => vi.stubEnv("PAYPM_WORKFORCE_FLOW_KEY_BASE64", Buffer.alloc(32, 9).toString("base64")));
afterEach(() => vi.unstubAllEnvs());

describe("signed workforce flow", () => {
  it("round trips a server-issued binding", () =>
    expect(decodeWorkforceState(encodeWorkforceState(flow()), now)).toEqual(flow()));
  it.each(["userId", "sessionId", "clientId", "requestId"] as const)("rejects changed %s", (field) => {
    const [payload, signature] = encodeWorkforceState(flow()).split(".");
    const value = JSON.parse(Buffer.from(payload, "base64url").toString("utf8"));
    value[field] = "attacker-chosen";
    expect(
      decodeWorkforceState(`${Buffer.from(JSON.stringify(value)).toString("base64url")}.${signature}`, now),
    ).toBeUndefined();
  });
  it("rejects expired, future, extended and wrong-key states", () => {
    expect(decodeWorkforceState(encodeWorkforceState(flow()), now + 300000)).toBeUndefined();
    expect(decodeWorkforceState(encodeWorkforceState({ ...flow(), issuedAt: now + 1 }), now)).toBeUndefined();
    expect(decodeWorkforceState(encodeWorkforceState({ ...flow(), expiresAt: now + 300001 }), now)).toBeUndefined();
    const encoded = encodeWorkforceState(flow());
    vi.stubEnv("PAYPM_WORKFORCE_FLOW_KEY_BASE64", Buffer.alloc(32, 8).toString("base64"));
    expect(decodeWorkforceState(encoded, now)).toBeUndefined();
  });
  it("rejects absent and malformed signing configuration", () => {
    vi.stubEnv("PAYPM_WORKFORCE_FLOW_KEY_BASE64", "");
    expect(() => encodeWorkforceState(flow())).toThrow();
    expect(decodeWorkforceState("payload.signature", now)).toBeUndefined();
    vi.stubEnv("PAYPM_WORKFORCE_FLOW_KEY_BASE64", "bad-key");
    expect(() => encodeWorkforceState(flow())).toThrow();
  });
});

describe("reviewed enrollment flow isolation", () => {
  it("binds exact operation to its distinct signed purpose", () => {
    const enrollmentId = "01234567-1234-4234-9234-0123456789ab";
    const enrolled = { ...flow(), purpose: "reviewed-workforce-enrollment" as const, enrollmentId };
    expect(decodeWorkforceState(encodeWorkforceState(enrolled), now)).toEqual(enrolled);
    expect(decodeWorkforceState(encodeWorkforceState({ ...enrolled, enrollmentId: "not-operation" }), now)).toBeUndefined();
    expect(decodeWorkforceState(encodeWorkforceState({ ...flow(), enrollmentId }), now)).toBeUndefined();
  });
});
