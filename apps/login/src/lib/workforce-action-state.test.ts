import { afterEach, describe, expect, it, vi } from "vitest";
import { decryptActionState, encryptActionState } from "./workforce-action-state";
afterEach(() => vi.unstubAllEnvs());
describe("private workforce ceremony state", () => {
  it("encrypts provider tokens with a separate purpose and denies tampering, expiry and wrong keys", () => {
    vi.stubEnv("PAYPM_WORKFORCE_FLOW_KEY_BASE64", Buffer.alloc(32, 6).toString("base64"));
    const now = Date.now(),
      state = {
        requestId: "request",
        baseSessionId: "base",
        stepSessionId: "step",
        stepSessionToken: "private-provider-token",
        userId: "700",
        clientId: "identity-client",
        challenge: "challenge",
        issuedAt: now,
        expiresAt: now + 300000,
      };
    const encoded = encryptActionState(state);
    expect(encoded).not.toContain(state.stepSessionToken);
    expect(decryptActionState(encoded, now)).toEqual(state);
    expect(decryptActionState(`${encoded.slice(0, -8)}changed`, now)).toBeUndefined();
    expect(decryptActionState(encoded, now + 300000)).toBeUndefined();
    vi.stubEnv("PAYPM_WORKFORCE_FLOW_KEY_BASE64", Buffer.alloc(32, 7).toString("base64"));
    expect(decryptActionState(encoded, now)).toBeUndefined();
  });
});
