import { createHash } from "node:crypto";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { logoutOperationsSession } from "./operations-logout";
import { mintOperationsRetirementProof, type OperationsRetirementAdmission } from "./operations-retirement-proof";
const { read, revoke, pending, retire, completed } = vi.hoisted(() => ({
  read: vi.fn(),
  revoke: vi.fn(),
  pending: vi.fn(),
  retire: vi.fn(),
  completed: vi.fn(),
}));
vi.mock("next/headers", () => ({ headers: () => new Headers() }));
vi.mock("./service-url", () => ({ getServiceConfig: () => ({ serviceConfig: { baseUrl: "https://auth.paypm.test" } }) }));
vi.mock("./workforce-store", () => ({ workforceStore: () => ({ sql: {}, revocationCompleted: completed }) }));
vi.mock("./operations-logout-store", () => ({
  OperationsLogoutStore: class {
    read = read;
    revoke = revoke;
    pending = pending;
  },
}));
vi.mock("./workforce-provider", () => ({ workforceProvider: () => ({ retireOwnedSession: retire }) }));
vi.mock("./workforce-policy", () => ({
  workforcePolicy: () => ({ issuer: "https://auth.paypm.test", organizationId: "300", emailOtpReady: false }),
}));
const hash = (v: string) => createHash("sha256").update(v).digest("hex"),
  secret = "l".repeat(40);
const a = (): OperationsRetirementAdmission => ({
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
let input: any, row: any;
const call = (value = input, token = secret, readback = false) =>
  logoutOperationsSession(
    new Request("https://login.paypm.test/logout", {
      method: "POST",
      headers: { authorization: "Bearer " + token },
      body: JSON.stringify(value),
    }),
    readback,
  );
beforeEach(() => {
  vi.resetAllMocks();
  vi.stubEnv("PAYPM_OPERATIONS_LOGOUT_TOKEN", secret);
  vi.stubEnv("PAYPM_OPERATIONS_RETIREMENT_PROOF_KEY_BASE64", Buffer.alloc(32, 29).toString("base64"));
  const admission = a();
  input = {
    requestId: "11111111-1111-4111-8111-111111111112",
    operationKey: "11111111-1111-4111-8111-111111111113",
    idToken: "signed-ID",
    accessToken: "original-access",
    nonce: "original-nonce",
    clientId: admission.clientId,
    retirementProof: mintOperationsRetirementProof(admission),
  };
  row = {
    request_id: input.requestId,
    operation_key: input.operationKey,
    person_id: admission.personId,
    issuer: admission.issuer,
    provider_subject: admission.providerSubject,
    base_session_id: admission.baseSessionId,
    client_id: admission.clientId,
    app_id: admission.appId,
    deployment_id: admission.deploymentId,
    environment: admission.environment,
    context_id: admission.contextId,
    revoked_at: new Date(),
  };
  read.mockResolvedValue(undefined);
  revoke.mockResolvedValue(row);
  pending.mockResolvedValue([]);
  retire.mockResolvedValue(true);
});
afterEach(() => {
  vi.unstubAllEnvs();
  vi.useRealTimers();
});
describe("paired-proof Operations logout", () => {
  it("retires captured exact historical admission after access expiry/readiness-off without granting authentication", async () => {
    vi.useFakeTimers();
    vi.advanceTimersByTime(301000);
    const response = await call();
    expect(response.status).toBe(200);
    expect(Object.keys(await response.json())).toHaveLength(15);
    expect(revoke).toHaveBeenCalledWith(
      input,
      expect.objectContaining({ personId: row.person_id, baseSessionId: "900", requestId: "original-oidc-request" }),
    );
    expect(response.headers.get("cache-control")).toBe("no-store");
  });
  it("keeps local revocation durable during provider outage then reads exact accepted outcome", async () => {
    pending.mockResolvedValue([{ provider_session_id: "900" }]);
    retire.mockRejectedValue(new Error("provider unavailable"));
    expect((await (await call()).json()).providerRetirement).toBe("pending");
    read.mockResolvedValue(row);
    pending.mockResolvedValueOnce([{ provider_session_id: "900" }]).mockResolvedValueOnce([]);
    retire.mockResolvedValue(true);
    const result = await call(input, secret, true);
    expect((await result.json()).providerRetirement).toBe("confirmed");
    expect(revoke).toHaveBeenCalledTimes(1);
    expect(retire).toHaveBeenLastCalledWith("900", "700");
    expect(completed).toHaveBeenCalledWith("900");
  });
  it.each(["wrong-purpose", "reused-purpose", "altered-pair", "altered-client", "altered-proof", "actor-field", "conflict"])(
    "denies %s without provider effects",
    async (kind) => {
      let body = { ...input },
        token = secret;
      if (kind === "wrong-purpose") token = "other";
      if (kind === "reused-purpose") vi.stubEnv("PAYPM_OPERATIONS_ACTION_BFF_TOKEN", secret);
      if (kind === "altered-pair") body.accessToken = "other-access";
      if (kind === "altered-client") body.clientId = "other-client";
      if (kind === "altered-proof") body.retirementProof += "A";
      if (kind === "actor-field") body.personId = row.person_id;
      if (kind === "conflict") read.mockRejectedValue(new Error("conflict"));
      const result = await call(body, token);
      expect(result.status).toBe(403);
      expect(revoke).not.toHaveBeenCalled();
      expect(retire).not.toHaveBeenCalled();
    },
  );
  it("distinguishes only a valid original capture's never-accepted readback for safe same-operation retry", async () => {
    const result = await call(input, secret, true);
    expect(result.status).toBe(404);
    expect(await result.json()).toEqual({ code: "operations_logout_not_found" });
    expect(revoke).not.toHaveBeenCalled();
    expect((await call({ ...input, retirementProof: "forged" }, secret, true)).status).toBe(403);
  });
});
