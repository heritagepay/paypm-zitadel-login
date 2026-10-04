import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { logoutIdentitySession } from "./identity-logout";
const { read, revoke, pending, retire, completed, admission } = vi.hoisted(() => ({
  read: vi.fn(),
  revoke: vi.fn(),
  pending: vi.fn(),
  retire: vi.fn(),
  completed: vi.fn(),
  admission: vi.fn(),
}));
vi.mock("next/headers", () => ({ headers: () => new Headers() }));
vi.mock("./service-url", () => ({ getServiceConfig: () => ({ serviceConfig: { baseUrl: "https://auth.paypm.test" } }) }));
vi.mock("./workforce-store", () => ({ workforceStore: () => ({ sql: {}, revocationCompleted: completed }) }));
vi.mock("./identity-admission-reader", () => ({ readIdentityAdmission: admission }));
vi.mock("./identity-logout-store", () => ({
  IdentityLogoutStore: class {
    read = read;
    revoke = revoke;
    pending = pending;
  },
}));
vi.mock("./workforce-provider", () => ({ workforceProvider: () => ({ retireOwnedSession: retire }) }));
vi.mock("./workforce-policy", () => ({
  workforcePolicy: () => ({ issuer: "https://auth.paypm.test", organizationId: "300" }),
}));
const secret = "i".repeat(40),
  input = {
    idToken: "original-signed-ID",
    accessToken: "original-access",
    nonce: "original-nonce",
    clientId: "identity@paypm",
  };
const a = {
  personId: "11111111-1111-4111-8111-111111111111",
  issuer: "https://auth.paypm.test",
  providerSubject: "700",
  baseSessionId: "900",
  clientId: input.clientId,
  contextId: "300",
  appId: "identity-administration",
  deploymentId: "heritagepay",
  environment: "sandbox",
  requestId: "oidc-request",
  challengeId: "11111111-1111-4111-8111-111111111112",
  revocationVersion: "2",
};
let row: any;
const call = (body: any = input, token = secret) =>
  logoutIdentitySession(
    new Request("https://login.paypm.test/identity/logout", {
      method: "POST",
      headers: { authorization: `Bearer ${token}` },
      body: JSON.stringify(body),
    }),
  );
beforeEach(() => {
  vi.resetAllMocks();
  vi.stubEnv("PAYPM_IDENTITY_LOGOUT_TOKEN", secret);
  vi.stubEnv("PAYPM_IDENTITY_ADMISSION_READER_TOKEN", "a".repeat(40));
  row = { admission: a, revoked_at: new Date(), provider_session_ids: ["900"] };
  revoke.mockResolvedValue(row);
  admission.mockImplementation(async () => Response.json(a));
  pending.mockResolvedValue([]);
  retire.mockResolvedValue(true);
});
afterEach(() => vi.unstubAllEnvs());
describe("distinct Identity paired logout", () => {
  it("commits local retirement before provider effects and returns only exact14 metadata", async () => {
    pending.mockResolvedValueOnce([{ provider_session_id: "900" }]).mockResolvedValue([]);
    const response = await call();
    expect(response.status).toBe(200);
    expect(revoke).toHaveBeenCalledWith(input, a);
    expect(retire).toHaveBeenCalledWith("900", "700");
    expect(revoke.mock.invocationCallOrder[0]).toBeLessThan(retire.mock.invocationCallOrder[0]);
    const result = await response.json();
    expect(Object.keys(result)).toHaveLength(14);
    expect(result.state).toBe("revoked");
    expect(result.providerRetirement).toBe("confirmed");
    expect(JSON.stringify(result)).not.toContain(input.accessToken);
    expect(response.headers.get("cache-control")).toBe("no-store");
  });
  it("accepted lost-result retry observes original without reauthenticating revoked base", async () => {
    read.mockResolvedValue(row);
    admission.mockImplementation(async () => Response.json({ active: false }, { status: 403 }));
    expect((await call()).status).toBe(200);
    expect(admission).not.toHaveBeenCalled();
    expect(revoke).not.toHaveBeenCalled();
  });
  it("provider outage retains durable local retirement and truthful pending503", async () => {
    pending.mockResolvedValue([{ provider_session_id: "900" }]);
    retire.mockRejectedValue(new Error("outage"));
    const response = await call();
    expect(response.status).toBe(503);
    expect(await response.json()).toMatchObject({ state: "revoked", providerRetirement: "pending" });
    expect(completed).not.toHaveBeenCalled();
  });
  it("never-accepted expired pair cannot retire an invented base", async () => {
    admission.mockImplementation(async () => Response.json({ active: false }, { status: 403 }));
    expect((await call()).status).toBe(403);
    expect(revoke).not.toHaveBeenCalled();
    expect(retire).not.toHaveBeenCalled();
  });
  it.each([
    "PAYPM_OPERATIONS_LOGOUT_TOKEN",
    "PAYPM_OPERATIONS_ADMISSION_READER_TOKEN",
    "PAYPM_IDENTITY_ADMISSION_READER_TOKEN",
    "PAYPM_IDENTITY_ACTION_BFF_TOKEN",
    "PAYPM_IDENTITY_ACTION_CONSUMER_TOKEN",
    "PAYPM_WORKFORCE_IDENTITY_CLIENT_SECRET",
  ])("rejects %s credential reuse before any authority effect", async (name) => {
    vi.stubEnv(name, secret);
    expect((await call()).status).toBe(403);
    expect(read).not.toHaveBeenCalled();
  });
  it("rejects caller actor/session fields and wrong purpose", async () => {
    expect((await call({ ...input, personId: a.personId })).status).toBe(403);
    expect((await call(input, "operations-purpose")).status).toBe(403);
    expect(read).not.toHaveBeenCalled();
  });
});
