// @vitest-environment node
import { randomUUID } from "node:crypto";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { retireLegacyRecoveryProfile, type LegacyRecoveryContext } from "./legacy-recovery-retirement";
import { workforceStore } from "./workforce-store";
vi.mock("./workforce-store", () => ({ workforceStore: vi.fn() }));
const caseId = randomUUID(),
  decisionId = randomUUID(),
  evidenceId = randomUUID();
const context: LegacyRecoveryContext = {
  version: 1,
  caseId,
  decisionId,
  revision: 1,
  personId: randomUUID(),
  originalAuthentication: { issuer: "https://auth.paypm.test", subject: "12345" },
  target: { issuer: "https://access.paypm.test", contactType: "phone", contactHash: "a".repeat(64) },
  appId: "wallet_mobile",
  deploymentId: "heritagepay",
  environment: "production",
  contextId: "wallet-owner-review",
  reviewerPersonId: randomUUID(),
  makerPersonId: randomUUID(),
  proofId: randomUUID(),
  caseHash: "b".repeat(64),
  checkedAt: new Date().toISOString(),
};
const caller = "synthetic-legacy-recovery-caller-purpose-key-12345";
let currentContext: LegacyRecoveryContext,
  state: string,
  organization: string,
  machine: boolean,
  mutations: number,
  uncertain: boolean,
  contextReads: number;
let store: {
  reserveLegacyRetirement: ReturnType<typeof vi.fn>;
  claimLegacyRetirement: ReturnType<typeof vi.fn>;
  legacyRetirementConfirmed: ReturnType<typeof vi.fn>;
};
const request = (body: unknown = { caseId, decisionId }, bearer = caller) =>
  new Request("https://login.paypm.test/api/internal/v1/recovery/legacy-retirements", {
    method: "POST",
    headers: { authorization: "Bearer " + bearer },
    body: JSON.stringify(body),
  });
beforeEach(() => {
  vi.resetAllMocks();
  state = "USER_STATE_ACTIVE";
  organization = "200";
  machine = false;
  mutations = 0;
  uncertain = false;
  contextReads = 0;
  currentContext = { ...context, checkedAt: new Date().toISOString() };
  for (const [key, value] of Object.entries({
    PAYPM_LEGACY_RECOVERY_CALLER_TOKEN: caller,
    PAYPM_LEGACY_RECOVERY_ISSUER: "https://auth.paypm.test",
    PAYPM_WORKFORCE_ORGANIZATION_ID: "300",
    PAYPM_LEGACY_RECOVERY_SERVICE_ORGANIZATION_ID: "400",
    PAYPM_LEGACY_RECOVERY_CONTEXTS_JSON: JSON.stringify([
      {
        appId: context.appId,
        deploymentId: context.deploymentId,
        environment: context.environment,
        organizationIds: ["200"],
      },
    ]),
    PAYPM_LEGACY_RECOVERY_IDENTITY_URL: "https://identity.paypm.test/",
    PAYPM_LEGACY_RECOVERY_IDENTITY_TOKEN_URL: "https://auth.paypm.test/oauth/v2/token",
    PAYPM_LEGACY_RECOVERY_IDENTITY_CLIENT_ID: "review-reader",
    PAYPM_LEGACY_RECOVERY_IDENTITY_CLIENT_SECRET: "synthetic-reader-secret",
    PAYPM_LEGACY_RECOVERY_IDENTITY_SCOPES: "identity.directory.read",
    PAYPM_LEGACY_RECOVERY_PROVIDER_TOKEN_URL: "https://auth.paypm.test/oauth/v2/token",
    PAYPM_LEGACY_RECOVERY_PROVIDER_CLIENT_ID: "commercial-retirement",
    PAYPM_LEGACY_RECOVERY_PROVIDER_CLIENT_SECRET: "synthetic-distinct-retirement-secret",
    PAYPM_LEGACY_RECOVERY_PROVIDER_SCOPES: "urn:zitadel:iam:org:project:id:zitadel:aud",
  }))
    vi.stubEnv(key, value);
  store = {
    reserveLegacyRetirement: vi.fn().mockResolvedValue({ id: evidenceId, state: "pending" }),
    claimLegacyRetirement: vi.fn().mockResolvedValue(true),
    legacyRetirementConfirmed: vi.fn().mockResolvedValue(undefined),
  };
  vi.mocked(workforceStore).mockReturnValue(store as never);
  vi.stubGlobal(
    "fetch",
    vi.fn(async (input: string | URL) => {
      const url = new URL(input);
      if (url.pathname === "/oauth/v2/token") return Response.json({ access_token: "synthetic-private-machine-token" });
      if (url.pathname.endsWith("/legacy-revocation-context")) {
        contextReads++;
        return Response.json({ ...currentContext, checkedAt: new Date().toISOString() });
      }
      if (url.pathname === "/v2/users/12345/deactivate") {
        mutations++;
        state = "USER_STATE_INACTIVE";
        if (uncertain) throw new Error("response lost");
        return Response.json({});
      }
      if (url.pathname === "/v2/users/12345")
        return Response.json({
          user: {
            userId: "12345",
            state,
            details: { resourceOwner: organization },
            ...(machine ? { machine: {} } : { human: { profile: {} } }),
          },
        });
      throw new Error("Unregistered transport");
    }),
  );
});
afterEach(() => {
  vi.unstubAllEnvs();
  vi.unstubAllGlobals();
});
describe("governed original commercial ZITADEL profile retirement", () => {
  it("reserves durable intent before mutation then confirms current inactive profile under exact canonical case", async () => {
    const result = await retireLegacyRecoveryProfile(request());
    expect(result.status).toBe(200);
    expect(await result.json()).toMatchObject({
      revocationEvidenceId: evidenceId,
      caseId,
      decisionId,
      personId: context.personId,
      originalAuthentication: context.originalAuthentication,
      appId: context.appId,
      deploymentId: context.deploymentId,
      environment: context.environment,
      kind: "legacy_profile_retired",
    });
    expect(mutations).toBe(1);
    expect(contextReads).toBe(2);
    expect(store.reserveLegacyRetirement).toHaveBeenCalledWith(
      caseId,
      decisionId,
      expect.stringMatching(/^[a-f0-9]{64}$/),
      expect.objectContaining({ caseHash: context.caseHash }),
      context.originalAuthentication.subject,
      "200",
    );
    expect(store.legacyRetirementConfirmed).toHaveBeenCalledWith(evidenceId);
  });
  it("reads uncertain provider outcome and does not mutate again on a retired response-lost retry", async () => {
    uncertain = true;
    expect((await retireLegacyRecoveryProfile(request())).status).toBe(200);
    expect(mutations).toBe(1);
    store.reserveLegacyRetirement.mockResolvedValue({ id: evidenceId, state: "retired" });
    expect((await retireLegacyRecoveryProfile(request())).status).toBe(200);
    expect(mutations).toBe(1);
  });
  it.each(["300", "400", "999"])("excludes workforce, service and unregistered organization %s", async (org) => {
    organization = org;
    expect((await retireLegacyRecoveryProfile(request())).status).toBe(503);
    expect(mutations).toBe(0);
    expect(store.reserveLegacyRetirement).not.toHaveBeenCalled();
  });
  it("denies machine accounts, mixed-profile registry, absent policy and restored retired profile", async () => {
    machine = true;
    expect((await retireLegacyRecoveryProfile(request())).status).toBe(503);
    machine = false;
    vi.stubEnv(
      "PAYPM_LEGACY_RECOVERY_CONTEXTS_JSON",
      JSON.stringify([
        {
          appId: context.appId,
          deploymentId: context.deploymentId,
          environment: context.environment,
          organizationIds: ["200", "300"],
        },
      ]),
    );
    expect((await retireLegacyRecoveryProfile(request())).status).toBe(503);
    vi.stubEnv("PAYPM_LEGACY_RECOVERY_CONTEXTS_JSON", "[]");
    expect((await retireLegacyRecoveryProfile(request())).status).toBe(503);
    expect(mutations).toBe(0);
  });
  it("rejects a case mismatch, self-review, arbitrary actor/issuer and caller credential substitution", async () => {
    for (const change of [
      { caseId: randomUUID() },
      { reviewerPersonId: context.personId },
      { originalAuthentication: { issuer: "https://other.paypm.test", subject: "12345" } },
      { environment: "sandbox" },
    ]) {
      currentContext = { ...context, ...change } as LegacyRecoveryContext;
      expect((await retireLegacyRecoveryProfile(request())).status).toBe(503);
    }
    currentContext = context;
    expect((await retireLegacyRecoveryProfile(request({ caseId, decisionId, actorId: context.personId }))).status).toBe(503);
    expect((await retireLegacyRecoveryProfile(request(undefined, "wrong-purpose-token"))).status).toBe(503);
    expect(mutations).toBe(0);
  });
  it("does not mark revocation when current provider state or canonical re-read is unavailable", async () => {
    store.claimLegacyRetirement.mockResolvedValue(false);
    expect((await retireLegacyRecoveryProfile(request())).status).toBe(503);
    expect(mutations).toBe(0);
    expect(store.legacyRetirementConfirmed).not.toHaveBeenCalled();
    store.reserveLegacyRetirement.mockResolvedValue({ id: evidenceId, state: "retired" });
    expect((await retireLegacyRecoveryProfile(request())).status).toBe(503);
    expect(mutations).toBe(0);
  });
});
