import { UserVerificationRequirement } from "@zitadel/proto/zitadel/session/v2/challenge_pb";
import { createHash } from "crypto";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import {
  approveLegacyMigration,
  canonicalLegacy,
  legacyIdentityRequest,
  legacyMigrationContext,
  obtainLegacyEligibility,
  type LegacyMigrationEligibility,
} from "../legacy-commercial-migration-client";
import {
  deleteLegacyMigrationState,
  getLegacyMigrationState,
  storeLegacyMigrationState,
} from "../legacy-commercial-migration-state";
import { createSessionFromChecksAndChallenges, getSession, setSession } from "../zitadel";
import { completeLegacyCommercialMigration, startLegacyCommercialMigration } from "./legacy-commercial-migration";
vi.mock("next/headers", () => ({ headers: () => new Headers({ origin: "https://login.paypm.test" }) }));
vi.mock("../service-url", () => ({ getServiceConfig: () => ({ serviceConfig: { baseUrl: "https://auth.paypm.test" } }) }));
vi.mock("../zitadel", () => ({ createSessionFromChecksAndChallenges: vi.fn(), getSession: vi.fn(), setSession: vi.fn() }));
vi.mock("../legacy-commercial-migration-client", async (original) => ({
  ...(await original<typeof import("../legacy-commercial-migration-client")>()),
  approveLegacyMigration: vi.fn(),
  legacyIdentityRequest: vi.fn(),
  legacyMigrationContext: vi.fn(),
  obtainLegacyEligibility: vi.fn(),
}));
vi.mock("../legacy-commercial-migration-state", async (original) => ({
  ...(await original<typeof import("../legacy-commercial-migration-state")>()),
  deleteLegacyMigrationState: vi.fn(),
  getLegacyMigrationState: vi.fn(),
  storeLegacyMigrationState: vi.fn(),
}));
const id = "11111111-1111-4111-8111-111111111111",
  challenge = Buffer.from("actual-original-provider-challenge-123").toString("base64url");
const eligibility: LegacyMigrationEligibility = {
  version: 1,
  eligibilityId: id,
  operationKey: id,
  personId: id,
  legacyAuthentication: {
    issuer: "https://auth.paypm.test",
    subject: "700",
    clientId: "merchant@paypm",
    tokenId: "access-jti",
  },
  authentication: { issuer: "https://access.paypm.test", subject: id },
  appId: "merchant_mobile",
  deploymentId: "heritagepay",
  environment: "sandbox",
  businessId: id,
  contactProofId: id,
  action: "merchant.auth.migration.approve",
  payloadHash: "a".repeat(64),
  issuedAt: "2026-10-03T14:00:00.000Z",
  expiresAt: "2026-10-03T14:05:00.000Z",
};
const command = {
  operationKey: id,
  originalAccessToken: "old-access-never-return",
  businessId: id,
  appId: "merchant_mobile",
  deploymentId: "heritagepay",
  environment: "sandbox" as const,
  authentication: eligibility.authentication,
  contactProof: { flowId: id, proofId: id, sessionToken: "new-session-never-return" },
};
const state = () => ({
  requestId: id,
  proofSessionId: "800",
  proofSessionToken: "proof-session-never-return",
  challenge,
  eligibility,
  issuedAt: Date.now() - 2000,
  expiresAt: Date.now() + 270000,
});
const time = (offset: number) => ({ seconds: BigInt(Math.floor((Date.now() + offset) / 1000)), nanos: 0 });
const session = () => ({
  id: "800",
  creationDate: time(-1000),
  expirationDate: time(270000),
  factors: {
    user: { id: "700", organizationId: "999", verifiedAt: time(-1000) },
    webAuthN: { verifiedAt: time(0), userVerified: true },
  },
});
function assertion() {
  const flags = Buffer.alloc(37);
  createHash("sha256").update("login.paypm.test").digest().copy(flags);
  flags[32] = 5;
  return {
    id: "actual-key",
    rawId: "actual-key",
    type: "public-key",
    response: {
      clientDataJSON: Buffer.from(
        JSON.stringify({ type: "webauthn.get", challenge, origin: "https://login.paypm.test" }),
      ).toString("base64url"),
      authenticatorData: flags.toString("base64url"),
      signature: "provider-verifies",
      userHandle: null,
    },
  };
}
beforeEach(() => {
  vi.resetAllMocks();
  vi.useFakeTimers();
  vi.setSystemTime(new Date("2026-10-03T14:00:30Z"));
  vi.stubEnv("PAYPM_LEGACY_MIGRATION_FLOW_KEY_BASE64", Buffer.alloc(32, 15).toString("base64"));
  vi.mocked(legacyMigrationContext).mockReturnValue({
    appId: command.appId,
    deploymentId: command.deploymentId,
    environment: command.environment,
    clientIds: ["merchant@paypm"],
    backendUrl: "https://api.paypm.test",
    backendApiKey: "fixture-prove".repeat(4),
    backendSigningKey: "fixture-prove-key".repeat(4),
    backendApprovalApiKey: "fixture-approve".repeat(4),
    backendApprovalSigningKey: "fixture-approve-key".repeat(4),
    rpId: "login.paypm.test",
    origin: "https://login.paypm.test",
  });
  vi.mocked(obtainLegacyEligibility).mockResolvedValue(eligibility);
  vi.mocked(createSessionFromChecksAndChallenges).mockResolvedValue({
    sessionId: "800",
    sessionToken: "proof-session-never-return",
    challenges: {
      webAuthN: {
        publicKeyCredentialRequestOptions: {
          publicKey: { challenge, rpId: "login.paypm.test", userVerification: "required" },
        },
      },
    },
  } as any);
  vi.mocked(legacyIdentityRequest).mockResolvedValue({
    requestId: id,
    receipt: "paypm-lc1.valid.fixture",
    expiresAt: new Date(Date.now() + 60000).toISOString(),
  });
  vi.mocked(getLegacyMigrationState).mockResolvedValue(state());
  vi.mocked(setSession).mockResolvedValue({ sessionToken: "accepted-session-never-return" } as any);
  vi.mocked(getSession).mockResolvedValue({ session: session() } as any);
  vi.mocked(approveLegacyMigration).mockResolvedValue({
    decisionId: id,
    state: "approved",
    proofKind: "legacy_zitadel_passkey",
  });
});
afterEach(() => {
  vi.useRealTimers();
  vi.unstubAllEnvs();
});
describe("separate original commercial migration ceremony", () => {
  it("uses original owning eligibility and REQUIRED-UV provider ceremony without workforce grants or returned tokens", async () => {
    const result = await startLegacyCommercialMigration(command);
    expect(result).toMatchObject({ requestId: id, publicKey: { challenge, userVerification: "required" } });
    expect(createSessionFromChecksAndChallenges).toHaveBeenCalledWith(
      expect.objectContaining({
        checks: expect.objectContaining({ user: expect.objectContaining({ search: { case: "userId", value: "700" } }) }),
        challenges: expect.objectContaining({
          webAuthN: expect.objectContaining({ userVerificationRequirement: UserVerificationRequirement.REQUIRED }),
        }),
      }),
    );
    expect(JSON.stringify(result)).not.toContain("never-return");
    expect(legacyIdentityRequest).toHaveBeenCalledWith("internal/v1/legacy-commercial-action-proofs/requests", {
      eligibility,
      proofSessionId: "800",
      challenge,
    });
  });
  it("does not create a provider challenge when current original ownership is unavailable", async () => {
    vi.mocked(obtainLegacyEligibility).mockRejectedValue(new Error("revoked"));
    expect(await startLegacyCommercialMigration(command)).toHaveProperty("error");
    expect(createSessionFromChecksAndChallenges).not.toHaveBeenCalled();
  });
  it("forwards exact assertion, checks fresh accepted provider proof and obtains durable owning approval", async () => {
    const exact = assertion();
    expect(await completeLegacyCommercialMigration({ requestId: id, assertion: exact })).toEqual({
      decision: { decisionId: id, state: "approved", proofKind: "legacy_zitadel_passkey" },
    });
    expect(setSession).toHaveBeenCalledWith(
      expect.objectContaining({
        sessionId: "800",
        checks: expect.objectContaining({ webAuthN: expect.objectContaining({ credentialAssertionData: exact }) }),
      }),
    );
    expect(approveLegacyMigration).toHaveBeenCalledWith("paypm-lc1.valid.fixture", eligibility);
    expect(storeLegacyMigrationState).toHaveBeenCalledWith(
      expect.objectContaining({ assertionHash: createHash("sha256").update(canonicalLegacy(exact)).digest("hex") }),
    );
    expect(deleteLegacyMigrationState).toHaveBeenCalled();
  });
  it("retries the same already accepted provider assertion without inventing another ceremony", async () => {
    const exact = assertion();
    vi.mocked(getLegacyMigrationState).mockResolvedValue({
      ...state(),
      assertionHash: createHash("sha256").update(canonicalLegacy(exact)).digest("hex"),
    });
    expect(await completeLegacyCommercialMigration({ requestId: id, assertion: exact })).toHaveProperty("decision");
    expect(setSession).not.toHaveBeenCalled();
  });
  it.each(["provider rejection", "wrong subject", "missing UV", "stale factor"])(
    "denies %s before owning approval",
    async (which) => {
      if (which === "provider rejection") vi.mocked(setSession).mockRejectedValue(new Error("reject"));
      else {
        const current = session();
        if (which === "wrong subject") current.factors.user.id = "701";
        if (which === "missing UV") current.factors.webAuthN.userVerified = false;
        if (which === "stale factor") current.factors.webAuthN.verifiedAt = time(-61000);
        vi.mocked(getSession).mockResolvedValue({ session: current } as any);
      }
      expect(await completeLegacyCommercialMigration({ requestId: id, assertion: assertion() })).toHaveProperty("error");
      expect(approveLegacyMigration).not.toHaveBeenCalled();
    },
  );
  it.each(["UP only", "changed challenge", "wrong origin"])(
    "denies signed assertion %s before provider completion",
    async (which) => {
      const proof = assertion();
      if (which === "UP only") {
        const flags = Buffer.from(proof.response.authenticatorData, "base64url");
        flags[32] = 1;
        proof.response.authenticatorData = flags.toString("base64url");
      } else
        proof.response.clientDataJSON = Buffer.from(
          JSON.stringify({
            type: "webauthn.get",
            challenge: which === "changed challenge" ? "wrong" : challenge,
            origin: which === "wrong origin" ? "https://other.test" : "https://login.paypm.test",
          }),
        ).toString("base64url");
      expect(await completeLegacyCommercialMigration({ requestId: id, assertion: proof })).toHaveProperty("error");
      expect(setSession).not.toHaveBeenCalled();
    },
  );
});
