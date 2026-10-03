"use server";
import { create, type Duration } from "@zitadel/client";
import { RequestChallengesSchema, UserVerificationRequirement } from "@zitadel/proto/zitadel/session/v2/challenge_pb";
import { ChecksSchema, type Checks } from "@zitadel/proto/zitadel/session/v2/session_service_pb";
import { createHash } from "crypto";
import { headers } from "next/headers";
import { providerTimestampMs, sessionExpiresAt, sessionLifetime, verifiedFactor } from "../authentication-policy";
import {
  approveLegacyMigration,
  canonicalLegacy,
  legacyIdentityRequest,
  legacyMigrationContext,
  obtainLegacyEligibility,
  type LegacyMigrationCommand,
} from "../legacy-commercial-migration-client";
import {
  deleteLegacyMigrationState,
  encryptLegacyMigrationState,
  getLegacyMigrationState,
  storeLegacyMigrationState,
} from "../legacy-commercial-migration-state";
import { getServiceConfig } from "../service-url";
import { createSessionFromChecksAndChallenges, getSession, setSession } from "../zitadel";
type JsonObject = NonNullable<NonNullable<Checks["webAuthN"]>["credentialAssertionData"]>;
const unavailable = () => ({ error: "Original commercial account verification unavailable" });
async function services(scope: { appId: string; deploymentId: string; environment: string }) {
  const context = legacyMigrationContext(scope),
    h = await headers();
  if (h.get("origin") !== context.origin) throw new Error("Original commercial proof origin denied");
  return { context, ...getServiceConfig(h) };
}
function validAssertion(assertion: JsonObject, challenge: string, rpId: string, origin: string) {
  try {
    const r = assertion.response;
    if (
      !r ||
      typeof r !== "object" ||
      Array.isArray(r) ||
      typeof r.clientDataJSON !== "string" ||
      typeof r.authenticatorData !== "string"
    )
      return false;
    const d = JSON.parse(Buffer.from(r.clientDataJSON, "base64url").toString("utf8")),
      auth = Buffer.from(r.authenticatorData, "base64url");
    return (
      d.type === "webauthn.get" &&
      d.challenge === challenge &&
      d.origin === origin &&
      d.crossOrigin !== true &&
      auth.length >= 37 &&
      (auth[32] & 5) === 5 &&
      auth.subarray(0, 32).equals(createHash("sha256").update(rpId).digest())
    );
  } catch {
    return false;
  }
}
export async function startLegacyCommercialMigration(command: LegacyMigrationCommand) {
  try {
    const { context, serviceConfig } = await services(command),
      eligibility = await obtainLegacyEligibility(command),
      issuedAt = Date.now(),
      expiresAt = Math.min(Date.parse(eligibility.expiresAt), issuedAt + 300000);
    encryptLegacyMigrationState({
      requestId: "pending",
      proofSessionId: "pending",
      proofSessionToken: "pending",
      challenge: "pending",
      eligibility,
      issuedAt,
      expiresAt,
    });
    const created = await createSessionFromChecksAndChallenges({
      serviceConfig,
      checks: create(ChecksSchema, {
        user: { search: { case: "userId", value: eligibility.legacyAuthentication.subject } },
      }),
      challenges: create(RequestChallengesSchema, {
        webAuthN: { domain: context.rpId, userVerificationRequirement: UserVerificationRequirement.REQUIRED },
      }),
      lifetime: sessionLifetime({ seconds: BigInt(300), nanos: 0 } as Duration),
    });
    const options = created.challenges?.webAuthN?.publicKeyCredentialRequestOptions as JsonObject | undefined,
      key = options?.publicKey;
    if (
      !created.sessionId ||
      !created.sessionToken ||
      !key ||
      typeof key !== "object" ||
      Array.isArray(key) ||
      typeof key.challenge !== "string" ||
      key.rpId !== context.rpId ||
      key.userVerification !== "required"
    )
      return unavailable();
    const result = await legacyIdentityRequest("internal/v1/legacy-commercial-action-proofs/requests", {
      eligibility,
      proofSessionId: created.sessionId,
      challenge: key.challenge,
    });
    if (!result || typeof result !== "object" || !("requestId" in result) || typeof result.requestId !== "string")
      return unavailable();
    await storeLegacyMigrationState({
      requestId: result.requestId,
      proofSessionId: created.sessionId,
      proofSessionToken: created.sessionToken,
      challenge: key.challenge,
      eligibility,
      issuedAt,
      expiresAt,
    });
    return { requestId: result.requestId, publicKey: key, expiresAt: new Date(expiresAt).toISOString() };
  } catch {
    return unavailable();
  }
}
export async function completeLegacyCommercialMigration(command: { requestId: string; assertion: JsonObject }) {
  try {
    const state = await getLegacyMigrationState();
    if (!state || state.requestId !== command.requestId) return unavailable();
    const { context, serviceConfig } = await services(state.eligibility);
    if (!validAssertion(command.assertion, state.challenge, context.rpId, context.origin)) return unavailable();
    const assertionHash = createHash("sha256").update(canonicalLegacy(command.assertion)).digest("hex");
    if (state.assertionHash && state.assertionHash !== assertionHash) return unavailable();
    let token = state.proofSessionToken;
    if (!state.assertionHash) {
      const accepted = await setSession({
        serviceConfig,
        sessionId: state.proofSessionId,
        sessionToken: token,
        challenges: undefined,
        checks: create(ChecksSchema, { webAuthN: { credentialAssertionData: command.assertion } }),
        lifetime: sessionLifetime({ seconds: BigInt(300), nanos: 0 } as Duration),
      });
      if (!accepted.sessionToken) return unavailable();
      token = accepted.sessionToken;
      await storeLegacyMigrationState({ ...state, proofSessionToken: token, assertionHash });
    }
    const { session } = await getSession({ serviceConfig, sessionId: state.proofSessionId, sessionToken: token }),
      verified = providerTimestampMs(session?.factors?.webAuthN?.verifiedAt),
      expires = session && sessionExpiresAt(session);
    if (
      !session ||
      session.factors?.user?.id !== state.eligibility.legacyAuthentication.subject ||
      session.factors.webAuthN?.userVerified !== true ||
      !verifiedFactor(session, session.factors.webAuthN.verifiedAt) ||
      verified === undefined ||
      verified < state.issuedAt ||
      Date.now() - verified > 60000 ||
      !expires ||
      expires > Date.now() + 300000
    )
      return unavailable();
    const result = await legacyIdentityRequest(
      `internal/v1/legacy-commercial-action-proofs/requests/${state.requestId}/complete`,
      { assertion: command.assertion },
    );
    if (
      !result ||
      typeof result !== "object" ||
      !("receipt" in result) ||
      typeof result.receipt !== "string" ||
      !result.receipt.startsWith("paypm-lc1.")
    )
      return unavailable();
    const decision = await approveLegacyMigration(result.receipt, state.eligibility);
    await deleteLegacyMigrationState();
    return { decision };
  } catch {
    return unavailable();
  }
}
