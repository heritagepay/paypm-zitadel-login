"use server";
import { create, type Duration } from "@zitadel/client";
import { RequestChallengesSchema, UserVerificationRequirement } from "@zitadel/proto/zitadel/session/v2/challenge_pb";
import { ChecksSchema, type Checks } from "@zitadel/proto/zitadel/session/v2/session_service_pb";
import { createHash } from "crypto";
import { headers } from "next/headers";
import { providerTimestampMs, sessionExpiresAt, sessionLifetime, verifiedFactor } from "../authentication-policy";
import { getSessionCookieById } from "../cookies";
import { getServiceConfig } from "../service-url";
import { deleteActionState, encryptActionState, getActionState, storeActionState } from "../workforce-action-state";
import { workforceIdentityRequest } from "../workforce-identity-client";
import { workforceEligible, workforcePolicy } from "../workforce-policy";
import { readWorkforceState } from "../workforce-state";
import { createSessionFromChecksAndChallenges, getSession, getUserByID, setSession } from "../zitadel";
type JsonObject = NonNullable<NonNullable<Checks["webAuthN"]>["credentialAssertionData"]>;

const unavailable = () => ({ error: "Workforce action verification unavailable" });
function originPolicy() {
  const origin = process.env.PAYPM_WORKFORCE_PASSKEY_ORIGIN,
    rpId = process.env.PAYPM_WORKFORCE_PASSKEY_RP_ID;
  if (!origin || !rpId) throw new Error("Passkey policy unavailable");
  const parsed = new URL(origin);
  if (parsed.origin !== origin || parsed.hostname !== rpId || parsed.protocol !== "https:")
    throw new Error("Passkey policy unavailable");
  return { origin, rpId };
}
function assertionValid(assertion: JsonObject, challenge: string) {
  try {
    const { origin, rpId } = originPolicy();
    const response = assertion.response;
    if (
      !response ||
      typeof response !== "object" ||
      Array.isArray(response) ||
      typeof response.clientDataJSON !== "string" ||
      typeof response.authenticatorData !== "string"
    )
      return false;
    const data = JSON.parse(Buffer.from(response.clientDataJSON, "base64url").toString("utf8"));
    const auth = Buffer.from(response.authenticatorData, "base64url");
    return (
      data.type === "webauthn.get" &&
      data.origin === origin &&
      data.challenge === challenge &&
      data.crossOrigin !== true &&
      auth.length >= 37 &&
      (auth[32] & 5) === 5 &&
      auth.subarray(0, 32).equals(createHash("sha256").update(rpId).digest())
    );
  } catch {
    return false;
  }
}
async function baseContext() {
  const policy = workforcePolicy(),
    flow = await readWorkforceState();
  if (!policy || !flow || flow.purpose !== "limited-admission" || !policy.clientIds.includes(flow.clientId))
    throw new Error("Admitted workforce session required");
  const cookie = await getSessionCookieById({ sessionId: flow.sessionId });
  if (!cookie || cookie.requestId !== flow.requestId) throw new Error("Admitted workforce session required");
  const { serviceConfig } = getServiceConfig(await headers());
  const { session } = await getSession({ serviceConfig, sessionId: cookie.id, sessionToken: cookie.token });
  if (
    !session ||
    session.factors?.user?.id !== flow.userId ||
    session.factors.user.organizationId !== policy.organizationId ||
    !sessionExpiresAt(session) ||
    !verifiedFactor(session, session.factors.otpEmail?.verifiedAt)
  )
    throw new Error("Admitted workforce session required");
  const { user } = await getUserByID({ serviceConfig, userId: flow.userId });
  if (!user || !(await workforceEligible(user, flow.clientId, "login")))
    throw new Error("Current workforce admission required");
  return { policy, flow, session, serviceConfig };
}
export async function startWorkforceAction(command: {
  action: string;
  payloadHash: string;
  appId: string;
  deploymentId: string;
  environment: "production" | "staging" | "sandbox";
}) {
  try {
    const { rpId } = originPolicy();
    if (!/^identity\.[a-z][a-z0-9.]{1,160}$/.test(command.action) || !/^([a-f0-9]{64})$/.test(command.payloadHash))
      return unavailable();
    const { policy, flow, serviceConfig } = await baseContext();
    const issuedAt = Date.now();
    encryptActionState({
      requestId: "pending",
      baseSessionId: flow.sessionId,
      stepSessionId: "pending",
      stepSessionToken: "pending",
      userId: flow.userId,
      clientId: flow.clientId,
      challenge: "pending",
      issuedAt,
      expiresAt: issuedAt + 300000,
    });
    const created = await createSessionFromChecksAndChallenges({
      serviceConfig,
      checks: create(ChecksSchema, { user: { search: { case: "userId", value: flow.userId } } }),
      challenges: create(RequestChallengesSchema, {
        webAuthN: { domain: rpId, userVerificationRequirement: UserVerificationRequirement.REQUIRED },
      }),
      lifetime: sessionLifetime({ seconds: BigInt(300), nanos: 0 } as Duration),
    });
    const options = created.challenges?.webAuthN?.publicKeyCredentialRequestOptions as JsonObject | undefined;
    const publicKey = options?.publicKey;
    if (
      !created.sessionId ||
      !created.sessionToken ||
      !publicKey ||
      typeof publicKey !== "object" ||
      Array.isArray(publicKey) ||
      typeof publicKey.challenge !== "string" ||
      publicKey.rpId !== rpId ||
      publicKey.userVerification !== "required"
    )
      return unavailable();
    const result = await workforceIdentityRequest("internal/v1/workforce-action-proofs/requests", {
      providerSubject: flow.userId,
      baseSessionId: flow.sessionId,
      stepSessionId: created.sessionId,
      clientId: flow.clientId,
      contextId: policy.organizationId,
      ...command,
      challenge: publicKey.challenge,
    });
    if (!result || typeof result !== "object" || !("requestId" in result) || typeof result.requestId !== "string")
      return unavailable();
    await storeActionState({
      requestId: result.requestId,
      baseSessionId: flow.sessionId,
      stepSessionId: created.sessionId,
      stepSessionToken: created.sessionToken,
      userId: flow.userId,
      clientId: flow.clientId,
      challenge: publicKey.challenge,
      issuedAt,
      expiresAt: issuedAt + 300000,
    });
    return { requestId: result.requestId, publicKey, expiresAt: new Date(issuedAt + 300000).toISOString() };
  } catch {
    return unavailable();
  }
}
export async function completeWorkforceAction(command: { requestId: string; assertion: JsonObject }) {
  try {
    const state = await getActionState();
    if (!state || state.requestId !== command.requestId || !assertionValid(command.assertion, state.challenge))
      return unavailable();
    const { flow, serviceConfig } = await baseContext();
    if (state.baseSessionId !== flow.sessionId || state.userId !== flow.userId || state.clientId !== flow.clientId)
      return unavailable();
    const accepted = await setSession({
      serviceConfig,
      sessionId: state.stepSessionId,
      sessionToken: state.stepSessionToken,
      challenges: undefined,
      checks: create(ChecksSchema, { webAuthN: { credentialAssertionData: command.assertion } }),
      lifetime: sessionLifetime({ seconds: BigInt(300), nanos: 0 } as Duration),
    });
    if (!accepted.sessionToken) return unavailable();
    const { session } = await getSession({
      serviceConfig,
      sessionId: state.stepSessionId,
      sessionToken: accepted.sessionToken,
    });
    const verified = providerTimestampMs(session?.factors?.webAuthN?.verifiedAt);
    if (
      !session ||
      session.factors?.user?.id !== state.userId ||
      session.factors.webAuthN?.userVerified !== true ||
      !verifiedFactor(session, session.factors.webAuthN.verifiedAt) ||
      verified === undefined ||
      verified < state.issuedAt ||
      Date.now() - verified > 60000
    )
      return unavailable();
    const result = await workforceIdentityRequest(
      `internal/v1/workforce-action-proofs/requests/${state.requestId}/complete`,
      { assertion: command.assertion },
    );
    if (
      !result ||
      typeof result !== "object" ||
      !("receipt" in result) ||
      typeof result.receipt !== "string" ||
      !result.receipt.startsWith("paypm-wf1.") ||
      !("expiresAt" in result) ||
      typeof result.expiresAt !== "string"
    )
      return unavailable();
    await deleteActionState();
    return { receipt: result.receipt, expiresAt: result.expiresAt };
  } catch {
    return unavailable();
  }
}
