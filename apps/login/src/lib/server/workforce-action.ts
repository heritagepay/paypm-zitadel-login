"use server";
import { create, type Duration } from "@zitadel/client";
import { RequestChallengesSchema, UserVerificationRequirement } from "@zitadel/proto/zitadel/session/v2/challenge_pb";
import { ChecksSchema, type Checks } from "@zitadel/proto/zitadel/session/v2/session_service_pb";
import { createHash } from "crypto";
import { headers } from "next/headers";
import { providerTimestampMs, sessionExpiresAt, sessionLifetime, verifiedFactor } from "../authentication-policy";
import { getSessionCookieById } from "../cookies";
import { isClassifiedError } from "../grpc/interceptors/error-classification";
import { getServiceConfig } from "../service-url";
import { deleteActionState, encryptActionState, getActionState, storeActionState } from "../workforce-action-state";
import { workforceAssertionHash } from "../workforce-assertion";
import { workforceIdentityRequest } from "../workforce-identity-client";
import { workforceEligible, workforcePolicy } from "../workforce-policy";
import { workforceProvider } from "../workforce-provider";
import { flushWorkforceRevocations } from "../workforce-revocations";
import { readWorkforceState } from "../workforce-state";
import { workforceStore } from "../workforce-store";
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
  if (
    !policy ||
    !flow?.challengeId ||
    flow.purpose !== "limited-admission" ||
    !policy.clientIds.includes(flow.clientId) ||
    !(await workforceStore().admission(flow.sessionId, flow.userId, flow.clientId, flow.requestId))
  )
    throw new Error("Admitted workforce session required");
  const cookie = await getSessionCookieById({ sessionId: flow.sessionId });
  if (!cookie || cookie.requestId !== flow.requestId) throw new Error("Admitted workforce session required");
  const { serviceConfig } = getServiceConfig(await headers());
  if (new URL(serviceConfig.baseUrl).origin !== new URL(policy.issuer).origin)
    throw new Error("Workforce provider unavailable");
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
  operationKey: string;
  action: string;
  payloadHash: string;
  appId: string;
  deploymentId: string;
  environment: "production" | "staging" | "sandbox";
}) {
  try {
    const { rpId } = originPolicy();
    if (
      !/^[a-f0-9]{8}-[a-f0-9]{4}-4[a-f0-9]{3}-[89ab][a-f0-9]{3}-[a-f0-9]{12}$/i.test(command.operationKey) ||
      !/^identity\.[a-z][a-z0-9.]{1,160}$/.test(command.action) ||
      !/^[a-f0-9]{64}$/.test(command.payloadHash) ||
      !/^[a-z][a-z0-9_.-]{0,127}$/.test(command.appId) ||
      !/^[a-z0-9_]{1,128}$/.test(command.deploymentId) ||
      !["production", "staging", "sandbox"].includes(command.environment)
    )
      return unavailable();
    const { policy, flow, serviceConfig } = await baseContext(),
      store = workforceStore();
    const scope = {
      action: command.action,
      payloadHash: command.payloadHash,
      appId: command.appId,
      deploymentId: command.deploymentId,
      environment: command.environment,
    };
    let row = await store.reserveAction({
      operationKey: command.operationKey,
      issuer: policy.issuer,
      providerSubject: flow.userId,
      baseSessionId: flow.sessionId,
      clientId: flow.clientId,
      requestId: flow.requestId,
      contextId: policy.organizationId,
      ...scope,
    });
    encryptActionState({
      requestId: "pending",
      baseSessionId: flow.sessionId,
      stepSessionId: "pending",
      stepSessionToken: "pending",
      userId: flow.userId,
      clientId: flow.clientId,
      challenge: "pending",
      issuedAt: row.created_at.getTime(),
      expiresAt: row.expires_at.getTime(),
    });
    if (row.state === "reserved") {
      if (!(await store.claimAction(row.operation_key))) {
        if (!row.provider_started_at || Date.now() - row.provider_started_at.getTime() < 10000) return unavailable();
        // A lost creation response cannot reconstruct the original public options.
        // Locate only this exact provider metadata, retire it durably, and require a new operation.
        const provider = await workforceProvider(serviceConfig, policy.organizationId);
        const orphan = await provider.findActionIntent(row.operation_key, flow.userId);
        await store.abandonAction(row.operation_key, orphan);
        await flushWorkforceRevocations(store, provider);
        return unavailable();
      }
      const created = await createSessionFromChecksAndChallenges({
        serviceConfig,
        checks: create(ChecksSchema, { user: { search: { case: "userId", value: flow.userId } } }),
        challenges: create(RequestChallengesSchema, {
          webAuthN: { domain: rpId, userVerificationRequirement: UserVerificationRequirement.REQUIRED },
        }),
        metadata: { paypm_workforce_action_intent: new TextEncoder().encode(row.operation_key) },
        timeoutMs: 5000,
        lifetime: sessionLifetime({
          seconds: BigInt(Math.floor((row.expires_at.getTime() - Date.now()) / 1000)),
          nanos: 0,
        } as Duration),
      });
      const options = created.challenges?.webAuthN?.publicKeyCredentialRequestOptions as JsonObject | undefined,
        publicKey = options?.publicKey;
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
      row = await store.actionCreated(row.operation_key, {
        sessionId: created.sessionId,
        sessionToken: created.sessionToken,
        publicKey,
      });
    }
    const material = store.actionMaterial(row);
    const result = await workforceIdentityRequest("internal/v1/workforce-action-proofs/requests", {
      providerSubject: flow.userId,
      baseSessionId: flow.sessionId,
      stepSessionId: material.sessionId,
      clientId: flow.clientId,
      contextId: policy.organizationId,
      ...scope,
      challenge: material.publicKey.challenge,
    });
    if (
      !result ||
      typeof result !== "object" ||
      !("requestId" in result) ||
      typeof result.requestId !== "string" ||
      !/^[a-f0-9-]{36}$/i.test(result.requestId)
    )
      return unavailable();
    row = await store.actionRegistered(row.operation_key, result.requestId);
    await baseContext();
    await storeActionState({
      requestId: result.requestId,
      baseSessionId: flow.sessionId,
      stepSessionId: material.sessionId,
      stepSessionToken: material.sessionToken,
      userId: flow.userId,
      clientId: flow.clientId,
      challenge: material.publicKey.challenge as string,
      issuedAt: row.created_at.getTime(),
      expiresAt: row.expires_at.getTime(),
    });
    return { requestId: result.requestId, publicKey: material.publicKey, expiresAt: row.expires_at.toISOString() };
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
    const store = workforceStore(),
      assertionHash = workforceAssertionHash(command.assertion),
      attempt = await store.passkeyAttempt(state.requestId, state.stepSessionId, assertionHash);
    let token = "";
    if (attempt.first) {
      try {
        const accepted = await setSession({
          serviceConfig,
          sessionId: state.stepSessionId,
          sessionToken: state.stepSessionToken,
          challenges: undefined,
          checks: create(ChecksSchema, { webAuthN: { credentialAssertionData: command.assertion } }),
          metadata: { ["paypm_workforce_passkey_request_" + state.requestId]: new TextEncoder().encode(assertionHash) },
          lifetime: sessionLifetime({ seconds: BigInt(300), nanos: 0 } as Duration),
        });
        token = accepted.sessionToken;
      } catch (error) {
        if (isClassifiedError(error) && error.isUserError) {
          await store.passkeyAttemptFailed(state.requestId);
          return unavailable();
        }
      }
    }
    const { session } = await getSession({
      serviceConfig,
      sessionId: state.stepSessionId,
      sessionToken: token,
    });
    const verified = providerTimestampMs(session?.factors?.webAuthN?.verifiedAt);
    if (
      !session ||
      session.id !== state.stepSessionId ||
      new TextDecoder().decode(session.metadata["paypm_workforce_passkey_request_" + state.requestId]) !== assertionHash ||
      session.factors?.user?.id !== state.userId ||
      !verifiedFactor(session, session.factors.user.verifiedAt) ||
      session.factors.webAuthN?.userVerified !== true ||
      !verifiedFactor(session, session.factors.webAuthN.verifiedAt) ||
      verified === undefined ||
      verified < state.issuedAt ||
      Date.now() - verified > 60000
    )
      return unavailable();
    await store.passkeyAttemptVerified(state.requestId);
    await baseContext();
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
