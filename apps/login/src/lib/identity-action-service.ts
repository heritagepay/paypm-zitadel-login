import { Code } from "@connectrpc/connect";
import { create, type Duration } from "@zitadel/client";
import { RequestChallengesSchema, UserVerificationRequirement } from "@zitadel/proto/zitadel/session/v2/challenge_pb";
import type { Session } from "@zitadel/proto/zitadel/session/v2/session_pb";
import { ChecksSchema } from "@zitadel/proto/zitadel/session/v2/session_service_pb";
import { AuthFactorState } from "@zitadel/proto/zitadel/user/v2/user_pb";
import { headers } from "next/headers";
import { createHash, randomBytes } from "node:crypto";
import "server-only";
import { providerTimestampMs, sessionLifetime } from "./authentication-policy";
import { isClassifiedError } from "./grpc/interceptors/error-classification";
import { readIdentityActionAuthority } from "./identity-action-authority";
import {
  assertIdentityCommand,
  exactObject,
  identityActionPair,
  identityActionReceiptMatches,
  identityUuid,
  sameIdentityBinding,
  sameIdentityOwner,
  type IdentityActionBinding,
  type IdentityActionCommand,
  type IdentityActionPair,
} from "./identity-action-contract";
import { identityActionStore, type IdentityActionRow } from "./identity-action-store";
import { readIdentityAdmission } from "./identity-admission-reader";
import { identityPrivatePurpose, type IdentityPrivatePurpose } from "./identity-private-purpose";
import { getServiceConfig } from "./service-url";
import { workforceIdentityRequest } from "./workforce-identity-client";
import { workforcePolicy } from "./workforce-policy";
import { workforceProvider } from "./workforce-provider";
import { flushWorkforceRevocations } from "./workforce-revocations";
import { workforceStore } from "./workforce-store";
import { createSessionFromChecksAndChallenges, getSession, listPasskeys, setSession } from "./zitadel";
const deny = () => new Error("Identity action unavailable");
class PasskeyEnrollmentRequired extends Error {
  readonly code = "passkey_enrollment_required";
}
const failure = (error?: unknown) =>
  Response.json(
    error instanceof PasskeyEnrollmentRequired
      ? { error: "Identity action unavailable", code: error.code }
      : { error: "Identity action unavailable" },
    { status: error instanceof PasskeyEnrollmentRequired ? 428 : 403, headers: { "cache-control": "no-store", "referrer-policy": "no-referrer" } },
  );
const json = (v: unknown) =>
  Response.json(v, { headers: { "cache-control": "no-store", "referrer-policy": "no-referrer" } });
function policy() {
  const p = workforcePolicy(),
    origin = process.env.PAYPM_WORKFORCE_PASSKEY_ORIGIN,
    rpId = process.env.PAYPM_WORKFORCE_PASSKEY_RP_ID;
  if (!p?.emailOtpReady || !origin || !rpId) throw deny();
  const u = new URL(origin);
  if (u.protocol !== "https:" || u.origin !== origin || u.hostname !== rpId) throw deny();
  return { ...p, origin, rpId };
}
/** Next removes its configured basePath before constructing the route-handler Request. */
function actionPath(url: URL) {
  const base = "/ui/v2/login";
  return url.pathname.startsWith(base + "/") ? url.pathname.slice(base.length) : url.pathname;
}
function privateRoute(request: Request, purpose: IdentityPrivatePurpose, path: string) {
  const u = new URL(request.url);
  if (
    request.method !== "POST" ||
    actionPath(u) !== "/api/internal/v1/identity/actions/requests" + path ||
    u.search ||
    request.headers.has("origin") ||
    request.headers.has("cookie")
  )
    throw deny();
  identityPrivatePurpose(request, purpose);
}
function publicRoute(request: Request, id: string, operation: "challenge" | "complete" | "cancel") {
  const u = new URL(request.url);
  if (actionPath(u) !== `/api/identity/actions/${id}/${operation}` || u.search) throw deny();
}
async function input(request: Request, keys: string[]) {
  const body = await request.text();
  if (Buffer.byteLength(body) > 32768) throw deny();
  const value: unknown = JSON.parse(body);
  if (!exactObject(value, keys)) throw deny();
  return value;
}
function callback(clientId: string, command: IdentityActionCommand) {
  const rows: unknown = JSON.parse(process.env.PAYPM_IDENTITY_ACTION_CLIENT_POLICIES_JSON ?? "null");
  if (!Array.isArray(rows) || !rows.length || rows.length > 16) throw deny();
  const seen = new Set<string>();
  for (const r of rows) {
    if (
      !exactObject(r, ["clientId", "callbackUrl"]) ||
      typeof r.clientId !== "string" ||
      !/^[A-Za-z0-9._:@-]{1,200}$/.test(r.clientId) ||
      seen.has(r.clientId) ||
      typeof r.callbackUrl !== "string"
    )
      throw deny();
    const u = new URL(r.callbackUrl);
    if (
      u.protocol !== "https:" ||
      u.pathname !== "/api/v1/auth/browser/actions/callback" ||
      u.username ||
      u.password ||
      u.search ||
      u.hash
    )
      throw deny();
    seen.add(r.clientId);
  }
  const r = rows.find((r) => r.clientId === clientId);
  if (!r) throw deny();
  if (command.purpose === "wallet_legacy_linkage") return r.callbackUrl as string;
  const staff = new URL(r.callbackUrl);
  staff.pathname = "/api/v1/auth/browser/staff-actions/callback";
  return staff.href;
}
async function admission(pair: IdentityActionPair) {
  if (!identityActionPair(pair)) throw deny();
  policy();
  const response = await readIdentityAdmission(
    new Request("https://internal.invalid/identity/admission", {
      method: "POST",
      headers: { authorization: `Bearer ${process.env.PAYPM_IDENTITY_ADMISSION_READER_TOKEN ?? ""}` },
      body: JSON.stringify(pair),
    }),
  );
  if (!response.ok) throw deny();
  const v = await response.json();
  if (
    v.active !== true ||
    v.plane !== "workforce" ||
    v.authenticationClass !== "workforce_limited" ||
    v.appId !== "identity-administration" ||
    !identityUuid(v.personId) ||
    !v.requestId ||
    !v.revocationVersion
  )
    throw deny();
  return v;
}
async function currentBinding(pair: IdentityActionPair, binding: IdentityActionBinding) {
  if (!identityActionPair(pair)) throw deny();
  // Persisted caller material also contains callback/capability custody. The
  // admission and authority contracts accept only this exact credential pair.
  const proof: IdentityActionPair = {
    idToken: pair.idToken,
    accessToken: pair.accessToken,
    nonce: pair.nonce,
    clientId: pair.clientId,
  };
  const a = await admission(proof);
  const fields = [
    "personId",
    "issuer",
    "providerSubject",
    "baseSessionId",
    "clientId",
    "contextId",
    "appId",
    "deploymentId",
    "environment",
  ] as const;
  if (fields.some((k) => a[k] !== binding.expected[k])) throw deny();
  const b = await readIdentityActionAuthority(binding.expected, binding.command, proof);
  return { binding: b, requestId: a.requestId as string };
}
async function live(row: IdentityActionRow, terminal = false) {
  const s = identityActionStore(),
    caller = s.caller(row);
  const v = await currentBinding(caller, row.binding);
  if (v.requestId !== row.request_id) throw deny();
  await s.row(row.id, terminal);
  return v;
}
async function providerConfig() {
  const p = policy(),
    { serviceConfig } = getServiceConfig(await headers());
  if (new URL(serviceConfig.baseUrl).origin !== p.issuer) throw deny();
  return { p, serviceConfig };
}
function assertionValid(assertion: Record<string, any>, challenge: string) {
  try {
    const p = policy(),
      r = assertion.response;
    if (
      !exactObject(assertion, ["id", "rawId", "type", "response"]) ||
      assertion.type !== "public-key" ||
      typeof assertion.id !== "string" ||
      typeof assertion.rawId !== "string" ||
      !exactObject(r, ["clientDataJSON", "authenticatorData", "signature", "userHandle"]) ||
      typeof r.signature !== "string"
    )
      return false;
    const data = JSON.parse(Buffer.from(r.clientDataJSON, "base64url").toString("utf8")),
      auth = Buffer.from(r.authenticatorData, "base64url");
    return (
      data.type === "webauthn.get" &&
      data.origin === p.origin &&
      data.challenge === challenge &&
      data.crossOrigin !== true &&
      auth.length >= 37 &&
      (auth[32] & 5) === 5 &&
      auth.subarray(0, 32).equals(createHash("sha256").update(p.rpId).digest())
    );
  } catch {
    return false;
  }
}
/** Ownership evidence from the pinned issuer, never a SID merely reported by the browser/create response. */
function providerOwned(session: Session | undefined, row: IdentityActionRow, sid: string) {
  const p = policy(),
    created = providerTimestampMs(session?.creationDate),
    expires = providerTimestampMs(session?.expirationDate);
  if (
    !session ||
    p.issuer !== row.issuer ||
    session.id !== sid ||
    session.factors?.user?.id !== row.provider_subject ||
    session.factors.user.organizationId !== p.organizationId ||
    new TextDecoder().decode(session.metadata["paypm_identity_action_intent"]) !== row.id ||
    new TextDecoder().decode(session.metadata["paypm_identity_action_client"]) !== row.client_id ||
    new TextDecoder().decode(session.metadata["paypm_identity_action_base"]) !== row.base_session_id ||
    created === undefined ||
    created > Date.now() ||
    expires === undefined ||
    expires <= created
  )
    throw deny();
  return session;
}
function accepted(session: Session | undefined, row: IdentityActionRow) {
  providerOwned(session, row, row.provider_session_id!);
  const p = policy(),
    verified = providerTimestampMs(session?.factors?.webAuthN?.verifiedAt),
    created = providerTimestampMs(session?.creationDate),
    expires = providerTimestampMs(session?.expirationDate);
  if (
    !session ||
    session.id !== row.provider_session_id ||
    session.factors?.user?.id !== row.provider_subject ||
    session.factors.user.organizationId !== p.organizationId ||
    session.factors.webAuthN?.userVerified !== true ||
    !row.proof_id ||
    !row.assertion_hash ||
    !row.verification_started_at ||
    verified === undefined ||
    created === undefined ||
    expires === undefined ||
    verified < row.verification_started_at.getTime() ||
    verified < created ||
    verified > Date.now() ||
    Date.now() - verified > 60000 ||
    expires <= Date.now() ||
    new TextDecoder().decode(session.metadata["paypm_identity_action_intent"]) !== row.id ||
    new TextDecoder().decode(session.metadata["paypm_workforce_passkey_request_" + row.proof_id]) !== row.assertion_hash
  )
    throw deny();
  return new Date(verified);
}
async function retirement(row: IdentityActionRow) {
  if (row.provider_conflicted) return "pending" as const;
  if (!row.provider_started_at) return "not_started" as const;
  const { p, serviceConfig } = await providerConfig();
  let session: Session | undefined;
  if (row.provider_session_id) {
    try {
      session = (await getSession({ serviceConfig, sessionId: row.provider_session_id, sessionToken: "" })).session;
      if (!session) throw deny();
    } catch (e) {
      if (isClassifiedError(e) && e.code === Code.NotFound) return "confirmed" as const;
      throw e;
    }
  } else
    session = await (
      await workforceProvider(serviceConfig, p.organizationId)
    ).inspectActionIntent(row.id, row.provider_subject, "paypm_identity_action_intent");
  // A dispatched create may still be unresolved: a missing metadata row cannot prove retirement.
  if (!session) return "pending" as const;
  providerOwned(session, row, session.id);
  const created = providerTimestampMs(session.creationDate),
    expires = providerTimestampMs(session.expirationDate);
  if (
    (row.provider_session_id && session.id !== row.provider_session_id) ||
    session.factors?.user?.id !== row.provider_subject ||
    session.factors.user.organizationId !== p.organizationId ||
    new TextDecoder().decode(session.metadata["paypm_identity_action_intent"]) !== row.id ||
    created === undefined ||
    created > Date.now() ||
    expires === undefined ||
    expires <= created
  )
    throw deny();
  return expires <= Date.now() ? ("confirmed" as const) : ("pending" as const);
}
async function register(row: IdentityActionRow) {
  if (row.state !== "created") return row;
  await live(row);
  const store = identityActionStore(),
    material = store.provider(row),
    e = row.binding.expected;
  const result = await workforceIdentityRequest("internal/v1/workforce-action-proofs/requests", {
    providerSubject: e.providerSubject,
    baseSessionId: e.baseSessionId,
    stepSessionId: material.sessionId,
    clientId: e.clientId,
    contextId: e.contextId,
    appId: e.appId,
    deploymentId: e.deploymentId,
    environment: e.environment,
    action: e.action,
    payloadHash: e.payloadHash,
    challenge: material.publicKey.challenge,
  });
  if (
    !exactObject(result, ["requestId", "expiresAt", "binding"]) ||
    !identityUuid(result.requestId) ||
    !sameIdentityBinding(result.binding, e) ||
    typeof result.expiresAt !== "string"
  )
    throw deny();
  await live(row);
  return store.registered(row.id, result.requestId, new Date(result.expiresAt));
}
async function dispatch(row: IdentityActionRow) {
  const s = identityActionStore(),
    { p, serviceConfig } = await providerConfig();
  if (row.state === "reserved") {
    // Missing enrollment is a known prerequisite, not an uncertain CreateSession
    // outcome. Leave the original request resumable without dispatching a challenge.
    if (!row.provider_started_at) {
      const keys = await listPasskeys({ serviceConfig, userId: row.provider_subject });
      if (!Array.isArray(keys.result)) throw deny();
      if (!keys.result.some((key) => key.state === AuthFactorState.READY)) throw new PasskeyEnrollmentRequired();
    }
    if (!(await s.claimCreation(row.id))) {
      // Unknown create outcome is never redispatched. Observe/retire only exact original metadata.
      if (row.provider_started_at && Date.now() - row.provider_started_at.getTime() >= 10000) {
        const provider = await workforceProvider(serviceConfig, p.organizationId),
          orphan = await provider.inspectActionIntent(row.id, row.provider_subject, "paypm_identity_action_intent");
        if (orphan) {
          providerOwned(orphan, row, orphan.id);
          await s.retire(row.id, orphan.id);
        }
      }
      throw deny();
    }
    await live(row);
    const r = await createSessionFromChecksAndChallenges({
      serviceConfig,
      checks: create(ChecksSchema, { user: { search: { case: "userId", value: row.provider_subject } } }),
      challenges: create(RequestChallengesSchema, {
        webAuthN: { domain: p.rpId, userVerificationRequirement: UserVerificationRequirement.REQUIRED },
      }),
      metadata: {
        paypm_identity_action_intent: new TextEncoder().encode(row.id),
        paypm_identity_action_client: new TextEncoder().encode(row.client_id),
        paypm_identity_action_base: new TextEncoder().encode(row.base_session_id),
      },
      timeoutMs: 5000,
      lifetime: sessionLifetime({
        seconds: BigInt(Math.floor((row.expires_at.getTime() - Date.now()) / 1000)),
        nanos: 0,
      } as Duration),
    });
    // Verify actual ownership before retaining or queuing any returned SID, including
    // malformed/lost challenge outcomes. Unknown/foreign provider evidence stays held.
    if (!r.sessionId || !/^[1-9]\d{0,39}$/.test(r.sessionId)) throw deny();
    providerOwned(
      (await getSession({ serviceConfig, sessionId: r.sessionId, sessionToken: r.sessionToken ?? "" })).session,
      row,
      r.sessionId,
    );
    const options = r.challenges?.webAuthN?.publicKeyCredentialRequestOptions as Record<string, any> | undefined,
      pk = options?.publicKey;
    if (
      !r.sessionId ||
      !/^[1-9]\d{0,39}$/.test(r.sessionId) ||
      !r.sessionToken ||
      !pk ||
      typeof pk.challenge !== "string" ||
      pk.rpId !== p.rpId ||
      pk.userVerification !== "required"
    ) {
      if (r.sessionId) await s.retire(row.id, r.sessionId);
      throw deny();
    }
    const saved = await s.created(row.id, { sessionId: r.sessionId, sessionToken: r.sessionToken, publicKey: pk });
    if (!saved) throw deny();
    row = saved;
  }
  row = await register(row);
  if (!["registered", "verified"].includes(row.state)) throw deny();
  await live(row);
  const url = new URL("/ui/v2/login/identity/step-up", p.origin);
  url.searchParams.set("requestId", row.id);
  url.searchParams.set("capability", s.caller(row).capability);
  return json({ requestId: row.id, expiresAt: row.expires_at.toISOString(), redirectUrl: url.href });
}
export async function startIdentityAction(request: Request, predecessorId?: string) {
  let stage = "private-request";
  try {
    if (predecessorId && !identityUuid(predecessorId)) throw deny();
    privateRoute(request, "PAYPM_IDENTITY_ACTION_BFF_TOKEN", predecessorId ? `/${predecessorId}/continue` : "");
    stage = "exact-envelope";
    const v = await input(request, [
      "requestId",
      "operationKey",
      "expected",
      "command",
      "callbackState",
      "idToken",
      "accessToken",
      "nonce",
      "clientId",
    ]);
    stage = "exact-command";
    assertIdentityCommand(v.expected, v.command);
    if (
      !identityActionPair(v) ||
      !identityUuid(v.requestId) ||
      v.operationKey !== v.command.operationKey ||
      typeof v.callbackState !== "string" ||
      !/^[A-Za-z0-9_-]{64}$/.test(v.callbackState)
    )
      throw deny();
    const pair = { idToken: v.idToken, accessToken: v.accessToken, nonce: v.nonce, clientId: v.clientId };
    stage = "current-authority";
    const initial = await currentBinding(pair, { expected: v.expected, command: v.command, caseId: v.operationKey }),
      s = identityActionStore();
    stage = "store-maintenance";
    await s.clearExpired();
    let previous: IdentityActionRow | undefined;
    if (predecessorId) {
      previous = await s.observe(predecessorId, initial.binding, initial.requestId);
      if (!previous || !sameIdentityOwner(previous.binding.expected, v.expected) || previous.id === v.requestId)
        throw deny();
      const r = await retirement(previous);
      if (
        r === "pending" ||
        (previous.expires_at.getTime() > Date.now() && !["cancelled", "retired"].includes(previous.state))
      )
        throw deny();
      await readIdentityActionAuthority(v.expected, v.command, pair, {
        requestId: previous.id,
        expected: previous.binding.expected,
        proofId: previous.proof_id,
        stepSessionId: previous.provider_session_id,
      });
      await s.retire(previous.id);
      previous = { ...previous, state: "retired" };
    }
    const material = {
      ...pair,
      capability: randomBytes(32).toString("base64url"),
      callbackState: v.callbackState,
      callbackUrl: callback(pair.clientId, initial.binding.command),
    };
    // Capability is regenerated only for an actual new reservation; hash excludes it, so retry returns the server-custodied original.
    stage = "reserve-original";
    const row = await s.reserve({
      id: v.requestId,
      binding: initial.binding,
      requestId: initial.requestId,
      material,
      predecessor: previous,
    });
    stage = "provider-dispatch";
    return await dispatch(row);
  } catch (error) {
    const code = error && typeof error === "object" && "code" in error && typeof error.code === "string" && /^[a-z0-9_]{1,80}$/.test(error.code) ? error.code : "unavailable";
    console.error(JSON.stringify({context: "identity-action-start", stage, code}));
    return failure(error);
  }
}
export async function readIdentityAction(request: Request, id: string) {
  try {
    if (!identityUuid(id)) throw deny();
    privateRoute(request, "PAYPM_IDENTITY_ACTION_CONSUMER_TOKEN", `/${id}/readback`);
    const v = await input(request, ["expected", "command"]);
    assertIdentityCommand(v.expected, v.command);
    const s = identityActionStore(),
      row = await s.row(id, true);
    if (!sameIdentityBinding(row.binding.expected, v.expected) || !sameIdentityBinding(row.binding.command, v.command))
      throw deny();
    await live(row, true);
    if (row.state === "cancelled") {
      if ((await retirement(row)) === "pending") throw deny();
      return json({ requestId: id, state: "cancelled", expected: row.binding.expected, command: row.binding.command });
    }
    if (row.state !== "verified" || !row.receipt_expires_at || row.receipt_expires_at.getTime() <= Date.now()) throw deny();
    const { serviceConfig } = await providerConfig(),
      actual = accepted(
        (await getSession({ serviceConfig, sessionId: row.provider_session_id!, sessionToken: "" })).session,
        row,
      );
    if (actual.getTime() !== row.verified_at?.getTime()) throw deny();
    await live(row);
    return json({
      requestId: id,
      state: "verified",
      receipt: s.receipt(row),
      proofId: row.proof_id,
      expiresAt: row.receipt_expires_at.toISOString(),
      expected: row.binding.expected,
      command: row.binding.command,
      caseId: row.operation_key,
    });
  } catch {
    return failure();
  }
}
export async function observeIdentityAction(request: Request, id: string) {
  try {
    if (!identityUuid(id)) throw deny();
    privateRoute(request, "PAYPM_IDENTITY_ACTION_BFF_TOKEN", `/${id}/status`);
    const v = await input(request, ["idToken", "accessToken", "nonce", "clientId", "expected", "command"]);
    assertIdentityCommand(v.expected, v.command);
    if (!identityActionPair(v)) throw deny();
    const pair = { idToken: v.idToken, accessToken: v.accessToken, nonce: v.nonce, clientId: v.clientId },
      binding = { expected: v.expected, command: v.command, caseId: v.command.operationKey };
    const initial = await currentBinding(pair, binding),
      s = identityActionStore(),
      original = await s.observe(id, initial.binding, initial.requestId);
    const r = original ? await retirement(original) : "not_started";
    if (
      original?.state === "verified" &&
      original.expires_at.getTime() > Date.now() &&
      original.receipt_expires_at &&
      original.receipt_expires_at.getTime() > Date.now()
    ) {
      const { serviceConfig } = await providerConfig();
      const actual = accepted(
        (await getSession({ serviceConfig, sessionId: original.provider_session_id!, sessionToken: "" })).session,
        original,
      );
      if (actual.getTime() !== original.verified_at?.getTime()) throw deny();
    }
    const final = await currentBinding(pair, binding),
      row = await s.observe(id, final.binding, final.requestId);
    if (
      !sameIdentityBinding(initial, final) ||
      (row &&
        (!original ||
          row.provider_session_id !== original.provider_session_id ||
          row.provider_started_at?.getTime() !== original.provider_started_at?.getTime() ||
          row.state !== original.state ||
          row.receipt_hash !== original.receipt_hash ||
          row.verified_at?.getTime() !== original.verified_at?.getTime()))
    )
      throw deny();
    let state = "not_started";
    if (row) {
      if (r === "pending" && ["cancelled", "retired"].includes(row.state)) state = "pending";
      else if (row.state === "cancelled") state = "cancelled";
      else if (
        row.expires_at.getTime() <= Date.now() ||
        (row.receipt_expires_at && row.receipt_expires_at.getTime() <= Date.now())
      )
        state = r === "pending" ? "pending" : "expired";
      else if (row.state === "retired" || r === "confirmed") state = "retired";
      else state = row.state === "verified" ? "verified" : row.provider_started_at ? "pending" : "not_started";
    }
    return json({
      requestId: id,
      state,
      expected: binding.expected,
      command: binding.command,
      caseId: binding.caseId,
      requestExpiresAt: row?.expires_at.toISOString() ?? null,
      receiptExpiresAt: row?.receipt_expires_at?.toISOString() ?? null,
      providerRetirement: r,
      checkedAt: new Date().toISOString(),
    });
  } catch {
    return failure();
  }
}
export async function readIdentityPublicChallenge(request: Request, id: string, capability: string) {
  try {
    if (request.method !== "GET" || !identityUuid(id)) throw deny();
    publicRoute(request, id, "challenge");
    const s = identityActionStore(),
      row = await s.capability(id, capability);
    if (row.state !== "registered") throw deny();
    await live(row);
    return json({
      requestId: id,
      action: row.binding.expected.action,
      publicKey: s.provider(row).publicKey,
      expiresAt: row.expires_at.toISOString(),
      returnUrl: new URL(s.caller(row).callbackUrl).origin,
    });
  } catch {
    return failure();
  }
}
export async function completeIdentityPublicAction(request: Request, id: string) {
  try {
    const { p, serviceConfig } = await providerConfig();
    if (request.method !== "POST" || request.headers.get("origin") !== p.origin || !identityUuid(id)) throw deny();
    publicRoute(request, id, "complete");
    const v = await input(request, ["capability", "assertion"]),
      s = identityActionStore();
    if (typeof v.capability !== "string" || !v.assertion || typeof v.assertion !== "object") throw deny();
    let row = await s.capability(id, v.capability);
    if (!["registered", "verified"].includes(row.state)) throw deny();
    await live(row);
    const material = s.provider(row);
    if (!assertionValid(v.assertion, material.publicKey.challenge as string)) throw deny();
    const attempt = await s.attempt(id, v.assertion);
    row = attempt.row;
    let token = "";
    if (attempt.first) {
      try {
        token = (
          await setSession({
            serviceConfig,
            sessionId: material.sessionId,
            sessionToken: material.sessionToken,
            challenges: undefined,
            checks: create(ChecksSchema, { webAuthN: { credentialAssertionData: v.assertion } }),
            metadata: { ["paypm_workforce_passkey_request_" + row.proof_id]: new TextEncoder().encode(row.assertion_hash!) },
            lifetime: sessionLifetime({
              seconds: BigInt(Math.floor((row.expires_at.getTime() - Date.now()) / 1000)),
              nanos: 0,
            } as Duration),
          })
        ).sessionToken;
      } catch (e) {
        if (isClassifiedError(e) && e.isUserError) {
          await s.retire(id);
          throw deny();
        }
      }
    }
    const verified = accepted(
      (await getSession({ serviceConfig, sessionId: material.sessionId, sessionToken: token })).session,
      row,
    );
    await live(row);
    const result = await workforceIdentityRequest(`internal/v1/workforce-action-proofs/requests/${row.proof_id}/complete`, {
      assertion: s.assertion(row),
    });
    if (
      !exactObject(result, ["receipt", "expiresAt", "binding"]) ||
      typeof result.receipt !== "string" ||
      !/^paypm-wf1\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]{43}$/.test(result.receipt) ||
      result.receipt.length > 8192 ||
      !sameIdentityBinding(result.binding, row.binding.expected) ||
      typeof result.expiresAt !== "string"
    )
      throw deny();
    const expires = new Date(result.expiresAt);
    if (!identityActionReceiptMatches(result.receipt, row.proof_id!, row.binding.expected, verified, expires)) throw deny();
    await live(row);
    row = await s.verified(id, verified, result.receipt, expires);
    const caller = s.caller(row),
      u = new URL(caller.callbackUrl);
    u.searchParams.set("requestId", id);
    u.searchParams.set("state", caller.callbackState);
    return json({ callbackUrl: u.href });
  } catch {
    return failure();
  }
}
export async function cancelIdentityPublicAction(request: Request, id: string) {
  try {
    const p = policy();
    if (request.method !== "POST" || request.headers.get("origin") !== p.origin || !identityUuid(id)) throw deny();
    publicRoute(request, id, "cancel");
    const v = await input(request, ["capability"]);
    if (typeof v.capability !== "string") throw deny();
    const s = identityActionStore(),
      row = await s.capability(id, v.capability, true);
    await live(row, true);
    const caller = s.caller(row),
      current = await live(row, true);
    await s.cancel(id);
    const { serviceConfig } = await providerConfig();
    await flushWorkforceRevocations(workforceStore(), await workforceProvider(serviceConfig, p.organizationId));
    const cancelled = await s.observe(id, row.binding, current.requestId);
    if (!cancelled || cancelled.state !== "cancelled" || (await retirement(cancelled)) === "pending") throw deny();
    await live(cancelled, true);
    const u = new URL(caller.callbackUrl);
    u.searchParams.set("requestId", id);
    u.searchParams.set("state", caller.callbackState);
    return json({ callbackUrl: u.href });
  } catch {
    return failure();
  }
}
