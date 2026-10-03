import { Code, create, type Duration } from "@zitadel/client";
import { RequestChallengesSchema, UserVerificationRequirement } from "@zitadel/proto/zitadel/session/v2/challenge_pb";
import type { Session } from "@zitadel/proto/zitadel/session/v2/session_pb";
import { ChecksSchema, type Checks } from "@zitadel/proto/zitadel/session/v2/session_service_pb";
import { headers } from "next/headers";
import { createHash, randomBytes, timingSafeEqual } from "node:crypto";
import "server-only";
import { providerTimestampMs, sessionLifetime, verifiedFactor } from "./authentication-policy";
import { isClassifiedError } from "./grpc/interceptors/error-classification";
import {
  operationsActionFamily,
  operationsCommand,
  operationsExpected,
  readOperationsActionAuthority,
  type OperationsActionFamily,
} from "./operations-action-authority";
import {
  operationsActionStore,
  type OperationsActionExpected,
  type OperationsActionRow,
  type OperationsCallerMaterial,
} from "./operations-action-store";
import { readOperationsAdmission } from "./operations-admission-reader";
import { getServiceConfig } from "./service-url";
import { workforceAssertionHash } from "./workforce-assertion";
import { workforcePolicy } from "./workforce-policy";
import { workforceProvider } from "./workforce-provider";
import { flushWorkforceRevocations } from "./workforce-revocations";
import { workforceStore } from "./workforce-store";
import { createSessionFromChecksAndChallenges, getSession, setSession } from "./zitadel";
type Assertion = NonNullable<NonNullable<Checks["webAuthN"]>["credentialAssertionData"]>;
const uuid = /^[a-f0-9]{8}-[a-f0-9]{4}-4[a-f0-9]{3}-[89ab][a-f0-9]{3}-[a-f0-9]{12}$/i;
const denied = () => new Error("Operations action verification unavailable");
const noStore = { "cache-control": "no-store" };
const failure = () =>
  Response.json({ error: "Operations action verification unavailable" }, { status: 403, headers: noStore });
function purpose(
  request: Request,
  name:
    | "PAYPM_OPERATIONS_ACTION_BFF_TOKEN"
    | "PAYPM_OPERATIONS_ACTION_CONSUMER_TOKEN"
    | "PAYPM_OPERATIONS_GRANT_BFF_TOKEN"
    | "PAYPM_OPERATIONS_GRANT_CONSUMER_TOKEN"
    | "PAYPM_OPERATIONS_DEPLOYMENT_GRANT_BFF_TOKEN"
    | "PAYPM_OPERATIONS_DEPLOYMENT_GRANT_CONSUMER_TOKEN",
) {
  const secret = process.env[name];
  if (
    !secret ||
    secret.length < 32 ||
    [
      "PAYPM_OPERATIONS_ACTION_BFF_TOKEN",
      "PAYPM_OPERATIONS_ACTION_CONSUMER_TOKEN",
      "PAYPM_OPERATIONS_GRANT_BFF_TOKEN",
      "PAYPM_OPERATIONS_GRANT_CONSUMER_TOKEN",
      "PAYPM_OPERATIONS_DEPLOYMENT_GRANT_BFF_TOKEN",
      "PAYPM_OPERATIONS_DEPLOYMENT_GRANT_CONSUMER_TOKEN",
      "PAYPM_OPERATIONS_ADMISSION_READER_TOKEN",
      "PAYPM_OPERATIONS_INTROSPECTION_CLIENT_SECRET",
      "PAYPM_WORKFORCE_ADMISSION_READER_TOKEN",
      "PAYPM_WORKFORCE_IDENTITY_CLIENT_SECRET",
      "PAYPM_WORKFORCE_FLOW_KEY_BASE64",
      "PAYPM_WORKFORCE_STORE_KEY_BASE64",
      "PAYPM_LEGACY_MIGRATION_FLOW_KEY_BASE64",
      "PAYPM_OPERATIONS_ACTION_AUTHORITY_API_KEY",
      "PAYPM_OPERATIONS_GRANT_AUTHORITY_API_KEY",
      "PAYPM_OPERATIONS_DEPLOYMENT_GRANT_AUTHORITY_API_KEY",
      "PAYPM_OPERATIONS_LOGOUT_TOKEN",
      "PAYPM_OPERATIONS_RETIREMENT_PROOF_KEY_BASE64",
      "PAYPM_OPERATIONS_STORE_KEY_BASE64",
    ]
      .filter((v) => v !== name)
      .some((v) => process.env[v] === secret)
  )
    throw denied();
  const actual = Buffer.from(request.headers.get("authorization") ?? ""),
    expected = Buffer.from(`Bearer ${secret}`);
  if (actual.length !== expected.length || !timingSafeEqual(actual, expected)) throw denied();
}
const familyPurpose = {
  settlement: { bff: "PAYPM_OPERATIONS_ACTION_BFF_TOKEN", consumer: "PAYPM_OPERATIONS_ACTION_CONSUMER_TOKEN" },
  grant: { bff: "PAYPM_OPERATIONS_GRANT_BFF_TOKEN", consumer: "PAYPM_OPERATIONS_GRANT_CONSUMER_TOKEN" },
  "deployment-grant": {
    bff: "PAYPM_OPERATIONS_DEPLOYMENT_GRANT_BFF_TOKEN",
    consumer: "PAYPM_OPERATIONS_DEPLOYMENT_GRANT_CONSUMER_TOKEN",
  },
} as const;
async function input(request: Request, keys: string[]) {
  const raw = await request.text();
  if (Buffer.byteLength(raw) > 32768) throw denied();
  const value = JSON.parse(raw);
  if (
    !value ||
    typeof value !== "object" ||
    Array.isArray(value) ||
    Object.keys(value).sort().join(",") !== keys.sort().join(",")
  )
    throw denied();
  return value;
}
function policy() {
  const workforce = workforcePolicy(),
    origin = process.env.PAYPM_WORKFORCE_PASSKEY_ORIGIN,
    rpId = process.env.PAYPM_WORKFORCE_PASSKEY_RP_ID;
  if (!workforce?.emailOtpReady || !origin || !rpId) throw denied();
  const parsed = new URL(origin);
  if (parsed.origin !== origin || parsed.hostname !== rpId || parsed.protocol !== "https:") throw denied();
  return { ...workforce, origin, rpId };
}
function callback(clientId: string) {
  const rows: unknown = JSON.parse(process.env.PAYPM_OPERATIONS_ACTION_CLIENT_POLICIES_JSON ?? "null");
  if (!Array.isArray(rows) || rows.length === 0 || rows.length > 16) throw denied();
  const seen = new Set<string>();
  for (const row of rows) {
    if (
      !row ||
      typeof row !== "object" ||
      Array.isArray(row) ||
      Object.keys(row).sort().join(",") !== "callbackUrl,clientId" ||
      typeof row.clientId !== "string" ||
      seen.has(row.clientId) ||
      typeof row.callbackUrl !== "string"
    )
      throw denied();
    const url = new URL(row.callbackUrl);
    if (
      url.protocol !== "https:" ||
      url.username ||
      url.password ||
      url.search ||
      url.hash ||
      url.pathname !== "/auth/workforce/actions/callback" ||
      url.href !== row.callbackUrl
    )
      throw denied();
    seen.add(row.clientId);
  }
  const row = rows.find((v) => v.clientId === clientId);
  if (!row) throw denied();
  return String(row.callbackUrl);
}
async function admission(proofs: Pick<OperationsCallerMaterial, "idToken" | "accessToken" | "nonce" | "clientId">) {
  const secret = process.env.PAYPM_OPERATIONS_ADMISSION_READER_TOKEN;
  if (!secret) throw denied();
  const response = await readOperationsAdmission(
    new Request("https://login.invalid/internal-admission", {
      method: "POST",
      headers: { authorization: `Bearer ${secret}` },
      body: JSON.stringify(proofs),
    }),
  );
  if (!response.ok) throw denied();
  const value = await response.json();
  if (
    value?.active !== true ||
    value.authenticationClass !== "workforce_limited" ||
    value.plane !== "workforce" ||
    typeof value.requestId !== "string"
  )
    throw denied();
  return value;
}
function expected(
  value: Record<string, string>,
  action: OperationsActionExpected["action"],
  payloadHash: string,
  family: OperationsActionFamily = "settlement",
): OperationsActionExpected {
  const result = {
    personId: value.personId,
    issuer: value.issuer,
    providerSubject: value.providerSubject,
    baseSessionId: value.baseSessionId,
    clientId: value.clientId,
    contextId: value.contextId,
    appId: value.appId,
    deploymentId: value.deploymentId,
    environment: value.environment as OperationsActionExpected["environment"],
    action,
    payloadHash,
  };
  if (!operationsExpected(result, family)) throw denied();
  return result;
}
async function live(row: OperationsActionRow, allowCancelled = false) {
  const store = operationsActionStore(),
    material = store.caller(row),
    proofs = {
      idToken: material.idToken,
      accessToken: material.accessToken,
      nonce: material.nonce,
      clientId: material.clientId,
    };
  const current = await admission(proofs),
    binding = row.binding;
  if (
    workforceAssertionHash(
      expected(
        current,
        binding.expected.action,
        binding.expected.payloadHash,
        operationsActionFamily(binding.expected.action),
      ),
    ) !== workforceAssertionHash(binding.expected) ||
    current.requestId !== row.request_id
  )
    throw denied();
  const authority = await readOperationsActionAuthority(binding.expected, binding.command, proofs);
  if (workforceAssertionHash(authority) !== workforceAssertionHash(binding)) throw denied();
  await store.row(row.id, allowCancelled);
  return { material, proofs };
}
async function providerConfig() {
  const p = policy(),
    { serviceConfig } = getServiceConfig(await headers());
  if (new URL(serviceConfig.baseUrl).origin !== p.issuer) throw denied();
  return { p, serviceConfig };
}
function assertionValid(assertion: Assertion, challenge: string) {
  try {
    const p = policy(),
      response = assertion.response;
    if (
      !response ||
      typeof response !== "object" ||
      Array.isArray(response) ||
      typeof response.clientDataJSON !== "string" ||
      typeof response.authenticatorData !== "string"
    )
      return false;
    const data = JSON.parse(Buffer.from(response.clientDataJSON, "base64url").toString("utf8")),
      auth = Buffer.from(response.authenticatorData, "base64url");
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
function accepted(session: Session | undefined, row: OperationsActionRow) {
  const p = policy(),
    verifiedAt = providerTimestampMs(session?.factors?.webAuthN?.verifiedAt);
  if (
    !session ||
    session.id !== row.provider_session_id ||
    session.factors?.user?.id !== row.provider_subject ||
    session.factors.user.organizationId !== p.organizationId ||
    !verifiedFactor(session, session.factors.user.verifiedAt) ||
    session.factors.webAuthN?.userVerified !== true ||
    !verifiedFactor(session, session.factors.webAuthN.verifiedAt) ||
    new TextDecoder().decode(session.metadata["paypm_operations_action_accept_" + row.id]) !== row.assertion_hash ||
    verifiedAt === undefined ||
    !row.verification_started_at ||
    verifiedAt < row.verification_started_at.getTime() ||
    Date.now() - verifiedAt > 60000 ||
    !assertionValid(
      operationsActionStore().assertion(row) as Assertion,
      operationsActionStore().provider(row).publicKey.challenge as string,
    )
  )
    throw denied();
  return new Date(verifiedAt);
}
function receiptResponse(row: OperationsActionRow) {
  if (!row.verified_at || !row.receipt_expires_at || row.receipt_expires_at.getTime() <= Date.now()) throw denied();
  return {
    proofId: row.id,
    ...row.binding.expected,
    command: row.binding.command,
    capabilityDecisionId: row.binding.capabilityDecisionId,
    resource: row.binding.resource,
    proofSessionId: row.provider_session_id,
    verifiedAt: row.verified_at.toISOString(),
    expiresAt: row.receipt_expires_at.toISOString(),
    consumedAt: row.consumed_at?.toISOString() ?? null,
    assurance: "paypm_fresh_operations_passkey",
  };
}
export async function startOperationsAction(request: Request, family: OperationsActionFamily = "settlement") {
  try {
    purpose(request, familyPurpose[family].bff);
    const value = await input(request, [
      "requestId",
      "idToken",
      "accessToken",
      "nonce",
      "clientId",
      "callbackState",
      "action",
      "payloadHash",
      "command",
    ]);
    if (
      typeof value.requestId !== "string" ||
      !uuid.test(value.requestId) ||
      typeof value.callbackState !== "string" ||
      !/^[A-Za-z0-9_-]{64}$/.test(value.callbackState) ||
      !operationsCommand(value.command, family) ||
      !["idToken", "accessToken", "nonce", "clientId", "action", "payloadHash"].every((k) => typeof value[k] === "string")
    )
      throw denied();
    const { p, serviceConfig } = await providerConfig(),
      proofs = { idToken: value.idToken, accessToken: value.accessToken, nonce: value.nonce, clientId: value.clientId };
    const current = await admission(proofs),
      e = expected(current, value.action, value.payloadHash, family),
      binding = await readOperationsActionAuthority(e, value.command, proofs),
      store = operationsActionStore();
    await store.clearExpired();
    const material = {
      ...proofs,
      capability: randomBytes(32).toString("base64url"),
      callbackState: value.callbackState,
      callbackUrl: callback(value.clientId),
    };
    let row = await store.reserve({ id: value.requestId, binding, requestId: current.requestId, material });
    if (row.state === "reserved") {
      if (!(await store.claimCreation(row.id))) {
        if (!row.provider_started_at || Date.now() - row.provider_started_at.getTime() < 10000) throw denied();
        const provider = await workforceProvider(serviceConfig, p.organizationId),
          orphan = await provider.findActionIntent(row.id, row.provider_subject, "paypm_operations_action_intent");
        await store.retire(row.id, orphan);
        await flushWorkforceRevocations(workforceStore(), provider);
        throw denied();
      }
      const result = await createSessionFromChecksAndChallenges({
        serviceConfig,
        checks: create(ChecksSchema, { user: { search: { case: "userId", value: row.provider_subject } } }),
        challenges: create(RequestChallengesSchema, {
          webAuthN: { domain: p.rpId, userVerificationRequirement: UserVerificationRequirement.REQUIRED },
        }),
        metadata: { paypm_operations_action_intent: new TextEncoder().encode(row.id) },
        timeoutMs: 5000,
        lifetime: sessionLifetime({
          seconds: BigInt(Math.floor((row.expires_at.getTime() - Date.now()) / 1000)),
          nanos: 0,
        } as Duration),
      });
      const options = result.challenges?.webAuthN?.publicKeyCredentialRequestOptions as Assertion | undefined,
        publicKey = options?.publicKey;
      if (
        !result.sessionId ||
        !/^[1-9]\d{0,39}$/.test(result.sessionId) ||
        !result.sessionToken ||
        !publicKey ||
        typeof publicKey !== "object" ||
        Array.isArray(publicKey) ||
        typeof publicKey.challenge !== "string" ||
        publicKey.rpId !== p.rpId ||
        publicKey.userVerification !== "required"
      ) {
        await store.retire(row.id, result.sessionId || undefined);
        throw denied();
      }
      row = await store.created(row.id, { sessionId: result.sessionId, sessionToken: result.sessionToken, publicKey });
    }
    if (row.state !== "created") throw denied();
    await live(row);
    const saved = store.caller(row),
      redirect = new URL("/operations/step-up", p.origin);
    redirect.searchParams.set("requestId", row.id);
    redirect.searchParams.set("capability", saved.capability);
    return Response.json(
      { requestId: row.id, expiresAt: row.expires_at.toISOString(), redirectUrl: redirect.href },
      { headers: noStore },
    );
  } catch {
    return failure();
  }
}
export async function readOperationsAction(request: Request, id: string, family: OperationsActionFamily = "settlement") {
  try {
    purpose(request, familyPurpose[family].bff);
    if (!uuid.test(id)) throw denied();
    const value = await input(request, ["expected", "command"]);
    if (!operationsExpected(value.expected, family) || !operationsCommand(value.command, family)) throw denied();
    const store = operationsActionStore(),
      row = await store.row(id, true);
    if (
      workforceAssertionHash(row.binding.expected) !== workforceAssertionHash(value.expected) ||
      workforceAssertionHash(row.binding.command) !== workforceAssertionHash(value.command)
    )
      throw denied();
    await live(row, true);
    if (row.state === "cancelled")
      return Response.json(
        {
          requestId: id,
          state: "cancelled",
          expected: row.binding.expected,
          command: row.binding.command,
          capabilityDecisionId: row.binding.capabilityDecisionId,
        },
        { headers: noStore },
      );
    if (row.state !== "verified" || !row.receipt_expires_at || row.receipt_expires_at.getTime() <= Date.now())
      throw denied();
    const { serviceConfig } = await providerConfig(),
      session = await getSession({ serviceConfig, sessionId: row.provider_session_id!, sessionToken: "" });
    if (accepted(session.session, row).getTime() !== row.verified_at?.getTime()) throw denied();
    await store.row(id);
    return Response.json(
      {
        requestId: id,
        state: "verified",
        receipt: store.receipt(row),
        expiresAt: row.receipt_expires_at.toISOString(),
        expected: row.binding.expected,
        command: row.binding.command,
        capabilityDecisionId: row.binding.capabilityDecisionId,
      },
      { headers: noStore },
    );
  } catch {
    return failure();
  }
}
/** Observe original intent without issuing a challenge, refreshing a credential, or replaying an assertion. */
export async function observeOperationsAction(request: Request, id: string, family: OperationsActionFamily = "settlement") {
  try {
    purpose(request, familyPurpose[family].bff);
    if (!uuid.test(id)) throw denied();
    const value = await input(request, ["idToken", "accessToken", "nonce", "clientId", "expected", "command"]);
    if (
      !operationsExpected(value.expected, family) ||
      !operationsCommand(value.command, family) ||
      !["idToken", "accessToken", "nonce", "clientId"].every((k) => typeof value[k] === "string")
    )
      throw denied();
    const proofs = { idToken: value.idToken, accessToken: value.accessToken, nonce: value.nonce, clientId: value.clientId },
      store = operationsActionStore();
    const currentBinding = async () => {
      const current = await admission(proofs);
      if (
        workforceAssertionHash(expected(current, value.expected.action, value.expected.payloadHash, family)) !==
        workforceAssertionHash(value.expected)
      )
        throw denied();
      return {
        current,
        binding: await readOperationsActionAuthority(value.expected, value.command, proofs),
      };
    };
    const initial = await currentBinding(),
      original = await store.observe(id, initial.binding, initial.current.requestId);
    let providerRetirement: "not_started" | "pending" | "confirmed" = "not_started",
      observed: Session | undefined;
    if (original?.provider_started_at) {
      providerRetirement = "pending";
      const { p, serviceConfig } = await providerConfig();
      if (original.provider_session_id) {
        try {
          observed = (await getSession({ serviceConfig, sessionId: original.provider_session_id, sessionToken: "" }))
            .session;
          if (!observed) throw denied();
        } catch (error) {
          if (!isClassifiedError(error) || error.code !== Code.NotFound) throw error;
          providerRetirement = "confirmed";
        }
      } else {
        observed = await (
          await workforceProvider(serviceConfig, p.organizationId)
        ).inspectActionIntent(id, original.provider_subject, "paypm_operations_action_intent");
      }
      if (observed) {
        const created = providerTimestampMs(observed.creationDate),
          expires = providerTimestampMs(observed.expirationDate),
          verified = providerTimestampMs(observed.factors?.user?.verifiedAt);
        if (
          (original.provider_session_id && observed.id !== original.provider_session_id) ||
          observed.factors?.user?.id !== original.provider_subject ||
          observed.factors.user.organizationId !== p.organizationId ||
          new TextDecoder().decode(observed.metadata["paypm_operations_action_intent"]) !== id ||
          created === undefined ||
          created > Date.now() ||
          expires === undefined ||
          expires <= created ||
          verified === undefined ||
          verified < created ||
          verified > Date.now()
        )
          throw denied();
        if (expires <= Date.now()) providerRetirement = "confirmed";
      }
    }
    const final = await currentBinding();
    if (workforceAssertionHash(initial.binding) !== workforceAssertionHash(final.binding)) throw denied();
    const row = await store.observe(id, final.binding, final.current.requestId);
    let state: "not_started" | "pending" | "verified" | "consumed" | "cancelled" | "expired" | "retired" = "not_started";
    if (row) {
      const raced =
        !original ||
        original.provider_started_at?.getTime() !== row.provider_started_at?.getTime() ||
        original.provider_session_id !== row.provider_session_id;
      if (raced) providerRetirement = row.provider_started_at ? "pending" : "not_started";
      const expired =
        row.expires_at.getTime() <= Date.now() || (row.receipt_expires_at?.getTime() ?? Infinity) <= Date.now();
      if (row.consumed_at) state = "consumed";
      else if (row.state === "cancelled") state = "cancelled";
      else if (row.state === "retired" || expired)
        state = providerRetirement === "pending" ? "pending" : expired ? "expired" : "retired";
      else if (providerRetirement === "confirmed") state = "retired";
      else if (row.state === "verified" && !raced && observed && providerRetirement === "pending") {
        if (accepted(observed, row).getTime() !== row.verified_at?.getTime()) throw denied();
        state = "verified";
      } else state = row.state === "reserved" && !row.provider_started_at ? "not_started" : "pending";
    }
    return Response.json(
      {
        requestId: id,
        state,
        expected: final.binding.expected,
        command: final.binding.command,
        capabilityDecisionId: final.binding.capabilityDecisionId,
        requestExpiresAt: row?.expires_at.toISOString() ?? null,
        receiptExpiresAt: row?.receipt_expires_at?.toISOString() ?? null,
        providerRetirement,
        checkedAt: new Date().toISOString(),
      },
      { headers: noStore },
    );
  } catch {
    return failure();
  }
}
export async function readOperationsPublicChallenge(request: Request, id: string, capability: string) {
  try {
    if (!uuid.test(id)) throw denied();
    policy();
    const store = operationsActionStore(),
      row = await store.capability(id, capability);
    if (row.state !== "created") throw denied();
    await live(row);
    await store.row(id);
    return Response.json(
      {
        requestId: id,
        action: row.binding.expected.action,
        publicKey: store.provider(row).publicKey,
        expiresAt: row.expires_at.toISOString(),
        returnUrl: new URL(store.caller(row).callbackUrl).origin,
      },
      { headers: noStore },
    );
  } catch {
    return failure();
  }
}
export async function completeOperationsPublicAction(request: Request, id: string) {
  try {
    const { p, serviceConfig } = await providerConfig();
    if (request.headers.get("origin") !== p.origin || !uuid.test(id)) throw denied();
    const value = await input(request, ["capability", "assertion"]);
    if (
      typeof value.capability !== "string" ||
      !value.assertion ||
      typeof value.assertion !== "object" ||
      Array.isArray(value.assertion)
    )
      throw denied();
    const store = operationsActionStore();
    let row = await store.capability(id, value.capability);
    if (!["created", "verified"].includes(row.state)) throw denied();
    await live(row);
    const provider = store.provider(row);
    if (!assertionValid(value.assertion, provider.publicKey.challenge as string)) throw denied();
    const attempt = await store.attempt(id, value.assertion);
    row = attempt.row;
    let token = "";
    if (attempt.first) {
      try {
        const result = await setSession({
          serviceConfig,
          sessionId: provider.sessionId,
          sessionToken: provider.sessionToken,
          challenges: undefined,
          checks: create(ChecksSchema, { webAuthN: { credentialAssertionData: value.assertion } }),
          metadata: { ["paypm_operations_action_accept_" + id]: new TextEncoder().encode(row.assertion_hash!) },
          lifetime: sessionLifetime({
            seconds: BigInt(Math.floor((row.expires_at.getTime() - Date.now()) / 1000)),
            nanos: 0,
          } as Duration),
        });
        token = result.sessionToken;
      } catch (error) {
        if (isClassifiedError(error) && error.isUserError) {
          await store.retire(id);
          throw denied();
        }
      }
    }
    const result = await getSession({ serviceConfig, sessionId: provider.sessionId, sessionToken: token }),
      verifiedAt = accepted(result.session, row);
    await live(row);
    row = await store.verified(id, verifiedAt);
    const caller = store.caller(row),
      url = new URL(caller.callbackUrl);
    url.searchParams.set("requestId", id);
    url.searchParams.set("state", caller.callbackState);
    return Response.json({ callbackUrl: url.href }, { headers: noStore });
  } catch {
    return failure();
  }
}
export async function consumeOperationsAction(
  request: Request,
  readback = false,
  family: OperationsActionFamily = "settlement",
) {
  try {
    purpose(request, familyPurpose[family].consumer);
    const value = await input(request, ["receipt", "expected", "command"]);
    if (
      typeof value.receipt !== "string" ||
      !/^paypm-ops1\.[A-Za-z0-9_-]{43}$/.test(value.receipt) ||
      !operationsExpected(value.expected, family) ||
      !operationsCommand(value.command, family)
    )
      throw denied();
    const store = operationsActionStore(),
      row = await store.byReceipt(value.receipt);
    if (
      workforceAssertionHash(row.binding.expected) !== workforceAssertionHash(value.expected) ||
      workforceAssertionHash(row.binding.command) !== workforceAssertionHash(value.command)
    )
      throw denied();
    await live(row);
    const { serviceConfig } = await providerConfig(),
      session = await getSession({ serviceConfig, sessionId: row.provider_session_id!, sessionToken: "" });
    if (accepted(session.session, row).getTime() !== row.verified_at?.getTime()) throw denied();
    const consumed = await store.consume(value.receipt, row.binding, readback);
    return Response.json(receiptResponse(consumed), { headers: noStore });
  } catch {
    return failure();
  }
}
export async function cancelOperationsPublicAction(request: Request, id: string) {
  try {
    const p = policy();
    if (request.headers.get("origin") !== p.origin || !uuid.test(id)) throw denied();
    const value = await input(request, ["capability"]);
    if (typeof value.capability !== "string") throw denied();
    const store = operationsActionStore(),
      row = await store.capability(id, value.capability, true);
    await live(row, true);
    const caller = store.caller(row);
    await store.cancel(id);
    const url = new URL(caller.callbackUrl);
    url.searchParams.set("requestId", id);
    url.searchParams.set("state", caller.callbackState);
    return Response.json({ callbackUrl: url.href }, { headers: noStore });
  } catch {
    return failure();
  }
}
export async function cleanupOperationsActions(request: Request) {
  try {
    purpose(request, "PAYPM_OPERATIONS_ACTION_CONSUMER_TOKEN");
    await input(request, []);
    const { p, serviceConfig } = await providerConfig();
    await operationsActionStore().clearExpired();
    await flushWorkforceRevocations(workforceStore(), await workforceProvider(serviceConfig, p.organizationId));
    return Response.json({ completed: true }, { headers: noStore });
  } catch {
    return failure();
  }
}
