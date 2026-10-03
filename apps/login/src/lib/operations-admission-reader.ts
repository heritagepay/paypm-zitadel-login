import { UserState } from "@zitadel/proto/zitadel/user/v2/user_pb";
import { headers } from "next/headers";
import { timingSafeEqual } from "node:crypto";
import "server-only";
import { providerTimestampMs, verifiedFactor } from "./authentication-policy";
import { verifyOperationsOidcProof } from "./operations-oidc-proof";
import { mintOperationsRetirementProof, type OperationsRetirementAdmission } from "./operations-retirement-proof";
import { getServiceConfig } from "./service-url";
import { identityWorkforceEligibility, workforceClientMode, workforcePolicy } from "./workforce-policy";
import { workforceProvider } from "./workforce-provider";
import { workforceStore } from "./workforce-store";
import { getUserByID } from "./zitadel";

type OperationsClient = {
  clientId: string;
  appId: string;
  deploymentId: string;
  environment: "production" | "staging" | "sandbox";
};
function registeredClient(clientId: string): OperationsClient | undefined {
  try {
    const rows: unknown = JSON.parse(process.env.PAYPM_OPERATIONS_OIDC_CLIENT_POLICIES_JSON ?? "null");
    if (!Array.isArray(rows) || rows.length === 0 || rows.length > 16) return undefined;
    const seen = new Set<string>();
    for (const row of rows) {
      if (
        !row ||
        typeof row !== "object" ||
        Array.isArray(row) ||
        Object.keys(row).sort().join(",") !== "appId,clientId,deploymentId,environment" ||
        typeof row.clientId !== "string" ||
        !/^[A-Za-z0-9._:@-]{1,200}$/.test(row.clientId) ||
        seen.has(row.clientId) ||
        !workforceClientMode(row.clientId) ||
        typeof row.appId !== "string" ||
        !/^[a-z][a-z0-9_.-]{0,127}$/.test(row.appId) ||
        typeof row.deploymentId !== "string" ||
        !/^[a-z0-9_]{1,128}$/.test(row.deploymentId) ||
        !["production", "staging", "sandbox"].includes(row.environment)
      )
        return undefined;
      seen.add(row.clientId);
    }
    return rows.find((row) => row.clientId === clientId);
  } catch {
    return undefined;
  }
}

/** Credential and current admission proof only. Operations permissions stay with their owning API. */
export async function readOperationsAdmission(request: Request): Promise<Response> {
  const deny = () => Response.json({ active: false }, { status: 403, headers: { "cache-control": "no-store" } });
  try {
    const policy = workforcePolicy(),
      secret = process.env.PAYPM_OPERATIONS_ADMISSION_READER_TOKEN;
    if (
      !policy?.emailOtpReady ||
      !secret ||
      secret.length < 32 ||
      [
        process.env.PAYPM_WORKFORCE_ADMISSION_READER_TOKEN,
        process.env.PAYPM_WORKFORCE_IDENTITY_CLIENT_SECRET,
        process.env.PAYPM_OPERATIONS_INTROSPECTION_CLIENT_SECRET,
        process.env.PAYPM_WORKFORCE_FLOW_KEY_BASE64,
        process.env.PAYPM_WORKFORCE_STORE_KEY_BASE64,
      ].includes(secret)
    )
      return deny();
    const actual = Buffer.from(request.headers.get("authorization") ?? ""),
      expected = Buffer.from(`Bearer ${secret}`);
    if (actual.length !== expected.length || !timingSafeEqual(actual, expected)) return deny();
    const raw = await request.text();
    if (Buffer.byteLength(raw) > 32768) return deny();
    const input = JSON.parse(raw);
    if (
      !input ||
      typeof input !== "object" ||
      Array.isArray(input) ||
      Object.keys(input).sort().join(",") !== "accessToken,clientId,idToken,nonce" ||
      !Object.values(input).every((value) => typeof value === "string" && value.length > 0)
    )
      return deny();
    const client = registeredClient(input.clientId);
    if (!client) return deny();
    const proof = await verifyOperationsOidcProof(input, policy.issuer);
    const store = workforceStore(),
      tuple = {
        issuer: proof.issuer,
        providerSubject: proof.providerSubject,
        baseSessionId: proof.baseSessionId,
        clientId: proof.clientId,
      };
    const admission = await store.currentAdmission(tuple);
    if (!admission) return deny();
    const { serviceConfig } = getServiceConfig(await headers());
    if (new URL(serviceConfig.baseUrl).origin !== policy.issuer) return deny();
    const row = await store.challenge(admission.challenge_id),
      provider = await workforceProvider(serviceConfig, policy.organizationId);
    const session = await provider.read(row);
    if (
      session.id !== proof.baseSessionId ||
      session.factors?.user?.id !== proof.providerSubject ||
      session.factors.user.organizationId !== policy.organizationId ||
      !verifiedFactor(session, session.factors.otpEmail?.verifiedAt) ||
      Math.floor(providerTimestampMs(session.factors.otpEmail?.verifiedAt) ?? 0) !== admission.verified_at.getTime()
    )
      return deny();
    const { user } = await getUserByID({ serviceConfig, userId: proof.providerSubject });
    if (
      !user ||
      user.state !== UserState.ACTIVE ||
      user.type.case !== "human" ||
      user.details?.resourceOwner !== policy.organizationId ||
      user.type.value.email?.isVerified !== true
    )
      return deny();
    const eligibility = await identityWorkforceEligibility.resolve({
      issuer: proof.issuer,
      subject: proof.providerSubject,
      clientId: proof.clientId,
      purpose: "login",
    });
    if (
      eligibility?.eligible !== true ||
      eligibility.organizationId !== policy.organizationId ||
      !/^[a-f0-9]{8}-[a-f0-9]{4}-[1-8][a-f0-9]{3}-[89ab][a-f0-9]{3}-[a-f0-9]{12}$/i.test(eligibility.personId)
    )
      return deny();
    // Only verified current use advances idle activity; logout/disable wins this final SQL check.
    if (!(await store.admission(proof.baseSessionId, proof.providerSubject, proof.clientId, admission.request_id)))
      return deny();
    const current = await store.currentAdmission(tuple);
    if (!current || String(current.epoch) !== String(admission.epoch)) return deny();
    const evidence: OperationsRetirementAdmission = {
      active: true,
      ...proof,
      personId: eligibility.personId,
      plane: "workforce",
      ...client,
      contextId: policy.organizationId,
      requestId: current.request_id,
      challengeId: current.challenge_id,
      authenticationClass: "workforce_limited",
      verifiedAt: current.verified_at.toISOString(),
      absoluteExpiresAt: current.absolute_expires_at.toISOString(),
      checkedAt: new Date().toISOString(),
      revocationVersion: String(current.epoch),
    };
    return Response.json(evidence, {
      headers: {
        "cache-control": "no-store",
        "X-PayPM-Operations-Retirement-Proof": mintOperationsRetirementProof(evidence),
      },
    });
  } catch {
    return deny();
  }
}
