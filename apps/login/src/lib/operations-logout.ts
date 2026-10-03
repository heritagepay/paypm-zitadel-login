import { headers } from "next/headers";
import { createHash, timingSafeEqual } from "node:crypto";
import "server-only";
import { OperationsLogoutStore, type LogoutAdmission, type LogoutInput } from "./operations-logout-store";
import { verifyOperationsRetirementProof } from "./operations-retirement-proof";
import { getServiceConfig } from "./service-url";
import { workforcePolicy } from "./workforce-policy";
import { workforceProvider } from "./workforce-provider";
import { workforceStore } from "./workforce-store";
const denied = () => new Error("Operations logout unavailable");
export async function logoutOperationsSession(request: Request, readback = false) {
  const noStore = { "cache-control": "no-store" };
  try {
    const policy = workforcePolicy(),
      secret = process.env.PAYPM_OPERATIONS_LOGOUT_TOKEN;
    if (
      !policy ||
      !secret ||
      secret.length < 32 ||
      [
        "PAYPM_OPERATIONS_ACTION_BFF_TOKEN",
        "PAYPM_OPERATIONS_ACTION_CONSUMER_TOKEN",
        "PAYPM_OPERATIONS_ADMISSION_READER_TOKEN",
        "PAYPM_OPERATIONS_INTROSPECTION_CLIENT_SECRET",
        "PAYPM_WORKFORCE_IDENTITY_CLIENT_SECRET",
        "PAYPM_WORKFORCE_ADMISSION_READER_TOKEN",
        "PAYPM_WORKFORCE_STORE_KEY_BASE64",
        "PAYPM_OPERATIONS_STORE_KEY_BASE64",
        "PAYPM_OPERATIONS_ACTION_AUTHORITY_API_KEY",
        "PAYPM_OPERATIONS_GRANT_BFF_TOKEN",
        "PAYPM_OPERATIONS_GRANT_CONSUMER_TOKEN",
        "PAYPM_OPERATIONS_GRANT_AUTHORITY_API_KEY",
        "PAYPM_OPERATIONS_DEPLOYMENT_GRANT_BFF_TOKEN",
        "PAYPM_OPERATIONS_DEPLOYMENT_GRANT_CONSUMER_TOKEN",
        "PAYPM_OPERATIONS_DEPLOYMENT_GRANT_AUTHORITY_API_KEY",
        "PAYPM_OPERATIONS_KYC_GRANT_BFF_TOKEN",
        "PAYPM_OPERATIONS_KYC_ACTION_BFF_TOKEN",
        "PAYPM_OPERATIONS_KYC_GRANT_CONSUMER_TOKEN",
        "PAYPM_OPERATIONS_KYC_ACTION_CONSUMER_TOKEN",
        "PAYPM_OPERATIONS_KYC_GRANT_AUTHORITY_API_KEY",
        "PAYPM_OPERATIONS_KYC_ACTION_AUTHORITY_API_KEY",
        "PAYPM_OPERATIONS_RETIREMENT_PROOF_KEY_BASE64",
      ].some((k) => process.env[k] === secret)
    )
      throw denied();
    const actual = Buffer.from(request.headers.get("authorization") ?? ""),
      expected = Buffer.from("Bearer " + secret);
    if (actual.length !== expected.length || !timingSafeEqual(actual, expected)) throw denied();
    const raw = await request.text();
    if (Buffer.byteLength(raw) > 32768) throw denied();
    const input = JSON.parse(raw) as LogoutInput;
    if (
      !input ||
      typeof input !== "object" ||
      Array.isArray(input) ||
      Object.keys(input).sort().join(",") !== "accessToken,clientId,idToken,nonce,operationKey,requestId,retirementProof" ||
      !Object.values(input).every((v) => typeof v === "string" && v.length > 0) ||
      ![input.requestId, input.operationKey].every((v) =>
        /^[a-f0-9]{8}-[a-f0-9]{4}-4[a-f0-9]{3}-[89ab][a-f0-9]{3}-[a-f0-9]{12}$/i.test(v),
      )
    )
      throw denied();
    const store = workforceStore(),
      logout = new OperationsLogoutStore(store.sql);
    let row = await logout.read(input);
    if (!row) {
      const a = verifyOperationsRetirementProof(input.retirementProof);
      const hash = (v: string) => createHash("sha256").update(v).digest("hex");
      if (
        a.clientId !== input.clientId ||
        a.issuer !== policy.issuer ||
        a.contextId !== policy.organizationId ||
        a.idTokenHash !== hash(input.idToken) ||
        a.accessTokenHash !== hash(input.accessToken) ||
        a.nonceHash !== hash(input.nonce)
      )
        throw denied();
      if (readback) return Response.json({ code: "operations_logout_not_found" }, { status: 404, headers: noStore });
      row = await logout.revoke(input, a as LogoutAdmission);
    }
    let pending = await logout.pending(row);
    if (pending.length) {
      try {
        const { serviceConfig } = getServiceConfig(await headers());
        if (new URL(serviceConfig.baseUrl).origin !== row.issuer) throw denied();
        const provider = await workforceProvider(serviceConfig, policy.organizationId);
        for (const item of pending) {
          if (await provider.retireOwnedSession(item.provider_session_id, row.provider_subject))
            await store.revocationCompleted(item.provider_session_id);
        }
      } catch {
        /* Local revocation is durable; uncertain provider work remains queued. */
      }
      pending = await logout.pending(row);
    }
    return Response.json(
      {
        requestId: row.request_id,
        operationKey: row.operation_key,
        personId: row.person_id,
        issuer: row.issuer,
        providerSubject: row.provider_subject,
        baseSessionId: row.base_session_id,
        clientId: row.client_id,
        appId: row.app_id,
        deploymentId: row.deployment_id,
        environment: row.environment,
        contextId: row.context_id,
        state: "revoked",
        revokedAt: row.revoked_at.toISOString(),
        providerRetirement: pending.length ? "pending" : "confirmed",
        checkedAt: new Date().toISOString(),
      },
      { headers: noStore },
    );
  } catch {
    return Response.json({ error: "Operations logout unavailable" }, { status: 403, headers: noStore });
  }
}
