import { headers } from "next/headers";
import "server-only";
import { readIdentityAdmission } from "./identity-admission-reader";
import { IdentityLogoutStore, type IdentityProofPair } from "./identity-logout-store";
import { identityPrivatePurpose } from "./identity-private-purpose";
import { getServiceConfig } from "./service-url";
import { workforcePolicy } from "./workforce-policy";
import { workforceProvider } from "./workforce-provider";
import { workforceStore } from "./workforce-store";
export async function logoutIdentitySession(request: Request) {
  const noStore = { "cache-control": "no-store" };
  try {
    identityPrivatePurpose(request, "PAYPM_IDENTITY_LOGOUT_TOKEN");
    const raw = await request.text();
    if (Buffer.byteLength(raw) > 32768) throw new Error();
    const input = JSON.parse(raw) as IdentityProofPair;
    if (
      !input ||
      typeof input !== "object" ||
      Array.isArray(input) ||
      Object.keys(input).sort().join(",") !== "accessToken,clientId,idToken,nonce" ||
      !Object.values(input).every((value) => typeof value === "string" && value.length > 0)
    )
      throw new Error();
    const workforce = workforceStore(),
      store = new IdentityLogoutStore(workforce.sql);
    let row = await store.read(input);
    if (!row) {
      const response = await readIdentityAdmission(
        new Request("https://login.invalid/identity-admission", {
          method: "POST",
          headers: { authorization: `Bearer ${process.env.PAYPM_IDENTITY_ADMISSION_READER_TOKEN ?? ""}` },
          body: JSON.stringify(input),
        }),
      );
      if (!response.ok) throw new Error();
      row = await store.revoke(input, await response.json());
    }
    let pending = await store.pending(row);
    if (pending.length) {
      try {
        const policy = workforcePolicy(),
          { serviceConfig } = getServiceConfig(await headers());
        if (
          !policy ||
          new URL(serviceConfig.baseUrl).origin !== row.admission.issuer ||
          policy.organizationId !== row.admission.contextId
        )
          throw new Error();
        const provider = await workforceProvider(serviceConfig, policy.organizationId);
        for (const item of pending)
          if (await provider.retireOwnedSession(item.provider_session_id, row.admission.providerSubject))
            await workforce.revocationCompleted(item.provider_session_id);
      } catch {
        /* Committed local retirement and provider queue survive uncertainty. */
      }
      pending = await store.pending(row);
    }
    const a = row.admission;
    return Response.json(
      {
        state: "revoked",
        personId: a.personId,
        issuer: a.issuer,
        providerSubject: a.providerSubject,
        baseSessionId: a.baseSessionId,
        clientId: a.clientId,
        contextId: a.contextId,
        appId: a.appId,
        deploymentId: a.deploymentId,
        environment: a.environment,
        revocationVersion: a.revocationVersion,
        revokedAt: row.revoked_at.toISOString(),
        providerRetirement: pending.length ? "pending" : "confirmed",
        checkedAt: new Date().toISOString(),
      },
      { status: pending.length ? 503 : 200, headers: noStore },
    );
  } catch {
    return Response.json({ error: "Identity logout unavailable" }, { status: 403, headers: noStore });
  }
}
