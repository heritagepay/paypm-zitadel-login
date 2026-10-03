import { headers } from "next/headers";
import { timingSafeEqual } from "node:crypto";
import "server-only";
import { providerTimestampMs, verifiedFactor } from "./authentication-policy";
import { getServiceConfig } from "./service-url";
import { workforceClientMode, workforcePolicy } from "./workforce-policy";
import { workforceProvider } from "./workforce-provider";
import { workforceStore } from "./workforce-store";
export async function readCurrentWorkforceAdmission(request: Request): Promise<Response> {
  const denied = () => Response.json({ active: false }, { status: 403, headers: { "cache-control": "no-store" } });
  try {
    const policy = workforcePolicy(),
      secret = process.env.PAYPM_WORKFORCE_ADMISSION_READER_TOKEN,
      bearer = request.headers.get("authorization");
    if (
      !policy?.emailOtpReady ||
      !secret ||
      secret.length < 32 ||
      [
        process.env.PAYPM_WORKFORCE_IDENTITY_CLIENT_SECRET,
        process.env.PAYPM_WORKFORCE_FLOW_KEY_BASE64,
        process.env.PAYPM_WORKFORCE_STORE_KEY_BASE64,
      ].includes(secret)
    )
      return denied();
    const actual = Buffer.from(bearer ?? ""),
      expected = Buffer.from("Bearer " + secret);
    if (actual.length !== expected.length || !timingSafeEqual(actual, expected)) return denied();
    const raw = await request.text();
    if (Buffer.byteLength(raw) > 4096) return denied();
    const input = JSON.parse(raw);
    if (
      !input ||
      typeof input !== "object" ||
      Array.isArray(input) ||
      Object.keys(input).sort().join(",") !== "baseSessionId,clientId,issuer,providerSubject" ||
      !Object.values(input).every((v) => typeof v === "string" && v.length > 0 && v.length <= 500) ||
      input.issuer !== policy.issuer ||
      !workforceClientMode(input.clientId)
    )
      return denied();
    const store = workforceStore(),
      current = await store.currentAdmission(input);
    if (!current) return denied();
    const { serviceConfig } = getServiceConfig(await headers());
    if (new URL(serviceConfig.baseUrl).origin !== new URL(policy.issuer).origin) return denied();
    const row = await store.challenge(current.challenge_id),
      provider = await workforceProvider(serviceConfig, policy.organizationId),
      session = await provider.read(row);
    if (
      session.id !== input.baseSessionId ||
      session.factors?.user?.id !== input.providerSubject ||
      !verifiedFactor(session, session.factors?.otpEmail?.verifiedAt) ||
      Math.floor(providerTimestampMs(session.factors?.otpEmail?.verifiedAt) ?? 0) !== current.verified_at.getTime()
    )
      return denied();
    if (!(await store.currentAdmission(input))) return denied();
    return Response.json(
      {
        active: true,
        ...input,
        requestId: current.request_id,
        challengeId: current.challenge_id,
        authenticationClass: "workforce_limited",
        verifiedAt: current.verified_at.toISOString(),
        absoluteExpiresAt: current.absolute_expires_at.toISOString(),
        checkedAt: new Date().toISOString(),
        revocationVersion: String(current.epoch),
      },
      { headers: { "cache-control": "no-store" } },
    );
  } catch {
    return denied();
  }
}
