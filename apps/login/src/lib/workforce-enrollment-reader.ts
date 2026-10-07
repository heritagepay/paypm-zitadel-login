import { headers } from "next/headers";
import { timingSafeEqual } from "node:crypto";
import "server-only";
import { providerTimestampMs, verifiedFactor } from "./authentication-policy";
import { getServiceConfig } from "./service-url";
import { workforceAssertionHash } from "./workforce-assertion";
import { enrollmentRuntime, enrollmentUuid } from "./workforce-enrollment-identity-client";
import { workforceEnrollmentStore } from "./workforce-enrollment-store";
import { workforcePolicy } from "./workforce-policy";
import { workforceProvider } from "./workforce-provider";
export async function readCurrentWorkforceEnrollment(request: Request): Promise<Response> {
  const denied = () => Response.json({ active: false }, { status: 403, headers: { "cache-control": "no-store" } });
  let timer: ReturnType<typeof setTimeout> | undefined;
  try {
    const runtime = enrollmentRuntime(),
      policy = workforcePolicy(),
      secret = process.env.PAYPM_WORKFORCE_ENROLLMENT_CEREMONY_READER_TOKEN;
    if (
      !runtime ||
      !policy?.emailOtpReady ||
      !secret ||
      secret.length < 32 ||
      request.headers.has("origin") ||
      request.headers.has("cookie") ||
      Object.entries(process.env).some(
        ([k, v]) =>
          k !== "PAYPM_WORKFORCE_ENROLLMENT_CEREMONY_READER_TOKEN" && /(?:SECRET|TOKEN|KEY_BASE64)$/.test(k) && v === secret,
      )
    )
      return denied();
    const expected = Buffer.from("Bearer " + secret),
      actual = Buffer.from(request.headers.get("authorization") ?? "");
    if (expected.length !== actual.length || !timingSafeEqual(expected, actual)) return denied();
    const work = async () => {
      const reader = request.body?.getReader();
      if (!reader) throw new Error("Body required");
      let size = 0;
      const chunks: Uint8Array[] = [];
      try {
        while (true) {
          const p = await reader.read();
          if (p.done) break;
          size += p.value.byteLength;
          if (size > 4096) throw new Error("Body exceeds cap");
          chunks.push(p.value);
        }
      } finally {
        await reader.cancel();
      }
      const body = JSON.parse(Buffer.concat(chunks).toString("utf8"));
      if (!body || Object.keys(body).join(",") !== "enrollmentId" || !enrollmentUuid(body.enrollmentId))
        throw new Error("Original enrollment required");
      const store = workforceEnrollmentStore(),
        ceremony = await store.ceremony(body.enrollmentId);
      if (
        ceremony.issuer !== policy.issuer ||
        ceremony.organizationId !== policy.organizationId ||
        !policy.clientIds.includes(ceremony.clientId) ||
        ceremony.sourceRevision !== runtime.sourceRevision ||
        ceremony.imageDigest !== runtime.imageDigest ||
        ceremony.configurationSha256 !== runtime.configurationSha256
      )
        throw new Error("Loaded ceremony changed");
      const { serviceConfig } = getServiceConfig(await headers());
      if (new URL(serviceConfig.baseUrl).origin !== policy.issuer) throw new Error("Registered issuer required");
      const provider = await workforceProvider(serviceConfig, policy.organizationId),
        row = await store.base.currentEnrollmentChallenge(ceremony.challengeId),
        session = await provider.read(row);
      const metadata = new TextDecoder().decode(session.metadata["paypm_workforce_enrollment_" + row.id]);
      if (
        metadata !== workforceAssertionHash(ceremony) ||
        !verifiedFactor(session, session.factors?.otpEmail?.verifiedAt) ||
        Math.floor(providerTimestampMs(session.factors?.otpEmail?.verifiedAt) ?? 0) !== row.verified_at?.getTime()
      )
        throw new Error("Actual accepted enrollment factor required");
      if (workforceAssertionHash(await store.ceremony(body.enrollmentId)) !== workforceAssertionHash(ceremony))
        throw new Error("Enrollment retired during read");
      return Response.json(ceremony, { headers: { "cache-control": "no-store" } });
    };
    return await Promise.race([
      work(),
      new Promise<never>((_, reject) => {
        timer = setTimeout(() => reject(new Error("Enrollment read deadline")), 8000);
      }),
    ]);
  } catch {
    return denied();
  } finally {
    if (timer) clearTimeout(timer);
  }
}
