import "server-only";

import { createCipheriv, createDecipheriv, hkdfSync, randomBytes } from "crypto";
import { cookies } from "next/headers";

type EnrollmentProof = { sessionId: string; userId: string; code: { id: string; code: string }; expiresAt: number };
const cookieName = "paypm_credential_enrollment";
function encryptionKey() {
  const encoded = process.env.PAYPM_LOGIN_ENROLLMENT_KEY_BASE64 ?? process.env.PAYPM_WORKFORCE_FLOW_KEY_BASE64;
  const source = Buffer.from(encoded ?? "", "base64");
  if (source.length !== 32 || source.toString("base64") !== encoded)
    throw new Error("Credential enrollment protection unavailable");
  return Buffer.from(
    hkdfSync("sha256", source, Buffer.alloc(0), Buffer.from("paypm-login-provider-credential-enrollment-v1"), 32),
  );
}

export function encryptEnrollmentProof(proof: EnrollmentProof) {
  const iv = randomBytes(12);
  const cipher = createCipheriv("aes-256-gcm", encryptionKey(), iv);
  cipher.setAAD(Buffer.from(cookieName));
  const ciphertext = Buffer.concat([cipher.update(JSON.stringify(proof), "utf8"), cipher.final()]);
  return Buffer.concat([iv, cipher.getAuthTag(), ciphertext]).toString("base64url");
}

export function decryptEnrollmentProof(encoded: string | undefined, now = Date.now()): EnrollmentProof | undefined {
  if (!encoded || encoded.length > 4096) return undefined;
  try {
    const data = Buffer.from(encoded, "base64url");
    if (data.length < 29) return undefined;
    const decipher = createDecipheriv("aes-256-gcm", encryptionKey(), data.subarray(0, 12));
    decipher.setAAD(Buffer.from(cookieName));
    decipher.setAuthTag(data.subarray(12, 28));
    const proof = JSON.parse(
      Buffer.concat([decipher.update(data.subarray(28)), decipher.final()]).toString("utf8"),
    ) as EnrollmentProof;
    if (
      ![proof.sessionId, proof.userId, proof.code?.id, proof.code?.code].every(
        (field) => typeof field === "string" && field.length > 0 && field.length <= 500,
      )
    )
      return undefined;
    if (!Number.isSafeInteger(proof.expiresAt) || proof.expiresAt <= now || proof.expiresAt > now + 300000) return undefined;
    return proof;
  } catch {
    return undefined;
  }
}

export async function storeEnrollmentProof(proof: EnrollmentProof) {
  const jar = await cookies();
  jar.set({
    name: cookieName,
    value: encryptEnrollmentProof(proof),
    httpOnly: true,
    secure: process.env.NODE_ENV === "production",
    sameSite: "lax",
    path: "/",
    maxAge: 300,
  });
}

export async function getEnrollmentProof(sessionId: string, userId: string) {
  const jar = await cookies();
  const proof = decryptEnrollmentProof(jar.get(cookieName)?.value);
  return proof?.sessionId === sessionId && proof.userId === userId ? proof : undefined;
}

export async function consumeEnrollmentProof() {
  const jar = await cookies();
  jar.delete(cookieName);
}
