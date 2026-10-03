import { createCipheriv, createDecipheriv, hkdfSync, randomBytes } from "crypto";
import { cookies } from "next/headers";
import "server-only";
import { validLegacyEligibility, type LegacyMigrationEligibility } from "./legacy-commercial-migration-client";
export type LegacyMigrationState = {
  requestId: string;
  proofSessionId: string;
  proofSessionToken: string;
  challenge: string;
  eligibility: LegacyMigrationEligibility;
  issuedAt: number;
  expiresAt: number;
  assertionHash?: string;
};
const name = "paypm_legacy_commercial_migration";
function key() {
  const encoded = process.env.PAYPM_LEGACY_MIGRATION_FLOW_KEY_BASE64,
    source = Buffer.from(encoded ?? "", "base64");
  if (
    source.length !== 32 ||
    source.toString("base64") !== encoded ||
    encoded === process.env.PAYPM_WORKFORCE_FLOW_KEY_BASE64
  )
    throw new Error("Legacy proof protection unavailable");
  return Buffer.from(
    hkdfSync("sha256", source, Buffer.alloc(0), Buffer.from("paypm-legacy-commercial-migration-cookie-v1"), 32),
  );
}
export function encryptLegacyMigrationState(state: LegacyMigrationState) {
  const iv = randomBytes(12),
    cipher = createCipheriv("aes-256-gcm", key(), iv);
  cipher.setAAD(Buffer.from(name));
  const body = Buffer.concat([cipher.update(JSON.stringify(state), "utf8"), cipher.final()]);
  return Buffer.concat([iv, cipher.getAuthTag(), body]).toString("base64url");
}
export function decryptLegacyMigrationState(value: string | undefined): LegacyMigrationState | undefined {
  try {
    if (!value || value.length > 8192) return undefined;
    const bytes = Buffer.from(value, "base64url"),
      decipher = createDecipheriv("aes-256-gcm", key(), bytes.subarray(0, 12));
    decipher.setAAD(Buffer.from(name));
    decipher.setAuthTag(bytes.subarray(12, 28));
    const s = JSON.parse(
      Buffer.concat([decipher.update(bytes.subarray(28)), decipher.final()]).toString("utf8"),
    ) as LegacyMigrationState;
    if (
      ![s.requestId, s.proofSessionId, s.proofSessionToken, s.challenge].every(
        (x) => typeof x === "string" && x.length > 0 && x.length <= 1024,
      ) ||
      !Number.isSafeInteger(s.issuedAt) ||
      !Number.isSafeInteger(s.expiresAt) ||
      s.issuedAt > Date.now() ||
      s.expiresAt <= Date.now() ||
      s.expiresAt - s.issuedAt > 300000 ||
      (s.assertionHash !== undefined && !/^[a-f0-9]{64}$/.test(s.assertionHash))
    )
      return undefined;
    validLegacyEligibility(s.eligibility, s.eligibility);
    return s;
  } catch {
    return undefined;
  }
}
export async function storeLegacyMigrationState(state: LegacyMigrationState) {
  (await cookies()).set({
    name,
    value: encryptLegacyMigrationState(state),
    httpOnly: true,
    secure: true,
    sameSite: "strict",
    path: "/",
    maxAge: 300,
  });
}
export async function getLegacyMigrationState() {
  return decryptLegacyMigrationState((await cookies()).get(name)?.value);
}
export async function deleteLegacyMigrationState() {
  (await cookies()).delete(name);
}
