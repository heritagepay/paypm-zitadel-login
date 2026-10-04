import { timingSafeEqual } from "node:crypto";
import "server-only";
export type IdentityPrivatePurpose =
  | "PAYPM_IDENTITY_ADMISSION_READER_TOKEN"
  | "PAYPM_IDENTITY_LOGOUT_TOKEN"
  | "PAYPM_IDENTITY_ACTION_BFF_TOKEN"
  | "PAYPM_IDENTITY_ACTION_CONSUMER_TOKEN";
export function identityPrivatePurpose(request: Request, name: IdentityPrivatePurpose) {
  const secret = process.env[name];
  const otherNames = Object.keys(process.env).filter(
    (key) =>
      key !== name &&
      /^PAYPM_(?:OPERATIONS|WORKFORCE|IDENTITY|LEGACY)_/.test(key) &&
      /(?:TOKEN|SECRET|KEY_BASE64|API_KEY)$/.test(key),
  );
  if (!secret || secret.length < 32 || otherNames.some((key) => process.env[key] === secret))
    throw new Error("Identity private purpose unavailable");
  const actual = Buffer.from(request.headers.get("authorization") ?? ""),
    expected = Buffer.from(`Bearer ${secret}`);
  if (actual.length !== expected.length || !timingSafeEqual(actual, expected))
    throw new Error("Identity private purpose unavailable");
}
