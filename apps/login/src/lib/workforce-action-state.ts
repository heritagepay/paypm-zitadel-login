import { createCipheriv, createDecipheriv, hkdfSync, randomBytes } from "crypto";
import { cookies } from "next/headers";
import "server-only";
export type WorkforceActionState = {
  requestId: string;
  baseSessionId: string;
  stepSessionId: string;
  stepSessionToken: string;
  userId: string;
  clientId: string;
  challenge: string;
  issuedAt: number;
  expiresAt: number;
};
const cookieName = "paypm_workforce_action";
function key() {
  const encoded = process.env.PAYPM_WORKFORCE_FLOW_KEY_BASE64;
  const source = Buffer.from(encoded ?? "", "base64");
  if (source.length !== 32 || source.toString("base64") !== encoded) throw new Error("Action proof protection unavailable");
  return Buffer.from(hkdfSync("sha256", source, Buffer.alloc(0), Buffer.from("paypm-workforce-action-cookie-v1"), 32));
}
export function encryptActionState(state: WorkforceActionState) {
  const iv = randomBytes(12);
  const cipher = createCipheriv("aes-256-gcm", key(), iv);
  cipher.setAAD(Buffer.from(cookieName));
  const body = Buffer.concat([cipher.update(JSON.stringify(state), "utf8"), cipher.final()]);
  return Buffer.concat([iv, cipher.getAuthTag(), body]).toString("base64url");
}
export function decryptActionState(value: string | undefined, now = Date.now()): WorkforceActionState | undefined {
  try {
    if (!value || value.length > 8192) return undefined;
    const bytes = Buffer.from(value, "base64url");
    if (bytes.length < 29) return undefined;
    const decipher = createDecipheriv("aes-256-gcm", key(), bytes.subarray(0, 12));
    decipher.setAAD(Buffer.from(cookieName));
    decipher.setAuthTag(bytes.subarray(12, 28));
    const state = JSON.parse(
      Buffer.concat([decipher.update(bytes.subarray(28)), decipher.final()]).toString("utf8"),
    ) as WorkforceActionState;
    if (
      ![
        state.requestId,
        state.baseSessionId,
        state.stepSessionId,
        state.stepSessionToken,
        state.userId,
        state.clientId,
        state.challenge,
      ].every((x) => typeof x === "string" && x.length > 0 && x.length <= 1024) ||
      !Number.isSafeInteger(state.issuedAt) ||
      !Number.isSafeInteger(state.expiresAt) ||
      state.issuedAt > now ||
      state.expiresAt <= now ||
      state.expiresAt - state.issuedAt > 300000
    )
      return undefined;
    return state;
  } catch {
    return undefined;
  }
}
export async function storeActionState(state: WorkforceActionState) {
  const jar = await cookies();
  jar.set({
    name: cookieName,
    value: encryptActionState(state),
    httpOnly: true,
    secure: process.env.NODE_ENV === "production",
    sameSite: "strict",
    path: "/",
    maxAge: 300,
  });
}
export async function getActionState() {
  return decryptActionState((await cookies()).get(cookieName)?.value);
}
export async function deleteActionState() {
  (await cookies()).delete(cookieName);
}
