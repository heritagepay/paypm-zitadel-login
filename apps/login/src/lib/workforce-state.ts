import "server-only";

import { createHmac, timingSafeEqual } from "crypto";
import { cookies } from "next/headers";
import { FRESH_PASSKEY_MS, WEB_SESSION_ABSOLUTE_MS } from "./authentication-policy";

export type WorkforceState = {
  purpose: "email-challenge" | "limited-admission" | "passkey-challenge";
  sessionId: string;
  userId: string;
  clientId: string;
  requestId: string;
  issuedAt: number;
  expiresAt: number;
  challengeId?: string;
};

function flowKey(): Buffer {
  const encoded = process.env.PAYPM_WORKFORCE_FLOW_KEY_BASE64;
  if (!encoded) throw new Error("Workforce flow signing key unavailable");
  const key = Buffer.from(encoded, "base64");
  if (key.length !== 32 || key.toString("base64") !== encoded) throw new Error("Invalid workforce flow signing key");
  return key;
}

export function encodeWorkforceState(state: WorkforceState): string {
  const payload = Buffer.from(JSON.stringify(state)).toString("base64url");
  return `${payload}.${createHmac("sha256", flowKey()).update(payload).digest("base64url")}`;
}

export function decodeWorkforceState(value: string | undefined, now = Date.now()): WorkforceState | undefined {
  if (!value || value.length > 4096) return undefined;
  try {
    const [payload, signature, extra] = value.split(".");
    if (!payload || !signature || extra) return undefined;
    const expected = createHmac("sha256", flowKey()).update(payload).digest();
    const received = Buffer.from(signature, "base64url");
    if (received.length !== expected.length || !timingSafeEqual(received, expected)) return undefined;
    const state = JSON.parse(Buffer.from(payload, "base64url").toString("utf8")) as WorkforceState;
    if (!["email-challenge", "limited-admission", "passkey-challenge"].includes(state.purpose)) return undefined;
    if (state.challengeId !== undefined && !/^[0-9a-f-]{36}$/.test(state.challengeId)) return undefined;
    if (
      ![state.sessionId, state.userId, state.clientId, state.requestId].every(
        (field) => typeof field === "string" && field.length > 0 && field.length <= 500,
      )
    )
      return undefined;
    if (
      !Number.isSafeInteger(state.issuedAt) ||
      !Number.isSafeInteger(state.expiresAt) ||
      state.issuedAt > now ||
      state.expiresAt <= now ||
      state.expiresAt <= state.issuedAt
    )
      return undefined;
    const maximum =
      state.purpose === "limited-admission"
        ? WEB_SESSION_ABSOLUTE_MS
        : state.purpose === "passkey-challenge"
          ? FRESH_PASSKEY_MS
          : 5 * 60 * 1000;
    if (state.expiresAt - state.issuedAt > maximum) return undefined;
    return state;
  } catch {
    return undefined;
  }
}

export async function writeWorkforceState(state: WorkforceState) {
  const jar = await cookies();
  jar.set({
    name: "paypm_workforce_flow",
    value: encodeWorkforceState(state),
    httpOnly: true,
    secure: process.env.NODE_ENV === "production",
    sameSite: "lax",
    path: "/",
    maxAge: Math.max(0, Math.floor((state.expiresAt - Date.now()) / 1000)),
  });
}

export async function readWorkforceState() {
  const jar = await cookies();
  return decodeWorkforceState(jar.get("paypm_workforce_flow")?.value);
}
export async function deleteWorkforceState() {
  const jar = await cookies();
  jar.delete("paypm_workforce_flow");
}
