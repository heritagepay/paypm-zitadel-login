import { createHash } from "node:crypto";
import "server-only";
const canonical = (v: unknown): string =>
  v === null || typeof v !== "object"
    ? JSON.stringify(v)
    : Array.isArray(v)
      ? `[${v.map((x) => canonical(x ?? null)).join(",")}]`
      : `{${Object.keys(v)
          .filter((k) => (v as Record<string, unknown>)[k] !== undefined)
          .sort()
          .map((k) => JSON.stringify(k) + ":" + canonical((v as Record<string, unknown>)[k]))
          .join(",")}}`;
export const workforceAssertionHash = (assertion: unknown) =>
  createHash("sha256").update(canonical(assertion)).digest("hex");
