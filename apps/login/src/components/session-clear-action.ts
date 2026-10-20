"use server";

import { clearSession } from "@/lib/server/session";

/** Keep the existing cookie mutation's class-shaped result inside the server. */
export async function clearNativeSession(input: { sessionId: string }): Promise<{ cleared: boolean }> {
  const result = await clearSession(input);
  return { cleared: result !== undefined };
}
