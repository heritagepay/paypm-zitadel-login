import { Code } from "@zitadel/client";
import "server-only";
import { isClassifiedError } from "./grpc/interceptors/error-classification";
import type { WorkforceProvider } from "./workforce-provider";
import type { WorkforceStore } from "./workforce-store";
/** Deletion was reserved locally before external effects; retries never restore admission. */
export async function flushWorkforceRevocations(store: WorkforceStore, provider: WorkforceProvider) {
  for (const pending of await store.pendingRevocations()) {
    try {
      await provider.revoke(pending.provider_session_id);
    } catch (error) {
      if (!isClassifiedError(error) || error.code !== Code.NotFound) throw error;
    }
    await store.revocationCompleted(pending.provider_session_id);
  }
}
