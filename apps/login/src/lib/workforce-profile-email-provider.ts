import { create, type Client } from "@zitadel/client";
import { SendEmailCodeRequestSchema, UserService } from "@zitadel/proto/zitadel/user/v2/user_service_pb";
import "server-only";
import { providerTimestampMs } from "./authentication-policy";
import { createServiceForHost } from "./service";
import type { ProfileDeliveryAcknowledgement } from "./workforce-enrollment-store";
import type { ServiceConfig } from "./zitadel";

/** Purpose-only native sendCode. No returnCode or caller-derived recipient/template. */
export async function deliverWorkforceProfileEmail(
  serviceConfig: ServiceConfig,
  input: { subject: string; organizationId: string; template: string },
  assertCurrentOwner: () => Promise<void>,
): Promise<ProfileDeliveryAcknowledgement> {
  const url = new URL(input.template);
  if (
    !/^[1-9]\d{0,39}$/.test(input.subject) ||
    !/^[1-9]\d{0,39}$/.test(input.organizationId) ||
    url.origin !== new URL(serviceConfig.baseUrl).origin ||
    url.protocol !== "https:" ||
    url.username ||
    url.password ||
    url.pathname !== "/ui/v2/login/workforce-enrollment" ||
    input.template.length > 200 ||
    url.searchParams.size !== 2 ||
    !/^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i.test(
      url.searchParams.get("operationId") ?? "",
    ) ||
    !/^oidc_[A-Za-z0-9_-]{1,480}$/.test(url.searchParams.get("requestId") ?? "") ||
    url.hash !== "#code={{.Code}}"
  )
    throw new Error("Profile delivery binding unavailable");
  const controller = new AbortController(),
    deadline = Date.now() + 8000;
  let timer: ReturnType<typeof setTimeout>;
  const expired = new Promise<never>((_, reject) => {
    timer = setTimeout(() => {
      controller.abort();
      reject(new Error("Profile delivery unconfirmed"));
    }, 8000);
  });
  const current = () => {
    if (controller.signal.aborted || Date.now() >= deadline) throw new Error("Profile delivery unconfirmed");
  };
  try {
    return await Promise.race([
      expired,
      (async () => {
        // Existing credentials can take time to resolve. A late resolution never starts a send.
        const api: Client<typeof UserService> = await createServiceForHost(UserService, serviceConfig);
        current();
        await assertCurrentOwner();
        current();
        const result = await api.sendEmailCode(
          create(SendEmailCodeRequestSchema, {
            userId: input.subject,
            verification: { case: "sendCode", value: { urlTemplate: input.template } },
          }),
          { signal: controller.signal, timeoutMs: Math.max(1, deadline - Date.now()) },
        );
        current();
        const change = providerTimestampMs(result.details?.changeDate);
        if (
          result.verificationCode !== undefined ||
          !result.details ||
          Object.keys(result).some((k) => !["$typeName", "$unknown", "details", "verificationCode"].includes(k)) ||
          result.details.resourceOwner !== input.organizationId ||
          typeof result.details.sequence !== "bigint" ||
          result.details.sequence <= BigInt(0) ||
          change === undefined ||
          change > Date.now() + 5000
        )
          throw new Error("Profile delivery acknowledgement unavailable");
        return {
          sequence: result.details.sequence.toString(),
          changeAt: new Date(change).toISOString(),
          resourceOwner: result.details.resourceOwner,
        };
      })(),
    ]);
  } finally {
    clearTimeout(timer!);
    controller.abort();
  }
}
