import type { RequestChallenges } from "@zitadel/proto/zitadel/session/v2/challenge_pb";
import type { Session } from "@zitadel/proto/zitadel/session/v2/session_pb";
import type { Checks } from "@zitadel/proto/zitadel/session/v2/session_service_pb";
import "server-only";
import { workforcePolicy, workforceRequestClient } from "./workforce-policy";
import { getUserByID, listUsers, type ServiceConfig } from "./zitadel";
/** Generic legacy Session helpers cannot bypass the Login-owned workforce quota reservation. */
export async function denyUnreservedWorkforceOtp(input: {
  serviceConfig: ServiceConfig;
  requestId?: string;
  checks?: Checks;
  challenges?: RequestChallenges;
  session?: Session;
}) {
  const policy = workforcePolicy();
  if (!policy?.emailOtpReady || (!input.checks?.otpEmail && !input.challenges?.otpEmail)) return;
  let staff = input.session?.factors?.user?.organizationId === policy.organizationId;
  if (!staff && input.requestId) staff = Boolean(await workforceRequestClient(input.serviceConfig, input.requestId));
  if (!staff && input.checks?.user?.search.case === "userId") {
    const { user } = await getUserByID({ serviceConfig: input.serviceConfig, userId: input.checks.user.search.value });
    staff = user?.details?.resourceOwner === policy.organizationId;
  }
  if (!staff && input.checks?.user?.search.case === "loginName") {
    const found = await listUsers({
      serviceConfig: input.serviceConfig,
      loginName: input.checks.user.search.value,
      organizationId: policy.organizationId,
    });
    staff = found.result.length > 0;
  }
  if (staff) throw new Error("Workforce email OTP requires its durable admitted flow");
}
