import { isSafeRedirectUri } from "@/lib/client-utils";
import { Cookie } from "@/lib/cookies";
import { isClassifiedError } from "@/lib/grpc/interceptors/error-classification";
import { sendLoginname, SendLoginnameCommand } from "@/lib/server/loginname";
import { createCallback, getAuthRequest, getLoginSettings, getUserByID, ServiceConfig } from "@/lib/zitadel";
import { Code, create } from "@zitadel/client";
import { CreateCallbackRequestSchema, SessionSchema } from "@zitadel/proto/zitadel/oidc/v2/oidc_service_pb";
import { Session } from "@zitadel/proto/zitadel/session/v2/session_pb";
import { satisfiesAuthorizationFreshness } from "./authentication-policy";
import { isSessionValid } from "./session";
import { workforceEligible, workforcePolicy } from "./workforce-policy";
import { readWorkforceState } from "./workforce-state";

type LoginWithOIDCAndSession = {
  serviceConfig: ServiceConfig;
  authRequest: string;
  sessionId: string;
  sessions: Session[];
  sessionCookies: Cookie[];
};
export async function loginWithOIDCAndSession({
  serviceConfig,
  authRequest,
  sessionId,
  sessions,
  sessionCookies,
}: LoginWithOIDCAndSession): Promise<{ error: string } | { redirect: string }> {
  const selectedSession = sessions.find((s) => s.id === sessionId);

  if (selectedSession && selectedSession.id) {
    let authenticationClass: "workforce_limited" | undefined;
    const response = await getAuthRequest({ serviceConfig, authRequestId: authRequest });
    const request = response?.authRequest;
    if (!request) return { error: "Session not found or invalid" };
    if (process.env.PAYPM_WORKFORCE_OIDC_CLIENT_IDS) {
      const registered = process.env.PAYPM_WORKFORCE_OIDC_CLIENT_IDS.split(",")
        .map((id) => id.trim())
        .includes(request.clientId);
      if (registered) {
        const policy = workforcePolicy();
        if (!policy || selectedSession.factors?.user?.organizationId !== policy.organizationId)
          return { error: "Workforce authentication unavailable" };
        const { user } = await getUserByID({ serviceConfig, userId: selectedSession.factors.user.id });
        if (!user || !(await workforceEligible(user, request.clientId, "login")))
          return { error: "Workforce authentication unavailable" };
        const admission = await readWorkforceState();
        if (
          policy.emailOtpReady &&
          admission?.purpose === "limited-admission" &&
          admission.sessionId === selectedSession.id &&
          admission.userId === selectedSession.factors.user.id &&
          admission.clientId === request.clientId &&
          admission.requestId === `oidc_${authRequest}`
        )
          authenticationClass = "workforce_limited";
      }
    }
    const isValid =
      (await isSessionValid({ serviceConfig, session: selectedSession, authenticationClass })) &&
      satisfiesAuthorizationFreshness(selectedSession, request, authenticationClass === "workforce_limited");

    console.log("Session is valid:", isValid);

    if (!isValid) {
      if (!selectedSession.factors?.user) return { error: "Session not found or invalid" };
      // if the session is not valid anymore, we need to redirect the user to re-authenticate /
      // TODO: handle IDP intent direcly if available
      const command: SendLoginnameCommand = {
        loginName: selectedSession.factors.user?.loginName,
        organization: selectedSession.factors?.user?.organizationId,
        requestId: `oidc_${authRequest}`,
      };

      const res = await sendLoginname(command);

      if (res && "redirect" in res && res?.redirect) {
        return { redirect: res.redirect };
      }
      return { error: "Session not found or invalid" };
    }

    const cookie = sessionCookies.find((cookie) => cookie.id === selectedSession?.id);

    if (cookie && cookie.id && cookie.token) {
      const session = {
        sessionId: cookie?.id,
        sessionToken: cookie?.token,
      };

      try {
        const { callbackUrl } = await createCallback({
          serviceConfig,
          req: create(CreateCallbackRequestSchema, {
            authRequestId: authRequest,
            callbackKind: {
              case: "session",
              value: create(SessionSchema, session),
            },
          }),
        });
        if (callbackUrl) {
          return { redirect: callbackUrl };
        } else {
          return { error: "An error occurred!" };
        }
      } catch (error: unknown) {
        // handle already handled gracefully as these could come up if old emails with requestId are used (reset password, register emails etc.)
        console.error(error);
        if (isClassifiedError(error) && error.code === Code.FailedPrecondition) {
          const loginSettings = await getLoginSettings({
            serviceConfig,
            organization: selectedSession.factors?.user?.organizationId,
          });

          if (loginSettings?.defaultRedirectUri && isSafeRedirectUri(loginSettings.defaultRedirectUri)) {
            return { redirect: loginSettings.defaultRedirectUri };
          } else if (loginSettings?.defaultRedirectUri) {
            console.warn("loginWithOIDCAndSession: Unsafe defaultRedirectUri prevented:", loginSettings.defaultRedirectUri);
          }

          const signedinUrl = "/signedin";

          const params = new URLSearchParams();
          if (selectedSession.factors?.user?.loginName) {
            params.append("loginName", selectedSession.factors?.user?.loginName);
          }
          if (selectedSession.factors?.user?.organizationId) {
            params.append("organization", selectedSession.factors?.user?.organizationId);
          }
          return { redirect: signedinUrl + "?" + params.toString() };
        } else {
          return { error: "Unknown error occurred" };
        }
      }
    }
  }

  // If no session found or no valid cookie, return error
  return { error: "Session not found or invalid" };
}
