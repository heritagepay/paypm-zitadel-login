import { timestampDate } from "@zitadel/client";
import { AuthRequest } from "@zitadel/proto/zitadel/oidc/v2/authorization_pb";
import { SAMLRequest } from "@zitadel/proto/zitadel/saml/v2/authorization_pb";
import { Session } from "@zitadel/proto/zitadel/session/v2/session_pb";
import { GetSessionResponse } from "@zitadel/proto/zitadel/session/v2/session_service_pb";
import { AuthenticationMethodType } from "@zitadel/proto/zitadel/user/v2/user_service_pb";
import { sessionExpiresAt, verifiedFactor } from "./authentication-policy";
import { getMostRecentCookieWithLoginname } from "./cookies";
import { shouldEnforceMFA } from "./verify-helper";
import { getLoginSettings, getSession, getUserByID, listAuthenticationMethodTypes, ServiceConfig } from "./zitadel";

type LoadMostRecentSessionParams = {
  serviceConfig: ServiceConfig;
  sessionParams: {
    loginName?: string;
    organization?: string;
  };
};

export async function loadMostRecentSession({
  serviceConfig,
  sessionParams,
}: LoadMostRecentSessionParams): Promise<Session | undefined> {
  const recent = await getMostRecentCookieWithLoginname({
    loginName: sessionParams.loginName,
    organization: sessionParams.organization,
  });

  if (!recent) {
    return undefined;
  }

  return getSession({ serviceConfig, sessionId: recent.id, sessionToken: recent.token }).then(
    (resp: GetSessionResponse) => resp.session,
  );
}

/**
 * mfa is required, session is not valid anymore (e.g. session expired, user logged out, etc.)
 * to check for mfa for automatically selected session -> const response = await listAuthenticationMethodTypes(userId);
 **/
export async function isSessionValid({
  serviceConfig,
  session,
  authenticationClass,
}: {
  serviceConfig: ServiceConfig;
  session: Session;
  authenticationClass?: "workforce_limited";
}): Promise<boolean> {
  // session can't be checked without user
  if (!session.factors?.user) {
    return false;
  }

  const now = Date.now();
  if (sessionExpiresAt(session, now) === undefined || !verifiedFactor(session, session.factors.user.verifiedAt, now)) {
    return false;
  }

  let mfaValid = true;

  // Check if user authenticated via different methods
  const validIDP = verifiedFactor(session, session.factors.intent?.verifiedAt, now);
  const validPassword = verifiedFactor(session, session.factors.password?.verifiedAt, now);
  const validPasskey = verifiedFactor(session, session.factors.webAuthN?.verifiedAt, now);

  // Get login settings to determine if MFA is actually required by policy
  const loginSettings = await getLoginSettings({ serviceConfig, organization: session.factors?.user?.organizationId });
  if (!loginSettings) return false;

  // This explicit class is only passed by the registered workforce finalizer
  // after signed flow admission and live Identity eligibility. It never grants
  // privileged authority, and cannot reuse email as both primary and MFA.
  if (authenticationClass === "workforce_limited") {
    if (!loginSettings.allowLocalAuthentication || !verifiedFactor(session, session.factors.otpEmail?.verifiedAt, now))
      return false;
    const [methods, result] = await Promise.all([
      listAuthenticationMethodTypes({ serviceConfig, userId: session.factors.user.id }),
      getUserByID({ serviceConfig, userId: session.factors.user.id }),
    ]);
    return (
      methods?.authMethodTypes?.includes(AuthenticationMethodType.OTP_EMAIL) === true &&
      result?.user?.type.case === "human" &&
      result.user.type.value.email?.isVerified === true
    );
  }

  // Use the existing shouldEnforceMFA function to determine if MFA is required
  const isMfaRequired = shouldEnforceMFA(session, loginSettings);

  // Only enforce MFA validation if MFA is required by policy
  if (isMfaRequired) {
    const authMethodTypes = await listAuthenticationMethodTypes({ serviceConfig, userId: session.factors.user.id });

    if (!authMethodTypes?.authMethodTypes) return false;
    const authMethods = authMethodTypes.authMethodTypes;
    // Filter to only MFA methods (exclude PASSWORD and PASSKEY)
    const mfaMethods = authMethods?.filter(
      (method) =>
        method === AuthenticationMethodType.TOTP ||
        method === AuthenticationMethodType.OTP_EMAIL ||
        method === AuthenticationMethodType.OTP_SMS ||
        method === AuthenticationMethodType.U2F,
    );

    if (mfaMethods && mfaMethods.length > 0) {
      // Check if any of the configured MFA methods have been verified
      const totpValid =
        mfaMethods.includes(AuthenticationMethodType.TOTP) && verifiedFactor(session, session.factors.totp?.verifiedAt, now);
      const otpEmailValid =
        mfaMethods.includes(AuthenticationMethodType.OTP_EMAIL) &&
        verifiedFactor(session, session.factors.otpEmail?.verifiedAt, now);
      const otpSmsValid =
        mfaMethods.includes(AuthenticationMethodType.OTP_SMS) &&
        verifiedFactor(session, session.factors.otpSms?.verifiedAt, now);
      const u2fValid = mfaMethods.includes(AuthenticationMethodType.U2F) && validPasskey && (validPassword || validIDP);

      mfaValid = totpValid || otpEmailValid || otpSmsValid || u2fValid;
    } else {
      // No specific MFA methods configured, but MFA is forced - check for any verified MFA factors
      // (excluding IDP which should be handled separately)
      const otpEmail = verifiedFactor(session, session.factors.otpEmail?.verifiedAt, now);
      const otpSms = verifiedFactor(session, session.factors.otpSms?.verifiedAt, now);
      const totp = verifiedFactor(session, session.factors.totp?.verifiedAt, now);
      const webAuthN = validPasskey && (validPassword || validIDP);
      // Note: Removed IDP (session.factors.intent?.verifiedAt) as requested

      mfaValid = !!(otpEmail || otpSms || totp || webAuthN);
    }
  }

  // If MFA is not required by policy, mfaValid remains true

  const validChecks = !!(validPassword || validPasskey || validIDP);

  if (!validChecks) {
    return false;
  }

  if (!mfaValid) {
    console.warn("[Session] MFA is required but not valid");
    return false;
  }

  // Check email verification if EMAIL_VERIFICATION environment variable is enabled
  if (process.env.EMAIL_VERIFICATION === "true") {
    const userResponse = await getUserByID({ serviceConfig, userId: session.factors.user.id });

    const humanUser = userResponse?.user?.type.case === "human" ? userResponse?.user.type.value : undefined;

    if (!humanUser?.email?.isVerified) {
      console.warn("[Session] Email is not verified");
      return false;
    }
  }

  return true;
}

export async function findValidSession({
  serviceConfig,
  sessions,
  authRequest,
  samlRequest,
  organization,
}: {
  serviceConfig: ServiceConfig;
  sessions: Session[];
  authRequest?: AuthRequest;
  samlRequest?: SAMLRequest;
  organization?: string;
}): Promise<Session | undefined> {
  let sessionsWithHint = sessions.filter((s) => {
    if (authRequest && authRequest.hintUserId) {
      return s.factors?.user?.id === authRequest.hintUserId;
    }
    if (authRequest && authRequest.loginHint) {
      return s.factors?.user?.loginName === authRequest.loginHint;
    }
    if (samlRequest) {
      // SAML requests don't contain user hints like OIDC (hintUserId/loginHint)
      // so we return all sessions for further processing
      return true;
    }
    return true;
  });

  if (organization) {
    sessionsWithHint = sessionsWithHint.filter((s) => s.factors?.user?.organizationId === organization);
  }

  if (sessionsWithHint.length === 0) {
    return undefined;
  }

  // sort by change date descending
  sessionsWithHint.sort((a, b) => {
    const dateA = a.changeDate ? timestampDate(a.changeDate).getTime() : 0;
    const dateB = b.changeDate ? timestampDate(b.changeDate).getTime() : 0;
    return dateB - dateA;
  });

  // return the first valid session according to settings
  for (const session of sessionsWithHint) {
    if (await isSessionValid({ serviceConfig, session })) {
      return session;
    }
  }

  return undefined;
}
