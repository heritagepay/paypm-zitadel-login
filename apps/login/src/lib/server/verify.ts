"use server";

import { createLogger } from "@/lib/logger";
import {
  createInviteCode,
  createPasskeyRegistrationLink,
  getLoginSettings,
  getSession,
  getUserByID,
  listAuthenticationMethodTypes,
  verifyEmail,
  verifyInviteCode,
  verifyTOTPRegistration,
  sendEmailCode as zitadelSendEmailCode,
} from "@/lib/zitadel";

import { create } from "@zitadel/client";
import { Session } from "@zitadel/proto/zitadel/session/v2/session_pb";
import { ChecksSchema } from "@zitadel/proto/zitadel/session/v2/session_service_pb";
import { AuthenticationMethodType } from "@zitadel/proto/zitadel/user/v2/user_service_pb";
import { getTranslations } from "next-intl/server";
import { headers } from "next/headers";
import { completeFlowOrGetUrl } from "../client";
import { getSessionCookieByLoginName } from "../cookies";
import { encryptEnrollmentProof, storeEnrollmentProof } from "../credential-enrollment";
import { getServiceConfig } from "../service-url";
import { loadMostRecentSession } from "../session";
import { checkMFAFactors } from "../verify-helper";
import { workforceEligible, workforceRequestClient } from "../workforce-policy";
import { createSessionAndUpdateCookie } from "./cookie";
import { getPublicHostWithProtocol } from "./host";

const logger = createLogger("verify");

export async function verifyTOTP(code: string, loginName?: string, organization?: string) {
  const _headers = await headers();
  const { serviceConfig } = getServiceConfig(_headers);

  return loadMostRecentSession({
    serviceConfig,
    sessionParams: {
      loginName,
      organization,
    },
  }).then((session) => {
    if (session?.factors?.user?.id) {
      return verifyTOTPRegistration({ serviceConfig, code, userId: session.factors.user.id });
    } else {
      throw Error("No user id found in session.");
    }
  });
}

type VerifyUserByEmailCommand = {
  userId: string;
  loginName?: string; // to determine already existing session
  organization?: string;
  code: string;
  isInvite: boolean;
  requestId?: string;
};

export async function sendVerification(command: VerifyUserByEmailCommand) {
  const t = await getTranslations("verify");
  const _headers = await headers();
  const { serviceConfig } = getServiceConfig(_headers);

  const verifyResponse = command.isInvite
    ? await verifyInviteCode({ serviceConfig, userId: command.userId, verificationCode: command.code }).catch((error) => {
        logger.warn("Could not verify invite:", { error });
        return { error: t("errors.couldNotVerifyInvite") };
      })
    : await verifyEmail({ serviceConfig, userId: command.userId, verificationCode: command.code }).catch((error) => {
        logger.warn("Could not verify email:", { error });
        return { error: t("errors.couldNotVerifyEmail") };
      });

  if ("error" in verifyResponse) {
    return verifyResponse;
  }

  if (!verifyResponse) {
    return { error: t("errors.couldNotVerify") };
  }

  let session: Session | undefined;
  const userResponse = await getUserByID({ serviceConfig, userId: command.userId });

  if (!userResponse || !userResponse.user) {
    return { error: t("errors.couldNotLoadUser") };
  }

  const user = userResponse.user;
  const loginSettings = await getLoginSettings({ serviceConfig, organization: user.details?.resourceOwner });
  if (!loginSettings?.allowLocalAuthentication) return { error: t("errors.couldNotVerify") };

  if (
    process.env.PAYPM_WORKFORCE_ORGANIZATION_ID &&
    user.details?.resourceOwner === process.env.PAYPM_WORKFORCE_ORGANIZATION_ID
  ) {
    const clientId = await workforceRequestClient(serviceConfig, command.requestId);
    if (!command.isInvite || !clientId || !(await workforceEligible(user, clientId, "enrollment")))
      return { error: t("errors.couldNotVerify") };
  }

  const sessionCookie = await getSessionCookieByLoginName({
    loginName: command.loginName ?? user.preferredLoginName,
    organization: command.organization,
  });

  if (sessionCookie) {
    session = await getSession({ serviceConfig, sessionId: sessionCookie.id, sessionToken: sessionCookie.token })
      .then((response) => {
        if (response?.session) {
          return response.session;
        }
      })
      .catch((error) => {
        // user session is not found, so we create a new one
        logger.warn("[verify] user session is not found, so we create a new one", { error });
        return undefined;
      });
  }
  if (session?.factors?.user?.id !== user.userId) session = undefined;

  // load auth methods for user
  const authMethodResponse = await listAuthenticationMethodTypes({ serviceConfig, userId: user.userId });

  if (!authMethodResponse || !authMethodResponse.authMethodTypes) {
    return { error: t("errors.couldNotLoadAuthenticators") };
  }

  const hasPrimaryMethod =
    authMethodResponse?.authMethodTypes?.some(
      (m: AuthenticationMethodType) =>
        m === AuthenticationMethodType.PASSWORD ||
        m === AuthenticationMethodType.PASSKEY ||
        m === AuthenticationMethodType.IDP,
    ) ?? false;

  // if no primary auth methods are found on the user, redirect to set one up
  if (!hasPrimaryMethod) {
    if (!session) {
      const checks = create(ChecksSchema, {
        user: {
          search: {
            case: "userId",
            value: user.userId,
          },
        },
      });

      const result = await createSessionAndUpdateCookie({
        checks,
        requestId: command.requestId,
      });
      session = result.session;
    }

    if (!session || session.factors?.user?.id !== user.userId) {
      return { error: t("errors.couldNotCreateSession") };
    }

    // Check protected storage before issuing any secret-bearing provider proof.
    try {
      encryptEnrollmentProof({
        sessionId: session.id,
        userId: user.userId,
        code: { id: "readiness", code: "readiness" },
        expiresAt: Date.now() + 300000,
      });
    } catch {
      return { error: t("errors.couldNotVerify") };
    }
    const registration = await createPasskeyRegistrationLink({ serviceConfig, userId: user.userId });
    if (!registration.code?.code || !registration.code.id) return { error: t("errors.couldNotVerify") };
    // This provider-issued registration proof follows successful invite/email
    // verification above. It replaces the predictable fingerprint cookie.
    const params = new URLSearchParams({
      sessionId: session.id,
      loginName: session.factors?.user?.loginName ?? user.preferredLoginName,
    });
    await storeEnrollmentProof({
      sessionId: session.id,
      userId: user.userId,
      code: registration.code,
      expiresAt: Date.now() + 300000,
    });

    if (command.requestId) {
      params.set("requestId", command.requestId);
    }

    return { redirect: `/passkey/set?${params}` };
  }

  // if no session found only show success page,
  // if user is invited, recreate invite flow to not depend on session
  if (!session?.factors?.user?.id) {
    const verifySuccessParams = new URLSearchParams({});

    if (command.userId) {
      verifySuccessParams.set("userId", command.userId);
    }

    if (("loginName" in command && command.loginName) || user.preferredLoginName) {
      verifySuccessParams.set(
        "loginName",
        "loginName" in command && command.loginName ? command.loginName : user.preferredLoginName,
      );
    }
    if (command.requestId) {
      verifySuccessParams.set("requestId", command.requestId);
    }
    if (command.organization) {
      verifySuccessParams.set("organization", command.organization);
    }

    return { redirect: `/verify/success?${verifySuccessParams}` };
  }

  // redirect to mfa factor if user has one, or redirect to set one up
  const mfaFactorCheck = await checkMFAFactors(
    serviceConfig,
    session,
    loginSettings,
    authMethodResponse.authMethodTypes,
    command.organization,
    command.requestId,
  );

  if (mfaFactorCheck?.redirect) {
    return mfaFactorCheck;
  }

  // login user if no additional steps are required
  if (command.requestId && session.id) {
    return completeFlowOrGetUrl(
      {
        sessionId: session.id,
        requestId: command.requestId,
        organization: command.organization ?? session.factors?.user?.organizationId,
      },
      loginSettings?.defaultRedirectUri,
    );
  }

  // Regular flow - return URL for client-side navigation
  return completeFlowOrGetUrl(
    {
      loginName: session.factors.user.loginName,
      organization: session.factors?.user?.organizationId,
    },
    loginSettings?.defaultRedirectUri,
  );
}

function buildVerificationUrlTemplate(
  hostWithProtocol: string,
  basePath: string,
  isInvite: boolean,
  requestId?: string,
): string {
  let urlTemplate = `${hostWithProtocol}${basePath}/verify?code={{.Code}}&userId={{.UserID}}&organization={{.OrgID}}`;

  if (isInvite) {
    urlTemplate += "&invite=true";
  }

  if (requestId) {
    urlTemplate += `&requestId=${encodeURIComponent(requestId)}`;
  }

  return urlTemplate;
}

type resendVerifyEmailCommand = {
  userId: string;
  isInvite: boolean;
  requestId?: string;
};

export async function resendVerification(command: resendVerifyEmailCommand) {
  const t = await getTranslations("verify");
  const _headers = await headers();
  const { serviceConfig } = getServiceConfig(_headers);
  const hostWithProtocol = await getPublicHostWithProtocol(_headers);

  const basePath = process.env.NEXT_PUBLIC_BASE_PATH ?? "";
  const urlTemplate = buildVerificationUrlTemplate(hostWithProtocol, basePath, command.isInvite, command.requestId);

  return command.isInvite
    ? createInviteCode({
        serviceConfig,
        userId: command.userId,
        urlTemplate,
      }).catch((error) => {
        if (error.code === 9) {
          return { error: t("errors.userAlreadyVerified") };
        }
        return { error: t("errors.couldNotResendInvite") };
      })
    : zitadelSendEmailCode({
        serviceConfig,
        userId: command.userId,
        urlTemplate,
      });
}

type SendEmailCommand = {
  userId: string;
  urlTemplate: string;
};

export async function sendEmailCode(command: SendEmailCommand) {
  const _headers = await headers();
  const { serviceConfig } = getServiceConfig(_headers);

  return zitadelSendEmailCode({ serviceConfig, userId: command.userId, urlTemplate: command.urlTemplate });
}

export async function sendInviteEmailCode(command: SendEmailCommand) {
  const _headers = await headers();
  const { serviceConfig } = getServiceConfig(_headers);

  return createInviteCode({ serviceConfig, userId: command.userId, urlTemplate: command.urlTemplate });
}

type InitialSendVerificationCommand = {
  userId: string;
  isInvite: boolean;
  requestId?: string;
};

export async function initialSendVerification(command: InitialSendVerificationCommand) {
  const _headers = await headers();
  const { serviceConfig } = getServiceConfig(_headers);
  const hostWithProtocol = await getPublicHostWithProtocol(_headers);

  const basePath = process.env.NEXT_PUBLIC_BASE_PATH ?? "";
  const urlTemplate = buildVerificationUrlTemplate(hostWithProtocol, basePath, command.isInvite, command.requestId);

  if (command.isInvite) {
    return createInviteCode({
      serviceConfig,
      userId: command.userId,
      urlTemplate,
    });
  } else {
    return zitadelSendEmailCode({
      serviceConfig,
      userId: command.userId,
      urlTemplate,
    });
  }
}
