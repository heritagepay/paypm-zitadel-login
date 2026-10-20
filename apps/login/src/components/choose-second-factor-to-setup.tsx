"use client";

import { handleServerActionResponse } from "@/lib/client-utils";
import { skipMFAAndContinueWithNextUrl } from "@/lib/server/session";
import { LoginSettings, SecondFactorType } from "@zitadel/proto/zitadel/settings/v2/login_settings_pb";
import { AuthenticationMethodType } from "@zitadel/proto/zitadel/user/v2/user_service_pb";
import { useTranslations } from "next-intl";
import { useRouter } from "next/navigation";
import { useEffect, useId, useRef, useState } from "react";
import { Alert } from "./alert";
import { EMAIL, SMS, TOTP, U2F } from "./auth-methods";
import { AutoSubmitForm } from "./auto-submit-form";
import { Spinner } from "./spinner";
import { Translated } from "./translated";

type Props = {
  userId: string;
  loginName?: string;
  sessionId?: string;
  requestId?: string;
  organization?: string;
  loginSettings: LoginSettings;
  userMethods: AuthenticationMethodType[];
  checkAfter: boolean;
  phoneVerified: boolean;
  emailVerified: boolean;
  force: boolean;
};

export function ChooseSecondFactorToSetup({
  userId,
  loginName,
  sessionId,
  requestId,
  organization,
  loginSettings,
  userMethods,
  checkAfter,
  phoneVerified,
  emailVerified,
  force,
}: Props) {
  const router = useRouter();
  const t = useTranslations("mfa.set");
  const params = new URLSearchParams({});

  const [error, setError] = useState<string>("");
  const [loading, setLoading] = useState(false);
  const inFlight = useRef(false);
  const mounted = useRef(true);
  const errorId = useId();
  const [samlData, setSamlData] = useState<{ url: string; fields: Record<string, string> } | null>(null);

  useEffect(() => {
    mounted.current = true;
    return () => {
      mounted.current = false;
    };
  }, []);

  async function skip() {
    if (force || inFlight.current || !mounted.current) return;
    inFlight.current = true;
    setLoading(true);
    setError("");
    let continuing = false;
    try {
      const response = await skipMFAAndContinueWithNextUrl({ userId, loginName, sessionId, organization, requestId });
      if (!mounted.current) return;
      let failed = false;
      const handled = handleServerActionResponse(response, router, setSamlData, () => {
        failed = true;
        setError(t("error"));
      });
      continuing = handled && !failed;
      if (!handled) setError(t("error"));
    } catch {
      if (mounted.current) setError(t("error"));
    } finally {
      if (!continuing) {
        inFlight.current = false;
        if (mounted.current) setLoading(false);
      }
    }
  }

  if (loginName) {
    params.append("loginName", loginName);
  }
  if (sessionId) {
    params.append("sessionId", sessionId);
  }
  if (requestId) {
    params.append("requestId", requestId);
  }
  if (organization) {
    params.append("organization", organization);
  }
  if (checkAfter) {
    params.append("checkAfter", "true");
  }

  return (
    <>
      {samlData && <AutoSubmitForm url={samlData.url} fields={samlData.fields} />}
      <div className="grid w-full grid-cols-1 gap-5 pt-4">
        {loginSettings.secondFactors.map((factor) => {
          switch (factor) {
            case SecondFactorType.OTP:
              return TOTP(userMethods.includes(AuthenticationMethodType.TOTP), "/otp/time-based/set?" + params);
            case SecondFactorType.U2F:
              return U2F(userMethods.includes(AuthenticationMethodType.U2F), "/u2f/set?" + params);
            case SecondFactorType.OTP_EMAIL:
              return (
                emailVerified && EMAIL(userMethods.includes(AuthenticationMethodType.OTP_EMAIL), "/otp/email/set?" + params)
              );
            case SecondFactorType.OTP_SMS:
              return phoneVerified && SMS(userMethods.includes(AuthenticationMethodType.OTP_SMS), "/otp/sms/set?" + params);
            default:
              return null;
          }
        })}
      </div>
      {!force && (
        <button
          className="paypm-mfa-skip text-sm"
          onClick={() => void skip()}
          disabled={loading}
          aria-busy={loading}
          aria-describedby={error ? errorId : undefined}
          type="button"
          data-testid="reset-button"
        >
          {loading && <Spinner className="h-5 w-5 flex-shrink-0" />}
          <Translated i18nKey={loading ? "set.pending" : "set.skip"} namespace="mfa" />
        </button>
      )}
      {error && (
        <div id={errorId} className="py-4" data-testid="error">
          <Alert>{error}</Alert>
        </div>
      )}
    </>
  );
}
