"use client";
import { coerceToArrayBuffer, coerceToBase64Url } from "@/helpers/base64";
import { useTranslations } from "next-intl";
import { useRouter } from "next/navigation";
import { useEffect, useRef, useState } from "react";
import { Alert } from "./alert";
import { Button, ButtonVariants } from "./button";
import { DynamicTheme } from "./dynamic-theme";
import { Spinner } from "./spinner";
type Flow = { requestId: string; action: string; publicKey: Record<string, unknown>; expiresAt: string; returnUrl: string };
export function OperationsActionPasskey({ requestId, capability }: { requestId: string; capability: string }) {
  const t = useTranslations("operationsAction"),
    router = useRouter(),
    epoch = useRef(0),
    prompt = useRef<AbortController | null>(null),
    assertion = useRef<Record<string, unknown> | null>(null);
  const [flow, setFlow] = useState<Flow>(),
    [busy, setBusy] = useState(false),
    [checking, setChecking] = useState(true),
    [cancelling, setCancelling] = useState(false),
    [error, setError] = useState(false),
    [now, setNow] = useState(0);
  const base = `/api/operations/actions/${encodeURIComponent(requestId)}`;
  function callback(value: unknown) {
    if (typeof value !== "string") throw new Error("unavailable");
    const url = new URL(value);
    if (
      url.protocol !== "https:" ||
      url.pathname !== "/auth/workforce/actions/callback" ||
      url.hash ||
      url.username ||
      url.password ||
      url.searchParams.get("requestId") !== requestId ||
      !/^[A-Za-z0-9_-]{64}$/.test(url.searchParams.get("state") ?? "") ||
      Array.from(url.searchParams.keys()).sort().join(",") !== "requestId,state" ||
      !flow ||
      url.origin !== flow.returnUrl
    )
      throw new Error("unavailable");
    return url.href;
  }
  async function load() {
    const current = epoch.current;
    setChecking(true);
    setError(false);
    try {
      const response = await fetch(`${base}/challenge`, {
        cache: "no-store",
        headers: { "X-PayPM-Ceremony-Capability": capability },
      });
      if (!response.ok) throw new Error("unavailable");
      const value = await response.json();
      if (
        value.requestId !== requestId ||
        typeof value.action !== "string" ||
        ![
          "operations.merchant.settlement.review",
          "operations.merchant.settlement.approve",
          "operations.merchant.settlement.execute",
          "operations.access.grant.review",
          "operations.access.grant.approve",
          "operations.access.grant.revoke",
          "operations.access.deployment-grant.review",
          "operations.access.deployment-grant.approve",
          "operations.access.deployment-grant.revoke",
          "operations.access.kyc-grant.review",
          "operations.access.kyc-grant.approve",
          "operations.access.kyc-grant.revoke",
        ].includes(value.action) ||
        !value.publicKey ||
        value.publicKey.userVerification !== "required" ||
        !Number.isFinite(Date.parse(value.expiresAt)) ||
        typeof value.returnUrl !== "string" ||
        new URL(value.returnUrl).origin !== value.returnUrl ||
        !value.returnUrl.startsWith("https://")
      )
        throw new Error("unavailable");
      if (current === epoch.current) {
        setFlow(value);
        setNow(Date.now());
      }
    } catch {
      if (current === epoch.current) setError(true);
    } finally {
      if (current === epoch.current) setChecking(false);
    }
  }
  useEffect(() => {
    const url = new URL(window.location.href);
    if (url.searchParams.has("capability")) {
      url.searchParams.delete("capability");
      window.history.replaceState(window.history.state, "", url.pathname + url.search);
    }
    void load();
    setNow(Date.now());
    const timer = setInterval(() => setNow(Date.now()), 1000);
    return () => {
      // This ref is a logout/cancellation generation, rather than a DOM node.
      // eslint-disable-next-line react-hooks/exhaustive-deps
      epoch.current++;
      prompt.current?.abort();
      clearInterval(timer);
    };
    // The server props bind this one request; reload deliberately loses the public capability.
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [requestId, capability]);
  const expired = !!flow && now >= Date.parse(flow.expiresAt);
  async function verify() {
    if (!flow || busy || cancelling || expired) return;
    const current = epoch.current;
    setBusy(true);
    setError(false);
    try {
      if (!assertion.current) {
        const publicKey = {
          ...flow.publicKey,
          challenge: coerceToArrayBuffer(flow.publicKey.challenge, "challenge"),
          allowCredentials: ((flow.publicKey.allowCredentials as { id: string; type: string }[] | undefined) ?? []).map(
            (c) => ({ ...c, id: coerceToArrayBuffer(c.id, "credential.id") }),
          ),
        } as PublicKeyCredentialRequestOptions;
        const controller = new AbortController();
        prompt.current = controller;
        const credential = (await navigator.credentials.get({
          publicKey,
          signal: controller.signal,
        })) as PublicKeyCredential | null;
        if (current !== epoch.current) return;
        if (!credential) throw new Error("unavailable");
        const response = credential.response as AuthenticatorAssertionResponse;
        assertion.current = {
          id: credential.id,
          rawId: coerceToBase64Url(credential.rawId, "rawId"),
          type: credential.type,
          response: {
            authenticatorData: coerceToBase64Url(response.authenticatorData, "authenticatorData"),
            clientDataJSON: coerceToBase64Url(response.clientDataJSON, "clientDataJSON"),
            signature: coerceToBase64Url(response.signature, "signature"),
            userHandle: response.userHandle ? coerceToBase64Url(response.userHandle, "userHandle") : null,
          },
        };
      }
      const response = await fetch(`${base}/complete`, {
        method: "POST",
        cache: "no-store",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({ capability, assertion: assertion.current }),
      });
      if (!response.ok) throw new Error("unavailable");
      const result = await response.json();
      if (current === epoch.current) router.push(callback(result.callbackUrl));
    } catch {
      if (current === epoch.current) setError(true);
    } finally {
      if (current === epoch.current) {
        setBusy(false);
        prompt.current = null;
      }
    }
  }
  async function cancel() {
    if (!flow || cancelling) return;
    epoch.current++;
    prompt.current?.abort();
    setCancelling(true);
    setError(false);
    try {
      const response = await fetch(`${base}/cancel`, {
        method: "POST",
        cache: "no-store",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({ capability }),
      });
      if (!response.ok) throw new Error("unavailable");
      const result = await response.json();
      router.push(callback(result.callbackUrl));
    } catch {
      setError(true);
    } finally {
      setBusy(false);
      setCancelling(false);
    }
  }
  const grantPrefix = flow?.action.startsWith("operations.access.kyc-grant.")
    ? "kycGrant"
    : flow?.action.startsWith("operations.access.deployment-grant.")
      ? "deploymentGrant"
      : flow?.action.startsWith("operations.access.grant.")
        ? "grant"
        : undefined;
  const action = grantPrefix
    ? grantPrefix +
      flow!.action
        .split(".")
        .at(-1)!
        .replace(/^./, (letter) => letter.toUpperCase())
    : flow?.action.split(".").at(-1);
  return (
    <DynamicTheme>
      <div className="flex flex-col space-y-4">
        <h1>{t("title")}</h1>
        <p className="ztdl-p">{t("description")}</p>
      </div>
      <div className="w-full" aria-busy={busy || checking || cancelling}>
        {flow && <p className="ztdl-p mb-4">{t(`actions.${action}`)}</p>}
        {checking ? (
          <p role="status" className="ztdl-p">
            <Spinner className="h-5 w-5" />
            {t("checking")}
          </p>
        ) : (
          <>
            {error && (
              <div className="mb-4">
                <Alert>{t("unavailable")}</Alert>
              </div>
            )}
            {flow && (
              <p className="paypm-auth-return-guidance mb-4">
                {expired
                  ? t("expired")
                  : t("expires", { minutes: Math.max(1, Math.ceil((Date.parse(flow.expiresAt) - now) / 60000)) })}
              </p>
            )}
            <div className="flex flex-col gap-4">
              <Button
                className="w-full"
                disabled={busy || cancelling || expired}
                onClick={() => void (flow ? verify() : load())}
              >
                {busy ? (
                  <>
                    <Spinner className="h-5 w-5" />
                    {t("verifying")}
                  </>
                ) : (
                  t(flow ? (assertion.current ? "retryVerification" : "verify") : "retry")
                )}
              </Button>
              {flow && (
                <Button
                  className="w-full"
                  variant={ButtonVariants.Secondary}
                  disabled={cancelling}
                  onClick={() => void cancel()}
                >
                  {t("cancel")}
                </Button>
              )}
            </div>
            {flow && (
              <p className="paypm-auth-return-guidance mt-4">
                <a href={flow.returnUrl}>{t("return")}</a>
              </p>
            )}
          </>
        )}
      </div>
    </DynamicTheme>
  );
}
