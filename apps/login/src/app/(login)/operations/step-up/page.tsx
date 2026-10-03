import { OperationsActionPasskey } from "@/components/operations-action-passkey";
import type { Metadata } from "next";
import { getTranslations } from "next-intl/server";
export const dynamic = "force-dynamic";
export async function generateMetadata(): Promise<Metadata> {
  const t = await getTranslations("operationsAction");
  return { title: t("title"), referrer: "no-referrer", robots: { index: false, follow: false } };
}
export default async function Page({
  searchParams,
}: {
  searchParams: Promise<Record<string, string | string[] | undefined>>;
}) {
  const value = await searchParams,
    requestId =
      typeof value.requestId === "string" &&
      /^[a-f0-9]{8}-[a-f0-9]{4}-4[a-f0-9]{3}-[89ab][a-f0-9]{3}-[a-f0-9]{12}$/i.test(value.requestId)
        ? value.requestId
        : "invalid",
    capability =
      typeof value.capability === "string" && /^[A-Za-z0-9_-]{43}$/.test(value.capability) ? value.capability : "invalid";
  return <OperationsActionPasskey requestId={requestId} capability={capability} />;
}
