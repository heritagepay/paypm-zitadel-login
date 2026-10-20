"use client";

import { Logo } from "@/components/logo";
import { PaypmBrand } from "@/components/paypm-brand";
import { useResponsiveLayout } from "@/lib/theme-hooks";
import { BrandingSettings } from "@zitadel/proto/zitadel/settings/v2/branding_settings_pb";
import { Children, ReactNode } from "react";
import { ThemeWrapper } from "./theme-wrapper";

/** Shared PayPM ceremony frame. Provider branding and every ceremony section are retained. */
export function DynamicTheme({
  branding,
  children,
}: {
  children: ReactNode | ((isSideBySide: boolean) => ReactNode);
  branding?: BrandingSettings;
}) {
  const { isSideBySide } = useResponsiveLayout();
  const actualChildren = typeof children === "function" ? children(isSideBySide) : children;
  const sections = Children.toArray(actualChildren);
  const hasSeparateTitle = sections.length > 1;

  return (
    <ThemeWrapper branding={branding}>
      <section className="paypm-auth-frame">
        <header className="paypm-auth-arrival">
          <PaypmBrand />
          {hasSeparateTitle && <div className="paypm-auth-title">{sections[0]}</div>}
        </header>
        <div className="paypm-auth-work">
          {branding?.lightTheme?.logoUrl && (
            <div className="paypm-auth-organization-brand">
              <Logo lightSrc={branding.lightTheme.logoUrl} height={40} width={148} />
            </div>
          )}
          {hasSeparateTitle ? sections.slice(1) : actualChildren}
        </div>
      </section>
    </ThemeWrapper>
  );
}
