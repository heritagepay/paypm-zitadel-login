# ZITADEL Login App Guide for AI Agents

## Context
The **Login App** (`apps/login`) provides the user interface for authentication flows (Login, Register, MFA, etc.). It is built with Next.js and React.

## Key Technology
- **Framework**: Next.js (React).
- **Styling**: TailwindCSS, configured via `apps/login/tailwind.config.mjs`.
- **Data Fetching**: Primarily server-side interaction with ZITADEL APIs via `@zitadel/client` or direct gRPC calls where applicable.
- **Language**: TypeScript.

## Architecture & Conventions
- **Routing**: Uses the Next.js App Router (routes are defined under `src/app/`).
- **Composability**: Components should be small and reusable.
- **State**: Critical authentication state is often managed via URL parameters (Auth Requests) and cookies/sessions.
- **Scope Rule**: For shared API typings and client behavior, also read `packages/AGENTS.md` and `proto/AGENTS.md`.

## Verified Nx Targets
- **Dev Server**: `pnpm nx run @zitadel/login:dev`
- **Build**: `pnpm nx run @zitadel/login:build`
- **Lint**: `pnpm nx run @zitadel/login:lint`
- **Test (all)**: `pnpm nx run @zitadel/login:test`
- **Test (unit)**: `pnpm nx run @zitadel/login:test-unit`
- **Test (integration)**: `pnpm nx run @zitadel/login:test-integration`
- **Pack (Docker)**: `pnpm nx run @zitadel/login:pack` — builds a local Docker image `zitadel/zitadel-login:local`. Requires Docker daemon.
- **PayPM image**: the in-cluster build engine builds every new `paypm-v4.15.3` head into `registry.paypm.net/heritagepay/zitadel-login:<sha>` (linux/amd64, labelled with the source revision and tree; build only, release pins stay manual). See `docs/BUILD_ENGINE.md` in heritagepay-gitops; the digest of each build is recorded in ConfigMap `paypm-build-ledger` (namespace `paypm-build`).
