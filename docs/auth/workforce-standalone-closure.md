# Workforce Login standalone dependency closure

The production Next16.2.6 build uses the existing locked pnpm10.30.3 workspace,
monorepo tracing root and default Turbopack collector. The standalone copy must
contain every target of its retained relative dependency links before the
unchanged production Dockerfile copies it into `/app`.

The contained build of merged `5782b451` completed dependency installation, proto
generation, client build and Login build. Its subsequent source-byte check
passed, but the full standalone closure check found exactly these two dangling
links. ROOT's bounded public package diagnostic confirmed their original
installed source targets and package versions:

| Retained standalone link | Original literal target | Locked package source |
| --- | --- | --- |
| `node_modules/.pnpm/node_modules/@colors/colors` | `../../@colors+colors@1.5.0/node_modules/@colors/colors` | `node_modules/.pnpm/@colors+colors@1.5.0/node_modules/@colors/colors` |
| `node_modules/.pnpm/node_modules/has-flag` | `../has-flag@3.0.0/node_modules/has-flag` | `node_modules/.pnpm/has-flag@3.0.0/node_modules/has-flag` |

These are existing hoisted workspace targets, not dependency upgrades. The
committed lock contains Colors1.5.0 under Karma6.4.4 and Has-flag3.0.0 under
Supports-color5.5.0, including the Nodemon3.1.14 development chain. Login's
Winston3.19.0 and Logform2.7.0 use Colors1.6.0; Supports-color7.2.0/8.1.1 use
Has-flag4.0.0. The original traces already contain the latter runtime versions.
Closing a retained hoisted link does not replace those existing packages or
claim that the historical test/development package owns Login behavior.

`next.config.mjs` includes only the two exact locked source package directories
in server-route traces. The patterns are relative to `apps/login` as required by
the [official Next output tracing contract](https://nextjs.org/docs/app/api-reference/config/next-config-js/output).
The workspace tracing root, collector, package manager, dependency versions,
server wrappers, Dockerfile, SQL001–006 and all authentication/authorization
policies remain unchanged. No links are removed, retargeted or adopted from a
foreign dependency tree.

The focused regression uses the actual pinned Next copier and glob against
synthetic `.nft.json` files. It reproduces both missing targets before includes,
then verifies retained literal links, byte-identical package contents and
standalone module resolution, preservation of the already traced1.6.0/4.0.0
versions, and exclusion of unrelated package payloads. This source gate does
not replace the actual contained production build: ROOT must run the unchanged
full standalone and final-image byte/closure checks against the new normally
merged source before publication. Server boot, migration execution, provider
readiness, staff eligibility and real email-OTP/passkey actors remain separate
gates. Default workforce readiness stays held.
