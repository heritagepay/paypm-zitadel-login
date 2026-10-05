# Workforce Login standalone dependency closure

- Owner: backend_auth; shared workforce authentication plane, not a commercial product.
- Authorized slice: ROOT's necessary source packaging repair after the actual contained production build of normally merged `5782b451ee615c51ac6c0a67b23e36cc24b5ba3d` / tree `89a8590f39b96924c2f141f4016f41560bd6eb75` failed its unchanged full standalone link-closure gate.
- Isolated branch: `fix/workforce-standalone-color-closure-20261005`. Preserve primary dirty UI, original action backlog, old CORE source and all failed build operations/diagnostics.
- Actual reported failure: production pnpm install, proto generation, client build and default Next16.2.6 Turbopack Login build completed. Source-byte parity passed. Exactly two standalone hoisted dependency links were dangling: `node_modules/.pnpm/node_modules/@colors/colors` and `node_modules/.pnpm/node_modules/has-flag`.
- Actor: authorized release operator. Denied actors: anonymous/browser/commercial principals attempting staff access or migration authority; their contracts are unchanged.
- Truth/providers: ZITADEL owns workforce credentials/current sessions; Identity owns Person and staff capabilities. This packaging correction changes neither truth.
- Dependencies: committed pnpm lock and exact existing dependency versions; unchanged Next tracing root and production build/Dockerfile/manager.
- State: source repair preparation; build/image/server/migration/provider/staff gates remain distinct and held until actual ROOT qualification.
- Design tier: not applicable; no presentation or French/English copy change.
- Non-goals: no UI, credentials, roles, invitations, OTP/passkey policy, migration SQL, server wrappers, dependency upgrade, webpack fallback, deployment or publication. Do not remove arbitrary dangling links or weaken the full closure gate.

## Acceptance

1. Bind each corrective include to the actual reported symlink target, its committed locked package and owning dependency chain. Do not guess a hoisted version from the existence of multiple lock entries.
2. Use narrow Next output tracing includes, preserve all previously configured tracing and server external dependencies, and retain the original production build recipe.
3. Reproduce both missing targets with an isolated synthetic trace/standalone fixture; prove the included package bytes close the retained links and load from the standalone tree, without external dependency traversal or an arbitrary package payload.
4. Run focused tests and relevant established source quality gates. Record inherited baseline failures explicitly and keep root's actual contained build separate.
5. Freeze a clean coherent reviewed commit and deliver a normal source PR under the existing authorization; ROOT owns merge and all artifact/runtime actions.

## Source basis

The committed Login importer depends on Winston3.19.0. Winston and Logform2.7.0 depend on `@colors/colors`1.6.0. The lock also contains `@colors/colors`1.5.0 under Karma6.4.4; that historical workspace/test chain does not independently prove a Login runtime requirement. Supports-color5.5.0 uses has-flag3.0.0; Supports-color7.2.0 and8.1.1 use has-flag4.0.0. ROOT subsequently confirmed both actual retained targets: Colors1.5.0 and Has-flag3.0.0. The includes select those exact existing store directories only; active NFT runtime entries for Colors1.6.0 and Has-flag4.0.0 are retained.

The [official Next output tracing contract](https://nextjs.org/docs/app/api-reference/config/next-config-js/output) describes project-relative includes combined with a monorepo tracing root. The local qualified Next16.2.6 collector applies includes to server route `.nft.json` files before standalone copying. No root-wide `**/*` include or exclusion is authorized.


## Qualified source gates and limits

- Focused existing migration packaging/enumeration plus new tracing regression: `bun run test-unit src/lib/workforce-standalone-tracing.test.ts src/lib/workforce-migration-packaging.test.ts src/lib/workforce-migrations.test.ts` passed3 files/11 tests.
- Actual pinned Next16.2.6 `copyTracedFiles` and compiled glob are exercised against synthetic traces. They reproduce the original two dangling links, then prove unchanged literal links and target bytes, standalone `require` resolution, retained1.6.0/4.0.0 runtime bytes and exclusion of an unrelated synthetic package.
- Local profile reuses the existing CORE dependency payload, not a new dependency installation; Bun invokes the unchanged Vitest script, whose actual child runtime is Node/Vitest4.1.7. Contained release pnpm10.30.3 and source lock remain unchanged.
- Full ESLint:0 errors/1 unchanged console warning. Owned config/test formatting and `git diff --check` pass.
- Full `bun .../typescript/bin/tsc --noEmit --incremental false`:30 diagnostics, byte-identical to the unchanged6c CORE baseline;0 new owned diagnostics. This inherited type gate is not reported green.
- Initial full unit invocation found a missing checked-in JSON fixture because the new checkout's sparse paths omitted root `docs/auth`. Restored the exact tracked source directory through sparse checkout; no fixture/assertion was invented or edited. Full unit result follows below.
- The incumbent formatter script includes `.` and touched three inherited formatting failures in this new isolated checkout. Those three changes were restored byte-for-byte from5782; no unrelated formatter repair remains. Full formatter baseline remains outside this slice.
- Initial scoped offline scan of the four owned source/record paths:16,069 bytes,0 findings. Final staged-source scan and immutable review binding follow below.
- No Docker build, image publication, migration/DB/credential/provider/native/device effect was performed by this child. ROOT's actual failed contained operations and diagnostics are retained; a new exact-source contained build is required after normal source delivery.

- Full unchanged `bun run test-unit`:93 passing files/1,338 passing tests;5 files/52 tests skipped because the explicit disposable-SQL opt-in was not configured. This slice changes no SQL and makes no fresh SQL execution claim. The CORE prior52-test execution remains separate historical evidence.

- Full unchanged `bun run lint-check-prettier` reports only the same three inherited paths: operations-logout-store.test.ts, server/idp-intent.test.ts and server/idp-intent.ts. All three bytes match5782; owned config/test formatting passes.

- Delivery visibility was reverified as PUBLIC for the existing `heritagepay/paypm-zitadel-login` fork. ROOT confirmed the inherited authorized source delivery covers this same fork and public package/config facts. No repository visibility change or private customer/provider/custody payload is included.

- Independent SOURCE review by `ory_release_prerequisites` cleared Nextconfig `ec0b6eb2a200ddea6f707281a655304c94b39b338cfa0c632ca338e29ad04f26` and tracing test `0f5d544d0dc8e3a0ad604bf7efaf3f762155c77a93c7d2d5a19cd67a8ae7ce66`: exact package targets, retained active versions, no collector or link pruning, and meaningful actual-Next synthetic regression. Reviewer did not execute tests/build/native or read custody.
- Final pinned-index offline Gitleaks scan covers all four owned paths and reports zero findings. Only truthful review/delivery records were appended after executable review; executable hashes remain unchanged.
