# PayPM hosted authentication composition

- Revision 2; owner root; state execute; baseline 6ba47a95555d67aea0a5107572bd9d000384aebe was clean; worker ownership changes are now present.
- Linked to the existing active cross-surface PayPM delivery goal. This is the unfinished hosted-auth visual slice, not completion of that goal.
- Plane: shared hosted authentication; authorized actor: requesting app's returning subject; denied actor: unaffiliated or insufficiently authorized subject remains denied by the product API.
- Truth/dependencies: ZITADEL v4.15.3 owns authentication; Identity owns memberships; product APIs own permissions. No new API or authority in this slice.
- Copy: bundled French and English namespaces in apps/login/locales; explicit provider overrides retain their existing precedence.
- UI: Tier A replacement of stock hosted composition within the already approved PayPM/C3 identity. Operate mode. Standard source slice, sensitive-auth preservation and later GitOps release overlays.
- State model: identifier/account selection, password/passkey/MFA, pending ceremony, inline rejected attempt, legitimate recovery, return. No financial completion or permission claim.
- Non-goals: new products, provider changes, registration-policy changes, memberships, role grants, credentials, certification, or production MFA enrollment for visual captures.

## Ready plan and acceptance

| ID | Step/outcome | Dependency and proof | Status |
| --- | --- | --- | --- |
| AUTH-V1 | Ground surface in constitution, existing C3 choice, live references and actual source owner map | PRODUCT.md, design-research, inspected target-geometry comps | passed; selected arrival-seam |
| AUTH-V2 | Shared PayPM shell/primitives cover existing ceremony content without dropped children | V1; component tests, all existing tests, TS/build and changed-source lint | not run |
| AUTH-V3 | FR/EN, compact/wide, errors, recovery, focus and reduced-motion remain usable | V2; rendered routes/catalog plus browser/device interaction | not run |
| AUTH-V4 | Immutable canary and public deployment retain real authentication behavior | V2-V3; GitOps, runtime, real native entry and callback evidence | not run |

Full private authentication is independent of visual development. Owner explicitly permits handling development credentials through the ordinary flow; secrets must remain out of logs/screenshots/commits. No known password is inferred and existing MFA remains enforced. Do not classify the whole goal blocked while useful authorized work remains.

Next action: implement the selected shared shell and semantic primitives; preserve every child and provider state. Keep comps by represented screen in .impeccable/mocks/hosted-auth/ with prompts and selected variant. Do not duplicate another commercial client.
