# Finite Contract Vault read grant continuation

Locked scope: add only `operations.contract-vault.read` to the existing finite
Operations deployment-read grant parser. Operations owns the explicit current
reviewer policy, exact deployment/environment resource admission and independent
grant effect. Login owns the fresh provider proof. No new policy, default grant,
company permission, KYC action or data ownership is introduced. Existing policies
must explicitly enumerate this capability before an actor can receive it.

The actual backend checkpoint 612a320 fixture is copied verbatim. Independent
tests recompute the explicit policy hash, canonical action hash and raw HMAC,
then exercise strict7 command/resource5/proof20, family separation and altered
owner denial. Current paired base, UP/UV, exact original operation, once-use
receipt, cancellation/logout and pure status semantics remain unchanged.
Twenty actual PostgreSQL lifecycle tests include concurrent retries for this
exact fixture. No presentation code or copy changes; design research does not
apply to this headless finite catalogue addition.

129 focused, 20 actual PostgreSQL and 1,329 full Login checks pass, with 42
intentional database/opt-in skips. Production types, owned lint and Webpack
build pass. Staged offline scan is separate. No live owner policy, credential,
role grant, provider or deployed resource admission was created.
