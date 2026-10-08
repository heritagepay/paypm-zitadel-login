# Workforce provider identification and authentication

The provider user lookup binds a Session to its subject. It does not prove possession of an OTP, password or passkey. In pinned ZITADEL4.15.3, `CheckUser` captures its timestamp before `SessionAdded` is persisted: [native command source](https://github.com/zitadel/zitadel/blob/v4.15.3/internal/command/session.go). A user-check timestamp earlier than creation is valid identification; an arbitrary tolerance window would confuse provider semantics with clock skew.

`sessionIdentifiesUser` checks nonempty subject, valid provider timestamps and lifecycle structure. It permits expired historical records solely for exact owned inspection. `activeSessionIdentifiesUser` also enforces current provider expiry and the eight-hour absolute ceiling. Callers retain exact expected subject, organization, client, request and metadata checks.

Every credential still uses strict `verifiedFactor` checks after creation and before current time. Workforce limited admission additionally requires verified email and an enrolled, provider-accepted fresh OTP. Action ceremonies still require current base admission, exact payload/resource/context, signed UP/UV, provider user verification, request freshness and one-use receipts. Identification alone grants neither login admission nor canonical enrollment nor privileges.

The original expired enrollment attempt cannot be repaired by editing its timestamps, replacing its identity or describing a new binary as its old pinned runtime. A separately qualified successor attempt and runtime lineage are the next required implementation; this repair does not implement or activate them.
