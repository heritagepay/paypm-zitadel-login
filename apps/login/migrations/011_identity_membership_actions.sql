-- Keep legacy Wallet bindings; admit only the ordinary Identity membership family.
ALTER TABLE login_identity_action_requests
  DROP CONSTRAINT login_identity_action_requests_binding_check,
  ADD CONSTRAINT login_identity_action_requests_binding_check CHECK (
    (
      (binding->'expected'->>'appId' = 'identity-administration')
      AND (
        (binding->'command'->>'purpose' = 'wallet_legacy_linkage'
         AND binding->'expected'->>'action' IN ('identity.wallet.legacy.linkage.intake','identity.wallet.legacy.linkage.review'))
        OR
        (binding->'command'->>'purpose' = 'commercial_membership'
         AND binding->'expected'->>'action' = 'identity.organization.membership.add'
         AND binding->'command'->>'role' = 'member'
         AND binding->'command'->>'businessId' ~ '^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[1-8][0-9a-fA-F]{3}-[89abAB][0-9a-fA-F]{3}-[0-9a-fA-F]{12}$'
         AND binding->'command'->>'memberPersonId' ~ '^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[1-8][0-9a-fA-F]{3}-[89abAB][0-9a-fA-F]{3}-[0-9a-fA-F]{12}$')
      )
    ) IS TRUE
  );
