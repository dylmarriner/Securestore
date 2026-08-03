-- Generic external-identity linkage for non-API-key auth methods, so one
-- column (rather than one per method) covers OIDC (subject claim), mTLS
-- (client certificate fingerprint), and any future method. Uniqueness is
-- scoped per auth_method since the same raw string could theoretically
-- collide across methods' namespaces (an OIDC `sub` vs. a cert
-- fingerprint are drawn from unrelated spaces, but nothing guarantees
-- that in general).

ALTER TABLE agents ADD COLUMN auth_identifier text;

CREATE UNIQUE INDEX agents_auth_method_identifier_idx
  ON agents(auth_method, auth_identifier)
  WHERE auth_identifier IS NOT NULL;
