-- Store the OIDC nonce bound to a one-time login state.

ALTER TABLE login_states ADD COLUMN nonce TEXT;
