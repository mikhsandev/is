-- Opt-in LAN callback capability is independent for every confidential development client.
-- OAuth provider tables remain managed by Better Auth.
CREATE TABLE nexus_oauth_dev_capabilities (
  oauth_client_id text PRIMARY KEY REFERENCES nexus_application_oauth_clients(oauth_client_id) ON DELETE RESTRICT,
  marker_uri text NOT NULL UNIQUE,
  enabled boolean NOT NULL DEFAULT false,
  changed_at timestamptz NOT NULL DEFAULT now(),
  changed_by text NOT NULL REFERENCES "user"(id)
);
CREATE TABLE nexus_oauth_dev_redirects (
  oauth_client_id text NOT NULL REFERENCES nexus_oauth_dev_capabilities(oauth_client_id) ON DELETE RESTRICT,
  redirect_uri text NOT NULL,
  created_at timestamptz NOT NULL DEFAULT now(),
  created_by text NOT NULL REFERENCES "user"(id),
  PRIMARY KEY(oauth_client_id, redirect_uri)
);
CREATE INDEX nexus_oauth_dev_redirects_lookup_idx ON nexus_oauth_dev_redirects(redirect_uri);
-- Audits use the existing nexus_registry_audit application-update event stream.
