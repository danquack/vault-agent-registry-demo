# =============================================================
# Vault — OAuth RS, secrets, ceiling policies, agent registry
# =============================================================
#
# The Vault provider doesn't have native resources for agent
# registry or OAuth Resource Server yet (Vault 2.x is new),
# so we use vault_generic_endpoint. Functionally identical,
# just less typed than a dedicated resource.

# --- Step 1: Activate OAuth Resource Server ---

resource "vault_generic_endpoint" "activate_oauth_rs" {
  path                 = "sys/activation-flags/oauth-resource-server/activate"
  disable_read         = true
  disable_delete       = true
  ignore_absent_fields = true
  data_json            = "{}"
}

# --- Step 2: Tell Vault to trust ZITADEL ---
#
# This creates an OAuth Resource Server "profile." When Vault sees
# a Bearer JWT, it matches the iss claim to a profile, fetches
# ZITADEL's public keys via JWKS, and validates the signature.
#
# ZITADEL's exchanged tokens carry the project ID as their audience
# (see zitadel.tf's exchange_app), not a per-agent client ID, so Vault
# only needs one profile with the project ID as the trusted audience.

locals {
  zitadel_issuer = "http://${var.zitadel_domain}:${var.zitadel_port}"
}

resource "vault_generic_endpoint" "oauth_rs_profile" {
  depends_on = [vault_generic_endpoint.activate_oauth_rs]

  path                 = "sys/config/oauth-resource-server/zitadel"
  disable_read         = true
  disable_delete       = true
  ignore_absent_fields = true

  data_json = jsonencode({
    issuer_id            = local.zitadel_issuer
    use_jwks             = true
    jwks_uri             = "${local.zitadel_issuer}/oauth/v2/keys"
    audiences            = [zitadel_project.demo.id]
    supported_algorithms = ["RS256"]
    user_claim           = "sub"
  })
}

# --- Step 3: Secrets ---
#
# Vault dev mode already auto-mounts "secret/" as a kv-v2 engine,
# so we just write into it rather than mounting it ourselves.

resource "vault_kv_secret_v2" "staging_db" {
  mount = "secret"
  name  = "staging/db-creds"
  data_json = jsonencode({
    username = "staging_app"
    password = "stg-hunter2"
    host     = "staging-db.internal:5432"
    database = "myapp_staging"
  })
}

resource "vault_kv_secret_v2" "staging_api" {
  mount = "secret"
  name  = "staging/api-keys"
  data_json = jsonencode({
    stripe_key   = "sk_test_abc123"
    sendgrid_key = "SG.test.xyz"
  })
}

resource "vault_kv_secret_v2" "prod_db" {
  mount = "secret"
  name  = "prod/db-creds"
  data_json = jsonencode({
    username = "prod_app"
    password = "ULTRA-SECRET-prod-pw"
    host     = "prod-db.internal:5432"
    database = "myapp_prod"
  })
}

# --- Step 4: Ceiling policies ---
#
# Ceiling policies set the MAXIMUM an agent can ever do.
# They're different from normal policies — a normal policy
# grants access, a ceiling policy caps it.

resource "vault_policy" "staging_ceiling" {
  name = "agent-staging-ceiling"

  policy = <<-EOT
    # Can read anything in staging
    path "secret/data/staging/*" {
      capabilities = ["read", "list"]
    }
    path "secret/metadata/staging/*" {
      capabilities = ["read", "list"]
    }

    # Can check its own registry record
    path "agent-registry/registration/entity-id/{{identity.entity.id}}" {
      capabilities = ["read"]
    }

    # Can never touch prod
    path "secret/data/prod/*" {
      capabilities = ["deny"]
    }
  EOT
}

resource "vault_policy" "narrow_ceiling" {
  name = "agent-narrow-ceiling"

  policy = <<-EOT
    # Can ONLY read this one specific secret
    path "secret/data/staging/db-creds" {
      capabilities = ["read"]
    }

    # Can check its own registry record
    path "agent-registry/registration/entity-id/{{identity.entity.id}}" {
      capabilities = ["read"]
    }

    # Everything else is denied
    path "secret/data/prod/*" {
      capabilities = ["deny"]
    }
  EOT
}

# --- Step 5: Baseline ACL policy ---
#
# The ceiling policy only CAPS access — it doesn't GRANT it. The
# baseline ACL (the entity's normal Vault policies) has to permit
# the path too. We give both agents the same broad baseline; each
# agent's ceiling then narrows what it can actually reach.

resource "vault_policy" "agent_baseline" {
  name = "agent-baseline"

  policy = <<-EOT
    path "secret/data/staging/*" {
      capabilities = ["read", "list"]
    }
    path "secret/metadata/staging/*" {
      capabilities = ["read", "list"]
    }
    path "secret/data/prod/*" {
      capabilities = ["read", "list"]
    }
    path "secret/metadata/prod/*" {
      capabilities = ["read", "list"]
    }
    path "agent-registry/registration/entity-id/{{identity.entity.id}}" {
      capabilities = ["read"]
    }
  EOT
}

# --- Step 6: Identity entities ---
#
# Each agent gets a Vault identity entity. The OAuth RS profile
# maps the JWT's sub claim to this entity via an alias (see below).

resource "vault_identity_entity" "ceiling_agent" {
  name     = "ceiling-agent"
  policies = ["default", "agent-baseline"]
  metadata = {
    agent_type = "ai-agent"
    demo       = "ceiling-only"
    model      = "claude"
  }
}

resource "vault_identity_entity" "rar_agent" {
  name     = "rar-agent"
  policies = ["default", "agent-baseline"]
  metadata = {
    agent_type = "ai-agent"
    demo       = "rar-scoped"
    model      = "claude"
  }
}

# Stand-in "subject" for the OBO delegation demo -- see zitadel.tf's
# delegated_subject machine user. This is the identity the agents act on
# behalf of via ZITADEL's real RFC 8693 token exchange; it needs the same
# baseline policy as the agents so the demo isolates "does the act claim
# make Vault apply the ceiling" rather than "does the subject even have
# baseline access."
resource "vault_identity_entity" "delegated_subject" {
  name     = "delegated-subject-test"
  policies = ["default", "agent-baseline"]
  metadata = {
    demo = "obo-delegation-subject"
  }
}

# --- Step 7: Entity aliases ---
#
# This is the missing link: it tells Vault "a JWT from this issuer,
# whose sub/act.sub claim equals this value, IS this Vault identity
# entity." Without this, the OAuth RS can validate the JWT signature but
# has no entity to resolve it to, so every request falls back to no
# policy at all.
#
# ZITADEL's `sub` claim is the machine user's numeric user ID (not a
# predictable username string like Authentik's), so each alias's `name`/
# `external_id` is that resource's own `id` -- both entities and their
# corresponding ZITADEL machine users are created in this same apply, so
# the real IDs are always available before the alias needs them.
#
# There's no typed resource for this yet (OAuth RS aliases key off
# "issuer", not the traditional "mount_accessor"), so we use
# vault_generic_endpoint against the raw identity API.

resource "vault_generic_endpoint" "ceiling_agent_alias" {
  depends_on = [
    vault_identity_entity.ceiling_agent,
    zitadel_machine_user.ceiling_agent,
  ]

  path                 = "identity/entity-alias"
  disable_read         = true
  disable_delete       = true
  ignore_absent_fields = true

  data_json = jsonencode({
    name         = zitadel_machine_user.ceiling_agent.id
    canonical_id = vault_identity_entity.ceiling_agent.id
    issuer       = local.zitadel_issuer
    external_id  = zitadel_machine_user.ceiling_agent.id
  })
}

resource "vault_generic_endpoint" "rar_agent_alias" {
  depends_on = [
    vault_identity_entity.rar_agent,
    zitadel_machine_user.rar_agent,
  ]

  path                 = "identity/entity-alias"
  disable_read         = true
  disable_delete       = true
  ignore_absent_fields = true

  data_json = jsonencode({
    name         = zitadel_machine_user.rar_agent.id
    canonical_id = vault_identity_entity.rar_agent.id
    issuer       = local.zitadel_issuer
    external_id  = zitadel_machine_user.rar_agent.id
  })
}

# Alias for the OBO demo's stand-in subject -- see delegated_subject above
# and zitadel.tf's delegated_subject machine user, whose ID becomes the
# exchanged JWT's top-level sub claim.
resource "vault_generic_endpoint" "delegated_subject_alias" {
  depends_on = [
    vault_identity_entity.delegated_subject,
    zitadel_machine_user.delegated_subject,
  ]

  path                 = "identity/entity-alias"
  disable_read         = true
  disable_delete       = true
  ignore_absent_fields = true

  data_json = jsonencode({
    name         = zitadel_machine_user.delegated_subject.id
    canonical_id = vault_identity_entity.delegated_subject.id
    issuer       = local.zitadel_issuer
    external_id  = zitadel_machine_user.delegated_subject.id
  })
}

# --- Step 6: Agent Registry records ---
#
# This is the key part. Each agent must be registered before
# it can authenticate via OAuth. The registration links the
# entity to its ceiling policies.

resource "vault_generic_endpoint" "register_ceiling_agent" {
  depends_on = [
    vault_generic_endpoint.oauth_rs_profile,
    vault_identity_entity.ceiling_agent,
    vault_policy.staging_ceiling,
  ]

  path                 = "agent-registry/register"
  disable_read         = true
  disable_delete       = true
  ignore_absent_fields = true

  data_json = jsonencode({
    display_name                   = "ceiling-agent"
    entity_id                      = vault_identity_entity.ceiling_agent.id
    ceiling_policies               = ["agent-staging-ceiling"]
    description                    = "Demo agent: ceiling policy only. Can read all of staging, denied prod."
    optional_authorization_details = true # no RAR required
    owner                          = vault_identity_entity.delegated_subject.id
  })
}

resource "vault_generic_endpoint" "register_rar_agent" {
  depends_on = [
    vault_generic_endpoint.oauth_rs_profile,
    vault_identity_entity.rar_agent,
    vault_policy.narrow_ceiling,
  ]

  path                 = "agent-registry/register"
  disable_read         = true
  disable_delete       = true
  ignore_absent_fields = true

  data_json = jsonencode({
    display_name                   = "rar-agent"
    entity_id                      = vault_identity_entity.rar_agent.id
    ceiling_policies               = ["agent-narrow-ceiling"]
    description                    = "Demo agent: ceiling + RAR. Ceiling allows staging/db-creds only. RAR scopes per-request."
    optional_authorization_details = false # RAR required on every request
    owner                          = vault_identity_entity.delegated_subject.id
  })
}

# The stand-in subject is also registered as an agent in its own right --
# an ad-hoc diagnostic for the on-behalf-of investigation (does registering
# the subject itself change anything about OBO resolution?). Self-owned
# since it isn't delegating to another identity.
resource "vault_generic_endpoint" "register_delegated_subject" {
  depends_on = [
    vault_generic_endpoint.oauth_rs_profile,
    vault_identity_entity.delegated_subject,
    vault_policy.staging_ceiling,
  ]

  path                 = "agent-registry/register"
  disable_read         = true
  disable_delete       = true
  ignore_absent_fields = true

  data_json = jsonencode({
    display_name                   = "delegated-subject-test"
    entity_id                      = vault_identity_entity.delegated_subject.id
    ceiling_policies               = ["agent-staging-ceiling"]
    description                    = "Ad-hoc registration for the OBO demo's stand-in subject, to test whether registering the subject itself as an agent affects on-behalf-of resolution."
    optional_authorization_details = true # no RAR required
    owner                          = vault_identity_entity.delegated_subject.id
  })
}

# --- Outputs ---

output "ceiling_agent_entity_id" {
  value = vault_identity_entity.ceiling_agent.id
}

output "rar_agent_entity_id" {
  value = vault_identity_entity.rar_agent.id
}
