# =============================================================
# ZITADEL — identity provider issuing real RFC 8693 OBO tokens
# =============================================================
#
# Swapped in for Authentik: Authentik has no native on-behalf-of/token
# exchange support, so getting a JWT with a real `act` claim required
# hand-fabricating one via a custom scope-mapping expression. ZITADEL
# implements genuine RFC 8693 token exchange, including actor delegation
# that produces a real `act: {iss, sub}` claim -- confirmed via a live
# spike: subject_token + actor_token exchange, with the audience-scoping
# and requested_token_type details below, yields exactly the JWT shape
# Vault's Agent Registry docs describe.

# Explicit org rather than relying on whichever org the admin PAT happens
# to default to -- this version of the provider requires org_id on
# several resources below, so create one org and reference its id
# everywhere for consistency.
resource "zitadel_org" "demo" {
  name = "vault-agent-demo"
}

resource "zitadel_project" "demo" {
  org_id                 = zitadel_org.demo.id
  name                   = "vault-agent-demo"
  project_role_assertion = true
}

# One shared role: every OBO participant (the stand-in subject and both
# agents) gets it, purely so ZITADEL's audience-scoping (see the user
# grants below) has a role to grant. The role itself carries no meaning
# to Vault -- ceiling enforcement is entirely Vault's own agent-registry
# policy, set in vault.tf.
resource "zitadel_project_role" "obo_participant" {
  org_id       = zitadel_org.demo.id
  project_id   = zitadel_project.demo.id
  role_key     = "obo-participant"
  display_name = "OBO Participant"
}

# --- Stand-in subject: the identity both agents act on behalf of ---

resource "zitadel_machine_user" "delegated_subject" {
  org_id            = zitadel_org.demo.id
  user_name         = "delegated-subject-test"
  name              = "Delegated Subject Test"
  access_token_type = "ACCESS_TOKEN_TYPE_JWT"
  with_secret       = true
}

resource "zitadel_user_grant" "delegated_subject_grant" {
  org_id     = zitadel_org.demo.id
  project_id = zitadel_project.demo.id
  user_id    = zitadel_machine_user.delegated_subject.id
  role_keys  = [zitadel_project_role.obo_participant.role_key]
}

# --- ceiling-agent: acts on behalf of delegated_subject, no RAR ---

resource "zitadel_machine_user" "ceiling_agent" {
  org_id            = zitadel_org.demo.id
  user_name         = "ceiling-agent"
  name              = "Ceiling Agent"
  access_token_type = "ACCESS_TOKEN_TYPE_JWT"
  with_secret       = true
}

resource "zitadel_user_grant" "ceiling_agent_grant" {
  org_id     = zitadel_org.demo.id
  project_id = zitadel_project.demo.id
  user_id    = zitadel_machine_user.ceiling_agent.id
  role_keys  = [zitadel_project_role.obo_participant.role_key]
}

# Token exchange with an actor_token (impersonation) requires the actor
# to hold an instance-level impersonator role -- confirmed via the spike;
# without this the exchange fails with "actor_token invalid".
resource "zitadel_instance_member" "ceiling_agent_impersonator" {
  user_id = zitadel_machine_user.ceiling_agent.id
  roles   = ["IAM_ADMIN_IMPERSONATOR"]
}

# --- rar-agent: acts on behalf of delegated_subject, RAR on every request ---

resource "zitadel_machine_user" "rar_agent" {
  org_id            = zitadel_org.demo.id
  user_name         = "rar-agent"
  name              = "RAR Agent"
  access_token_type = "ACCESS_TOKEN_TYPE_JWT"
  with_secret       = true
}

resource "zitadel_user_grant" "rar_agent_grant" {
  org_id     = zitadel_org.demo.id
  project_id = zitadel_project.demo.id
  user_id    = zitadel_machine_user.rar_agent.id
  role_keys  = [zitadel_project_role.obo_participant.role_key]
}

resource "zitadel_instance_member" "rar_agent_impersonator" {
  user_id = zitadel_machine_user.rar_agent.id
  roles   = ["IAM_ADMIN_IMPERSONATOR"]
}

# Instance-wide switch required before any actor_token exchange is
# honored, regardless of per-user impersonator roles.
resource "zitadel_default_security_settings" "impersonation" {
  enable_impersonation = true
}

# --- The exchange client ---
#
# Token exchange is client-authenticated by an application, not by the
# subject/actor machine users themselves -- the demo scripts authenticate
# as this app to perform the actual exchange call. token_exchange must be
# paired with a "real" OIDC grant type (authorization_code here) for
# ZITADEL to accept the app's config as compliant; the redirect URI is
# never actually used since nothing in this demo does a browser login.
resource "zitadel_application_oidc" "exchange_app" {
  org_id            = zitadel_org.demo.id
  project_id        = zitadel_project.demo.id
  name              = "obo-exchange-app"
  redirect_uris     = ["http://localhost/callback"]
  response_types    = ["OIDC_RESPONSE_TYPE_CODE"]
  grant_types       = ["OIDC_GRANT_TYPE_AUTHORIZATION_CODE", "OIDC_GRANT_TYPE_TOKEN_EXCHANGE"]
  app_type          = "OIDC_APP_TYPE_WEB"
  auth_method_type  = "OIDC_AUTH_METHOD_TYPE_BASIC"
  access_token_type = "OIDC_TOKEN_TYPE_JWT"
}

# --- Hand credentials to the demo scripts ---
#
# The scripts run in separate containers from Terraform and can't read
# Terraform state directly, so write everything they need to a file on
# a volume both sides mount (see docker-compose.yml's agent-credentials
# volume).
resource "local_file" "agent_credentials" {
  filename        = "/agent-credentials/credentials.json"
  file_permission = "0644"
  content = jsonencode({
    issuer                 = local.zitadel_issuer
    project_id             = zitadel_project.demo.id
    exchange_client_id     = zitadel_application_oidc.exchange_app.client_id
    exchange_client_secret = zitadel_application_oidc.exchange_app.client_secret
    # .client_id here, not .id -- .id is the entity's numeric user ID (what
    # ends up in the JWT's sub/act.sub claim, used directly by vault.tf's
    # entity aliases), while .client_id is the separate identifier OAuth
    # client_credentials calls actually authenticate with.
    delegated_subject_client_id     = zitadel_machine_user.delegated_subject.client_id
    delegated_subject_client_secret = zitadel_machine_user.delegated_subject.client_secret
    ceiling_agent_client_id          = zitadel_machine_user.ceiling_agent.client_id
    ceiling_agent_client_secret      = zitadel_machine_user.ceiling_agent.client_secret
    rar_agent_client_id              = zitadel_machine_user.rar_agent.client_id
    rar_agent_client_secret          = zitadel_machine_user.rar_agent.client_secret
  })
}
