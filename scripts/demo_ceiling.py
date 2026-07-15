#!/usr/bin/env python3
"""
DEMO 1: CEILING POLICY ONLY
============================
This agent has a ceiling policy that allows all of staging/* but denies prod/*.
No RAR constraints -- the ceiling is the only guardrail.

Per Vault's docs, ceiling policies are only enforced for delegated,
"on-behalf-of" requests -- a plain client_credentials token never exercises
them. So the JWT here carries that shape: top-level `sub` names a stand-in
subject ("delegated-subject-test"), and a nested `act.sub` names ceiling-agent
as the actor -- a real RFC 8693 token exchange against ZITADEL, not a
hand-fabricated claim (see terraform/zitadel.tf and lib.get_obo_token).

The scenario is fixed on purpose: "deploy to staging, then run a prod health
check" always requests the same three paths, so every run is identical and
reproducible -- no AI model is involved in deciding what to ask for.
"""

import os

from lib import decode_jwt, fetch_secret, get_obo_token, load_credentials, print_results, print_token_steps

VAULT_ADDR = os.environ.get("VAULT_ADDR", "http://localhost:8200")
ZITADEL_URL = os.environ.get("ZITADEL_URL", "http://localhost:8080")
TOKEN_ENDPOINT = f"{ZITADEL_URL}/oauth/v2/token"

# Fixed scenario: deploy v2.3.1 to staging, then a prod health check.
PATHS = ["staging/db-creds", "staging/api-keys", "prod/db-creds"]


def main():
    print()
    print("=" * 60)
    print("  DEMO 1: CEILING POLICY ONLY")
    print("  Agent: ceiling-agent, acting on behalf of: delegated-subject-test")
    print("  Ceiling: agent-staging-ceiling (staging=yes, prod=no)")
    print("  RAR: disabled (optional_authorization_details=true)")
    print("  Scenario: deploy v2.3.1 to staging, then a prod health check")
    print("=" * 60)
    print()

    creds = load_credentials()
    token = get_obo_token(TOKEN_ENDPOINT, creds, creds["ceiling_agent_client_id"], creds["ceiling_agent_client_secret"])
    _, claims = decode_jwt(token)
    print_token_steps("ceiling-agent", claims)

    results = [fetch_secret(VAULT_ADDR, token, path) for path in PATHS]
    print_results(results)

    print("Ceiling policy 'agent-staging-ceiling' should allow staging/* and")
    print("deny prod/* -- see the per-request breakdown above for what")
    print("actually happened, derived from Vault's own server logs.")
    print()


if __name__ == "__main__":
    main()
