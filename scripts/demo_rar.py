#!/usr/bin/env python3
"""
DEMO 2: RAR (Rich Authorization Requests)
==========================================
This agent has a narrow ceiling AND uses RAR to scope each request.

Per Vault's docs, ceiling policies are only enforced for delegated,
"on-behalf-of" requests -- a plain client_credentials token never exercises
them. So the JWT here carries that shape: top-level `sub` names a stand-in
subject ("delegated-subject-test"), and a nested `act.sub` names rar-agent
as the actor -- a real RFC 8693 token exchange against ZITADEL, not a
hand-fabricated claim (see terraform/zitadel.tf and lib.get_obo_token).

The orchestrator (this script, acting as the "task dispatcher") would
normally mint JWTs with authorization_details claims that say exactly which
path and capabilities each request is allowed to use. ZITADEL's RAR support
requires additional protocol config beyond what's set up here, so this demo
shows the concept by printing the RAR that would be in the JWT alongside the
real Bearer token, rather than actually embedding it.

The plan is fixed on purpose: no AI model is involved in deciding what to
request, so every run is identical and reproducible.
"""

import json
import os

from lib import decode_jwt, fetch_secret, get_obo_token, load_credentials, print_results, print_token_steps

VAULT_ADDR = os.environ.get("VAULT_ADDR", "http://localhost:8200")
ZITADEL_URL = os.environ.get("ZITADEL_URL", "http://localhost:8080")
TOKEN_ENDPOINT = f"{ZITADEL_URL}/oauth/v2/token"

# Fixed plan: deploy v2.3.1 to staging. No AI model involved in choosing this.
STEPS = [
    {"step": "Get DB connection info", "path": "staging/db-creds", "capability": "read"},
    {"step": "Get API keys", "path": "staging/api-keys", "capability": "read"},
]


def main():
    print()
    print("=" * 60)
    print("  DEMO 2: RAR (Rich Authorization Requests)")
    print("  Agent: rar-agent, acting on behalf of: delegated-subject-test")
    print("  Ceiling: agent-narrow-ceiling (only staging/db-creds)")
    print("  RAR: REQUIRED (optional_authorization_details=false)")
    print("=" * 60)

    print()
    print("  Layer 1 - Baseline ACL:  what the identity COULD do")
    print("  Layer 2 - Ceiling:       max the agent can EVER do")
    print("  Layer 3 - RAR:           what THIS REQUEST can do")
    print("  All three must permit the operation. RAR is embedded in the")
    print("  JWT by the orchestrator -- a per-request leash.")
    print()

    creds = load_credentials()
    token = get_obo_token(TOKEN_ENDPOINT, creds, creds["rar_agent_client_id"], creds["rar_agent_client_secret"])
    _, claims = decode_jwt(token)
    print_token_steps("rar-agent", claims)

    print()
    print("  RAR constraints the orchestrator would attach per step (not yet")
    print("  embedded in the real token -- see README):")
    for s in STEPS:
        rar = [{
            "type": "vault:path_access",
            "path": f"secret/data/{s['path']}",
            "capabilities": [s["capability"]],
        }]
        print(f"    '{s['step']}' -> {json.dumps(rar)}")

    results = [
        fetch_secret(
            VAULT_ADDR, token, s["path"],
            note=f"({s['step']} -- intended RAR: capabilities=[{s['capability']}])",
        )
        for s in STEPS
    ]

    scenarios = [
        ("staging/db-creds", "ALLOWED (ceiling allows, RAR would allow)"),
        ("staging/api-keys", "DENIED (ceiling blocks -- only db-creds allowed)"),
        ("prod/db-creds", "DENIED (ceiling denies prod, RAR can't override)"),
    ]
    results += [
        fetch_secret(VAULT_ADDR, token, path, note=f"(expected: {expect})")
        for path, expect in scenarios
    ]

    print_results(results)

    print("Ceiling vs RAR interaction shown above.")

    print("Key differences:")
    print("  CEILING: set by admin at registration time, static, broad boundary")
    print("  RAR:     set by orchestrator per request, dynamic, narrow scope")
    print("  Together: ceiling = the fence around the yard, RAR = the leash")
    print("  for this walk. Both must permit; RAR can't exceed ceiling.")
    print()
    print("See the per-request breakdowns above for what actually happened")
    print("on this run -- derived from Vault's own server logs, not assumed.")
    print()


if __name__ == "__main__":
    main()
