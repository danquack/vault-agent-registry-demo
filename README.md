# Vault Agent Registry Demo

A demo environment showing how AI agents are meant to authenticate with HashiCorp Vault using the **Agent Registry**, **OAuth Resource Server**, **ceiling policies**, and **RAR (Rich Authorization Requests)**.

> **Status: infrastructure, entity resolution, and real on-behalf-of delegation all work; ceiling enforcement itself is blocked by an undiagnosed Vault behavior.** Both demos authenticate against [ZITADEL](https://zitadel.com) and get a genuine RFC 8693 token-exchange JWT — a real `act: {iss, sub}` claim from the IdP itself, not a hand-fabricated one. Vault partially recognizes it — it resolves the actor entity — but then denies every request with no logged reason at any verbosity, regardless of IdP. See [Known Gap: On-Behalf-Of Delegation Doesn't Resolve](#known-gap-on-behalf-of-delegation-doesnt-resolve) for the full investigation.

## Prerequisites

- Docker and Docker Compose
- A Vault Enterprise license (set `VAULT_LICENSE` env var)

## Quick Start

### 1. Set up environment

```bash
cd vault-agent-registry-demo
# create .env or export VAULT_LICENSE to your Vault Enterprise license
```

### 2. Spin everything up

```bash
docker compose up -d
```

This starts ZITADEL (db + server) and Vault, waits for both to report healthy, then automatically runs Terraform to provision everything. Terraform is a one-shot container (`terraform-provisioner`) that applies and exits; `docker compose ps` will show it as `Exited (0)` once done.

It creates:

- A ZITADEL org and project, with a project role every OBO participant is granted (needed for ZITADEL's audience-scoping, not meaningful to Vault)
- Three ZITADEL machine users: `ceiling-agent`, `rar-agent`, and a stand-in subject (`delegated-subject-test`) both agents act on behalf of — all issuing JWT-format access tokens
- A ZITADEL OIDC application with the token-exchange grant enabled, and instance-wide impersonation turned on, with both agents granted the `IAM_ADMIN_IMPERSONATOR` role — the actual RFC 8693 delegation plumbing
- Vault OAuth Resource Server profile pointing to ZITADEL
- KV v2 secrets at `staging/db-creds`, `staging/api-keys`, `prod/db-creds`
- A shared baseline ACL policy (`agent-baseline`) — required because ceiling policies only *cap* access, they don't *grant* it
- Two ceiling policies (`agent-staging-ceiling`, `agent-narrow-ceiling`)
- Three Vault identity entities with Agent Registry records, matching the three ZITADEL machine users above
- Entity aliases keyed on each ZITADEL machine user's numeric ID (what actually shows up in the JWT's `sub`/`act.sub` claims)
- Terraform also writes the provisioned client IDs/secrets to a shared file (`agent-credentials` volume) since the demo scripts run in separate containers and can't read Terraform state directly

### 3. Run the demos

```bash
docker compose up demo-ceiling demo-rar
```

Both scripts fire every secret request in their scenario, then print each result once the whole batch is done.

**Expected result vs. actual result:**

| Demo | Path | Expected | Actual |
| ---- | ---- | -------- | ------ |
| 1 (ceiling-agent) | `staging/db-creds` | `ALLOWED` (ceiling permits staging) | `DENIED` |
| 1 (ceiling-agent) | `staging/api-keys` | `ALLOWED` (ceiling permits staging) | `DENIED` |
| 1 (ceiling-agent) | `prod/db-creds` | `DENIED` (ceiling blocks prod) | `DENIED` |
| 2 (rar-agent) | `staging/db-creds` | `ALLOWED` (ceiling + RAR both permit) | `DENIED` |
| 2 (rar-agent) | `staging/api-keys` | `DENIED` (ceiling only allows db-creds) | `DENIED` |
| 2 (rar-agent) | `prod/db-creds` | `DENIED` (ceiling blocks prod) | `DENIED` |

Every request in both demos comes back `DENIED` right now, including the ones the ceiling is supposed to *allow* — that's the tell that this isn't the ceiling policy correctly restricting access, it's the entire on-behalf-of auth path failing before any policy gets evaluated. See [Known Gap](#known-gap-on-behalf-of-delegation-doesnt-resolve) for the current state of that investigation.

## What This Demo Shows

Vault's Agent Registry lets you register AI agent identities and constrain what they can do. Two enforcement layers work together:

| Layer              | Set by                                 | When    | What it does                              |
| ------------------ | --------------------------------------- | ------- | ------------------------------------------ |
| **Ceiling policy** | Admin (at registration time)           | Static  | Maximum boundary the agent can ever reach |
| **RAR**            | Orchestrator (per request, in the JWT) | Dynamic | Narrows access for this specific request  |

Both must permit the operation. RAR can never exceed the ceiling. **Note:** as of today, neither demo gets far enough to actually observe the ceiling layer — both are correctly shaped as delegated requests, but Vault denies before evaluating ceiling policy — see [Known Gap](#known-gap-on-behalf-of-delegation-doesnt-resolve).

### Demo 1: Ceiling Only

The `ceiling-agent` has a ceiling policy allowing all of `staging/*` but denying `prod/*`, acting on behalf of a stand-in subject (`delegated-subject-test`). The scenario is fixed - "deploy to staging, then run a prod health check". The job will request `staging/db-creds`, `staging/api-keys`, and `prod/db-creds`. The ceiling is *intended* to allow the first two and block the last — see [Known Gap](#known-gap-on-behalf-of-delegation-doesnt-resolve) for why every request is currently denied instead.

### Demo 2: Ceiling + RAR

The `rar-agent` has a narrow ceiling (only `staging/db-creds`) AND requires RAR on every request, also acting on behalf of the same stand-in subject. The orchestrator would mint JWTs scoped to exactly one path per step. Intended to show how ceiling + RAR interact where RAR can't exceed the ceiling — same caveat as Demo 1 applies here.

## How It Works

```
┌─────────────┐             ┌──────────┐     ┌─────────────────────┐
│  ZITADEL    │  3 requests │  Agent   │────>│   Vault             │
│  (OAuth IdP)│<───────────>│ (Python  │Bearer│                     │
│             │  real RFC   │  script) │token │  OAuth RS validates │
└─────────────┘  8693       └──────────┘     │  Registry checks    │
                 exchange                    │  Ceiling enforces   │
                                              │  RAR narrows        │
                                              └─────────────────────┘
```


1. Agent gets a JWT from ZITADEL via a real RFC 8693 token exchange -- three round-trips: a `client_credentials` token for the stand-in subject, a `client_credentials` token for the agent (the actor), then an exchange call presenting both, requesting a JWT back. The result has top-level `sub` = the subject, `act.sub` = the agent -- genuine IdP-issued delegation, not a fabricated claim (see `scripts/lib.py`'s `get_obo_token`).
2. Agent sends Vault API request with `Authorization: Bearer <jwt>`  no api call to vault for `/auth/login`, no Vault token
3. Vault's OAuth Resource Server validates the JWT signature via its trusted public key
4. Vault maps the JWT's claims to identity entities via entity aliases -- `sub` to the subject, `act.sub` to the agent
5. Vault checks the Agent Registry for the agent entity's ceiling policies, since this is a delegated, on-behalf-of request -- **but see [Known Gap](#known-gap-on-behalf-of-delegation-doesnt-resolve): this is where it currently breaks**
6. If RAR is required, Vault checks the `authorization_details` claim in the JWT
7. All three layers (baseline ACL + ceiling + RAR) must permit the operation

### Reading the demo output

Vault's HTTP response to a denied request is always a generic `403 permission denied`. The real reason only shows up in Vault's server logs. Rather than hide that, both scripts (`scripts/lib.py`) shell out to `docker logs vault-server` after every request and match the actual error against the steps below.

Requests all fire first; nothing prints until every request in the batch is done, then each result prints together with a marker (`OK` / `DENIED` / `ERROR`) and the real Vault error text (no paraphrasing, highlighted in the terminal) next to whichever step it stopped at. If Vault's logs don't contain any `[ERROR]` line at all for a denial, the script says so explicitly rather than guessing. Current output looks like this:

```
   1. Requesting credentials from the IdP (client_id + client_secret)
          client_id=ceiling-agent
   2. Receiving the JWT
          iss: http://zitadel:8080
          sub: 382065892881596420
          aud: ['382065892881661956']
          jti: V2_382066101002960900-at_382066101003026436
          act.sub: 382065892864819204  (on-behalf-of delegation)

DENIED
  GET secret/data/staging/db-creds
      DENIED  (403) -> ['permission denied']
      3. Presenting the JWT to Vault as a Bearer credential
      4. Vault checks the token's signature and shape (issuer, audience, jti, typ)
      5. Vault looks up which identity (entity) this token belongs to

         Vault logged nothing at all for this denial (no [ERROR] line in the server log) -- not diagnosable from logs alone.

      RESULT: DENIED -- stopped at step 5.
```

This is derived from the actual server logs on every run.

## Known Gap: On-Behalf-Of Delegation Doesn't Resolve

Per HashiCorp's docs ([native-ai-agent-support/index.mdx](https://github.com/hashicorp/web-unified-docs/blob/main/content/vault/v2.x/content/docs/concepts/native-ai-agent-support/index.mdx)): **ceiling policies are documented to restrict only delegated, "on-behalf-of" (OBO) requests.**

> "The authorization ceiling is the primary governance mechanism the Agent Registry provides. It restricts what an agent can do when it acts **on behalf of another identity** in a delegation, or on-behalf-of, flow."

> `ceiling_policies` — "List of policy names that define the agent's authorization ceiling, used to limit permissions **only in on-behalf-of requests**."

> "Vault evaluates the entity's baseline policies and, **for delegated on-behalf-of workflows**, the agent's authorization ceiling."

[audit/schema.mdx](https://github.com/hashicorp/web-unified-docs/blob/main/content/vault/v2.x/content/docs/audit/schema.mdx) documents how Vault detects a delegated request — a nested `act` claim in the JWT (RFC 8693 token-exchange convention), where `act.sub` names the *actor* (the agent) while the top-level `sub` names the *subject* being acted for:

> `actor_entity_id` — "The ID of the entity referred to by the `act.sub` claim of the JWT. Vault will only set this field if the JWT is for an on-behalf-of workflow."

A plain `client_credentials` grant doesn't produce that shape on its own. This demo went through two identity providers trying to get a real one:

- **Authentik** has no native token-exchange/delegation support at all, so getting this JWT shape out of it required hand-fabricating the claims via a custom scope-mapping expression (a Python snippet that overrides `sub` and injects `act`) — not something a real orchestrator could rely on.
- **ZITADEL** (what the demo uses now) implements genuine RFC 8693 token exchange, including actor delegation that produces a real, IdP-issued `act: {iss, sub}` claim — confirmed live: `scripts/lib.py`'s `get_obo_token` performs an actual three-step exchange (subject token → actor token → exchange call), and the resulting JWT has exactly the shape Vault's docs describe, no fabrication involved.

**With a completely genuine `act` claim in place, the request still fails** — and the investigation into why is thorough:

| Variation tried | Result |
|---|---|
| Self-referential `act.sub` == `sub` (actor acting on behalf of itself) | Entity resolution fails (`entity_id: None` in audit log), no error logged |
| Genuinely distinct subject entity, no baseline policy granting access | Same |
| Distinct subject entity **with** the same `agent-baseline` policy the agent has | Same |
| Agent Registry registration's `owner` field set to the subject's entity ID | Same |
| `jwt_type` set to `transaction_token` instead of `access_token` (a newer IETF draft spec built for actor/delegation chains) | Same -- and this token doesn't have the required `txn`/`may_act`/`rctx` shape a real Transaction Token needs, so this is likely the wrong direction rather than a fix |
| `act.sub` with an added `act.iss` field | Same |
| Switching from a hand-fabricated `act` claim (Authentik) to a real one from an IdP's own RFC 8693 implementation (ZITADEL) | Same -- identical denial, identical single debug line, on a completely different IdP |
| Every relevant Vault logger (`core`, `identity`, `policy`, `agent_registry`, `system`) set to `trace` | Only ever logs one line, `[DEBUG] core: building separate ACL for actor entity: entity_id=<correct agent entity id>` -- confirming Vault *does* resolve the actor -- then nothing further, at any verbosity, before the request is denied |

The IdP-swap result is the most conclusive data point: identical Vault behavior with a completely different token issuer and a completely genuine `act` claim rules out anything specific to Authentik's fabricated claim, or to any particular IdP's JWT quirks. Vault correctly resolves the actor entity (the debug line proves it) but the request is still denied with zero diagnostic trail past that point, regardless of the subject's policies, the registration's `owner` field, the JWT claim shape, or which IdP issued the token. This looks like an incomplete OBO implementation in this particular `vault-enterprise:latest` build, or a requirement not covered anywhere in the public docs. Confirming or fixing it further would need either HashiCorp's internal implementation docs or source access to the Enterprise-only code path, neither available while writing this up.

RAR (`authorization_details`) has no equivalent delegation caveat anywhere in the docs — it appears to apply to any OAuth JWT request regardless of delegation. That part of Demo 2 is unaffected by this gap; its RAR constraints remain illustrative only (see the script output for what's actually embedded in the token today vs. what an orchestrator would embed), independent of whether OBO resolution ever gets fixed.

## Key Vault Concepts

### Agent Registry vs JWT Auth

These are **different front doors** to Vault:

|                | JWT Auth                       | OAuth Resource Server                 |
| -------------- | ------------------------------- | -------------------------------------- |
| Endpoint       | `POST /auth/jwt/login`         | Any API path, Bearer token            |
| Result         | Vault token (lease, renewable) | No Vault token — direct access        |
| Roles          | Auth roles with policies       | Registry record with ceiling policies |
| Agent Registry | Not connected                  | Required for registered agents        |

### Three-Layer Authorization

```
Request arrives with Bearer JWT
         │
         ▼
  ┌─ Baseline ACL ─┐
  │ Does the entity │──── NO ──> DENIED
  │ have a policy   │
  │ allowing this?  │
  └───── YES ───────┘
         │
         ▼
  ┌── Ceiling ──────┐
  │ Does the ceiling │──── NO ──> DENIED
  │ policy permit    │
  │ this path?       │
  └───── YES ────────┘
         │
         ▼
  ┌──── RAR ────────┐
  │ Does the JWT's   │──── NO ──> DENIED
  │ authorization_   │
  │ details allow    │
  │ this operation?  │
  └───── YES ────────┘
         │
         ▼
      ALLOWED
```

### Ceiling Policy Example

```hcl
# Agent can read staging, never touch prod
path "secret/data/staging/*" {
  capabilities = ["read", "list"]
}
path "secret/data/prod/*" {
  capabilities = ["deny"]
}
```

### RAR Constraint Example (in JWT)

```json
{
  "authorization_details": [{
    "type": "vault:path_access",
    "path": "secret/data/staging/db-creds",
    "capabilities": ["read"]
  }]
}
```

## Cleanup

```bash
docker compose down -v
rm -f terraform/terraform.tfstate terraform/terraform.tfstate.backup
```
