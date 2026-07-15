"""
Shared helpers for the ceiling/RAR demo scripts.

No AI model is involved anywhere in this file or the two demo scripts --
the security behavior being demonstrated (or, currently, failing to be
demonstrated) is entirely a property of Vault's OAuth Resource Server.
Which secret paths get requested is a fixed, hardcoded scenario so every
run is identical and reproducible.

Requests are made immediately, but nothing about the result prints until
print_results() is called at the end -- see demo_ceiling.py / demo_rar.py.
"""

import base64
import json
import subprocess

import requests

CREDENTIALS_PATH = "/agent-credentials/credentials.json"


# One continuous, numbered checklist for the whole flow. Steps 1-2 happen
# once per script run (fetching the token); steps 3-7 happen once per
# secret request (presenting that same token and walking it through
# Vault's pipeline).
BOLD_RED = "\033[1;31m"
RESET = "\033[0m"

TOKEN_STEPS = [
    "Requesting credentials from the IdP (client_id + client_secret)",
    "Receiving the JWT",
]

PIPELINE_STEPS = [
    "Presenting the JWT to Vault as a Bearer credential",
    "Vault checks the token's signature and shape (issuer, audience, jti, typ)",
    "Vault looks up which identity (entity) this token belongs to",
    "Vault checks the Agent Registry + ceiling policy for that identity",
    "Vault checks RAR constraints, if the registration requires them",
]

_PIPELINE_OFFSET = len(TOKEN_STEPS)


def decode_jwt(token):
    """Decode a JWT's header and payload without verifying the signature."""
    header_b64, payload_b64, _ = token.split(".")
    header_b64 += "=" * (-len(header_b64) % 4)
    payload_b64 += "=" * (-len(payload_b64) % 4)
    header = json.loads(base64.urlsafe_b64decode(header_b64))
    payload = json.loads(base64.urlsafe_b64decode(payload_b64))
    return header, payload


def load_credentials():
    """Read the client IDs/secrets Terraform provisioned in ZITADEL --
    written to a shared volume since this script runs in a separate
    container from Terraform and can't read its state directly."""
    with open(CREDENTIALS_PATH) as f:
        return json.load(f)


def get_token(token_endpoint, client_id, client_secret, scope="profile"):
    resp = requests.post(token_endpoint, data={
        "client_id": client_id,
        "client_secret": client_secret,
        "grant_type": "client_credentials",
        "scope": scope,
    })
    resp.raise_for_status()
    return resp.json()["access_token"]


def get_obo_token(token_endpoint, creds, actor_id, actor_secret):
    """
    Get a JWT shaped as a genuine RFC 8693 on-behalf-of delegation: the
    stand-in subject (delegated_subject) is the token's top-level sub,
    and the calling agent (actor_id/actor_secret) becomes its act.sub via
    ZITADEL's real token-exchange grant -- no hand-fabricated claims.

    Three real HTTP round-trips, matching what a token-exchange-aware
    orchestrator would actually do:
      1. client_credentials for the subject
      2. client_credentials for the actor (the agent)
      3. token-exchange, presenting both, requesting a JWT back
    Both client_credentials calls request the project's audience scope --
    without it ZITADEL's exchange step rejects the subject/actor tokens
    as invalid, since the exchanging app can't otherwise treat them as
    active (see terraform/zitadel.tf).
    """
    audience_scope = f"openid profile urn:zitadel:iam:org:project:id:{creds['project_id']}:aud"

    subject_token = get_token(
        token_endpoint, creds["delegated_subject_client_id"], creds["delegated_subject_client_secret"],
        scope=audience_scope,
    )
    actor_token = get_token(token_endpoint, actor_id, actor_secret, scope=audience_scope)

    resp = requests.post(token_endpoint, data={
        "grant_type": "urn:ietf:params:oauth:grant-type:token-exchange",
        "subject_token": subject_token,
        "subject_token_type": "urn:ietf:params:oauth:token-type:access_token",
        "actor_token": actor_token,
        "actor_token_type": "urn:ietf:params:oauth:token-type:access_token",
        "requested_token_type": "urn:ietf:params:oauth:token-type:jwt",
    }, auth=(creds["exchange_client_id"], creds["exchange_client_secret"]))
    resp.raise_for_status()
    return resp.json()["access_token"]


def print_token_steps(client_id, claims):
    """Print steps 1-2 (requesting credentials, receiving the JWT)."""
    print(f"   1. {TOKEN_STEPS[0]}")
    print(f"          client_id={client_id}")
    print(f"   2. {TOKEN_STEPS[1]}")
    print(f"          iss: {claims['iss']}")
    print(f"          sub: {claims['sub']}")
    print(f"          aud: {claims.get('aud')}")
    print(f"          jti: {claims.get('jti')}")
    if "act" in claims:
        print(f"          act.sub: {claims['act'].get('sub')}  (on-behalf-of delegation)")


def _tail_container_logs(container, since_seconds):
    """Best-effort read of a container's recent stdout/stderr via the
    Docker CLI. Returns (log_text, docker_ok) -- docker_ok is False only if
    the `docker` command itself couldn't be run (not on PATH, no socket
    access, container missing); a successful call with no matching log
    lines is a different case the caller should report distinctly."""
    try:
        result = subprocess.run(
            ["docker", "logs", container, "--since", f"{since_seconds}s"],
            capture_output=True, text=True, timeout=5,
        )
        return result.stdout + result.stderr, True
    except Exception:
        return "", False


def diagnose_vault_denial(vault_container="vault-server", since_seconds=5):
    """
    Pull Vault's own server-side error for the most recent request and
    translate it into which pipeline step it actually failed at. Vault's
    HTTP response to the client is always a generic "permission denied"
    -- it never says why. Returns None if nothing recognizable was found.
    """
    log_text, docker_ok = _tail_container_logs(vault_container, since_seconds)

    if "claim jti/uti is missing" in log_text:
        return {
            "stage": _PIPELINE_OFFSET + 2,
            "detail": 'Vault error: "JWT schema validation failed: claim jti/uti is missing"',
        }

    if "unsupported jwt type" in log_text:
        return {
            "stage": _PIPELINE_OFFSET + 2,
            "detail": 'Vault error: "JWT schema validation failed: unsupported jwt type"',
        }

    if "no alias found" in log_text or "error looking up entity" in log_text:
        return {
            "stage": _PIPELINE_OFFSET + 3,
            "detail": 'Vault error: "no alias found" / "error looking up entity"',
        }

    # Fall back to whatever Vault actually logged, verbatim, instead of
    # guessing at a stage -- an unrecognized error is still more useful
    # to the reader than a canned "couldn't read the logs" message.
    error_lines = [line for line in log_text.splitlines() if "[ERROR]" in line]
    if error_lines:
        return {
            "stage": _PIPELINE_OFFSET + 2,
            "detail": f"Vault error (raw, unrecognized): {error_lines[-1].split(']', 1)[-1].strip()}",
        }

    if not docker_ok:
        return {
            "stage": _PIPELINE_OFFSET + 3,
            "detail": "Couldn't read Vault's server logs to pinpoint the exact stage (is `docker` on PATH?).",
        }

    # docker ran fine and returned log text, but none of it was an [ERROR]
    # line -- Vault denied the request without logging anything about it.
    return {
        "stage": _PIPELINE_OFFSET + 3,
        "detail": "Vault logged nothing at all for this denial (no [ERROR] line in the server log) -- not diagnosable from logs alone.",
    }


def _pipeline_lines(failed_at=None, unknown=False, detail=None):
    """
    Build the lines for steps 3+ (the per-request Vault pipeline). Only
    steps that actually ran are included -- once a request is stopped,
    the steps after it never executed, so they aren't listed.
    """
    lines = []
    if unknown:
        return lines

    for offset, step in enumerate(PIPELINE_STEPS):
        i = _PIPELINE_OFFSET + 1 + offset
        lines.append(f"    {i}. {step}")
        if failed_at is not None and i == failed_at:
            if detail:
                lines.append("")
                lines.append(f"       {BOLD_RED}{detail}{RESET}")
                lines.append("")
            break  # steps after this one never ran

    if failed_at is None:
        lines.append("    RESULT: ALLOWED -- request passed every check above.")
    else:
        lines.append(f"    RESULT: DENIED -- stopped at step {failed_at}.")
    return lines


def fetch_secret(vault_addr, token, path, vault_container="vault-server", note=None):
    """
    GET a secret from Vault with a Bearer token. Makes the request right
    away but doesn't print anything -- returns a result dict for
    print_results() to render later, once every request in the batch
    is done. `note` is an optional caller-supplied context line (e.g. the
    intended RAR for this request) shown above the GET line.
    """
    lines = [note, f"GET secret/data/{path}"] if note else [f"GET secret/data/{path}"]

    try:
        resp = requests.get(
            f"{vault_addr}/v1/secret/data/{path}",
            headers={"Authorization": f"Bearer {token}"},
            timeout=10,
        )
    except requests.RequestException as e:
        lines.append(f"    COULDN'T REACH VAULT -- {e}")
        return {"path": path, "marker": "ERROR", "lines": lines}

    try:
        data = resp.json() if resp.text else {}
    except ValueError:
        data = {"errors": [resp.text[:200] or "(empty response body)"]}

    if resp.status_code == 200:
        secret = data.get("data", {}).get("data", {})
        redacted = {k: (v[:4] + "..." if isinstance(v, str) else v) for k, v in secret.items()}
        lines.append(f"    ALLOWED ({resp.status_code}) -> {json.dumps(redacted)}")
        lines += _pipeline_lines(failed_at=None)
        return {"path": path, "marker": "OK", "lines": lines}

    if resp.status_code >= 500:
        lines.append(f"    DENIED  ({resp.status_code}) -> {data.get('errors', ['?'])}")
        lines += _pipeline_lines(unknown=True)
        return {"path": path, "marker": "ERROR", "lines": lines}

    lines.append(f"    DENIED  ({resp.status_code}) -> {data.get('errors', ['?'])}")
    diagnosis = diagnose_vault_denial(vault_container)
    lines += _pipeline_lines(failed_at=diagnosis["stage"], detail=diagnosis["detail"])
    return {"path": path, "marker": "DENIED", "lines": lines}


def print_results(results):
    """Print every fetch_secret() result, in order, each headed by its
    marker (OK / DENIED / ERROR)."""
    print()
    for r in results:
        print(f"{r['marker']}")
        for line in r["lines"]:
            print(f"  {line}")
        print()
