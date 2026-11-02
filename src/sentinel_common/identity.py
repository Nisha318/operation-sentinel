"""Work out who performed an API call, in a form that is safe to compare."""

import re

_ASSUMED_ROLE = re.compile(r"^arn:(aws[a-z-]*):sts::(\d{12}):assumed-role/([^/]+)/[^/]+$")


def normalize_actor(user_identity):
    """Return a stable ARN for the principal behind a CloudTrail userIdentity block.

    Assumed role sessions are collapsed to the ARN of the role that issued them, so
    a list of allowed actors can name roles instead of individual session ARNs.
    """
    identity = user_identity or {}
    if identity.get("type") == "AssumedRole":
        issuer = (identity.get("sessionContext") or {}).get("sessionIssuer") or {}
        if issuer.get("arn"):
            return issuer["arn"]
        match = _ASSUMED_ROLE.match(identity.get("arn", ""))
        if match:
            partition, account, role = match.groups()
            return f"arn:{partition}:iam::{account}:role/{role}"
    return identity.get("arn", "")


def is_listed(actor, allowed):
    """Exact match only. No wildcards, no prefix matching."""
    return bool(actor) and actor in set(allowed)
