"""Pure policy evaluation. No AWS calls, so every rule here is unit testable.

Violation tiers
  critical : Allow with Action "*" (or NotAction) on Resource "*"  -> deny all
  high     : Allow with a service wide wildcard (rds:*) on Resource "*" -> targeted deny
  trust    : wildcard or external principal in a role trust policy -> deny all

Conditions are deliberately ignored. A statement that is broad but conditioned is
still flagged, because a trivial condition is the easiest way to disguise a grant.
Legitimate broad grants go through the authorized actor list, not through the rules.
"""

import re

CRITICAL = "critical"
HIGH = "high"
DENY_ALL = "deny_all"
DENY_TARGETED = "deny_targeted"

_RANK = {None: 0, HIGH: 1, CRITICAL: 2}

# Actions that move data out, or make it shareable. Maintained by hand.
# A service wildcard on a service that is not listed falls back to denying service:*.
EXFIL_ACTIONS = {
    "rds": [
        "rds:CopyDBClusterSnapshot",
        "rds:CopyDBSnapshot",
        "rds:CreateDBClusterSnapshot",
        "rds:CreateDBSnapshot",
        "rds:ModifyDBClusterSnapshotAttribute",
        "rds:ModifyDBSnapshotAttribute",
        "rds:StartExportTask",
    ],
    "ec2": [
        "ec2:CopySnapshot",
        "ec2:CreateImage",
        "ec2:CreateSnapshot",
        "ec2:CreateSnapshots",
        "ec2:ModifyImageAttribute",
        "ec2:ModifySnapshotAttribute",
    ],
    "s3": [
        "s3:DeleteBucketPolicy",
        "s3:PutBucketAcl",
        "s3:PutBucketPolicy",
        "s3:PutBucketPublicAccessBlock",
        "s3:PutObjectAcl",
    ],
}

_SERVICE_WILDCARD = re.compile(r"^[A-Za-z0-9-]+:\*$")
_ARN_ACCOUNT = re.compile(r"^arn:aws[a-z-]*:iam::(\d{12}):")


def _as_list(value):
    if value is None:
        return []
    return value if isinstance(value, list) else [value]


def _statements(doc):
    if not isinstance(doc, dict):
        return []
    return [s for s in _as_list(doc.get("Statement")) if isinstance(s, dict)]


def _finding(tier, response, reason, services=None):
    return {"tier": tier, "response": response, "reason": reason, "services": services or []}


def evaluate_policy_document(doc):
    """Return findings for one permissions policy document."""
    findings = []
    for index, statement in enumerate(_statements(doc)):
        if statement.get("Effect") != "Allow":
            continue
        resources = _as_list(statement.get("Resource"))
        if "*" not in resources and "NotResource" not in statement:
            continue
        if "NotAction" in statement:
            findings.append(
                _finding(CRITICAL, DENY_ALL, f"statement {index}: Allow with NotAction on all resources")
            )
            continue
        actions = [a for a in _as_list(statement.get("Action")) if isinstance(a, str)]
        if any(a in ("*", "*:*") for a in actions):
            findings.append(_finding(CRITICAL, DENY_ALL, f'statement {index}: Allow "*" on all resources'))
            continue
        services = sorted({a.split(":", 1)[0].lower() for a in actions if _SERVICE_WILDCARD.match(a)})
        if services:
            findings.append(
                _finding(
                    HIGH,
                    DENY_TARGETED,
                    f"statement {index}: service wide wildcard on all resources ({', '.join(services)})",
                    services,
                )
            )
    return findings


def _account_of(principal):
    if principal.isdigit() and len(principal) == 12:
        return principal
    match = _ARN_ACCOUNT.match(principal)
    return match.group(1) if match else None


def evaluate_trust_policy(doc, own_account_id, trusted_account_ids=()):
    """Return findings for a role trust (assume role) policy document."""
    trusted = {own_account_id, *trusted_account_ids}
    findings = []
    for index, statement in enumerate(_statements(doc)):
        if statement.get("Effect") != "Allow":
            continue
        principal = statement.get("Principal")
        conditioned = bool(statement.get("Condition"))
        values = []
        if principal == "*":
            values = [("AWS", "*")]
        elif isinstance(principal, dict):
            values = [(kind, v) for kind, raw in principal.items() for v in _as_list(raw)]
        for kind, value in values:
            if kind != "AWS" or not isinstance(value, str):
                continue
            if value == "*":
                if conditioned:
                    findings.append(
                        _finding(HIGH, DENY_ALL, f"trust statement {index}: wildcard principal limited only by conditions")
                    )
                else:
                    findings.append(
                        _finding(CRITICAL, DENY_ALL, f"trust statement {index}: any AWS principal can assume this role")
                    )
                continue
            account = _account_of(value)
            if account and account not in trusted:
                findings.append(
                    _finding(HIGH, DENY_ALL, f"trust statement {index}: external account {account} can assume this role")
                )
    return findings


def summarize(findings):
    """Collapse findings into (tier, response, services)."""
    tier, response, services = None, None, set()
    for item in findings:
        if _RANK[item["tier"]] > _RANK[tier]:
            tier = item["tier"]
        if item["response"] == DENY_ALL:
            response = DENY_ALL
        elif response != DENY_ALL:
            response = DENY_TARGETED
            services.update(item["services"])
    return tier, response, sorted(services)


def targeted_actions(services):
    actions = set()
    for service in services:
        actions.update(EXFIL_ACTIONS.get(service, [f"{service}:*"]))
    return actions


def build_deny_policy(sid, actions):
    return {
        "Version": "2012-10-17",
        "Statement": [{"Sid": sid, "Effect": "Deny", "Action": sorted(actions), "Resource": "*"}],
    }


def build_deny_all_policy():
    return {
        "Version": "2012-10-17",
        "Statement": [{"Sid": "SentinelQuarantine", "Effect": "Deny", "Action": "*", "Resource": "*"}],
    }
