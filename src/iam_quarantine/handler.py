"""IAM quarantine responder.

Trigger: CloudTrail IAM API calls routed by EventBridge (us-east-1, IAM is global).

Design notes
  * Every invocation evaluates the LIVE state of the role (trust policy, inline policies,
    attached managed policies at their default version). It does not trust the event payload
    to describe the violation. That makes it idempotent and covers policy version changes.
  * Only roles tagged sentinel:protected=true are touched. The Lambda role's IAM permissions
    carry the same tag condition, so the scope is enforced by AWS and not only by this code.
  * Response is quarantine, never revert: an inline deny is attached and the offending grant
    is left in place as evidence. Release is a manual, audited step (docs/runbook.md).
"""

import json
import os
from datetime import datetime, timezone

import boto3
from botocore.exceptions import ClientError

from iam_quarantine import policy_eval
from sentinel_common import alerts, identity, util
from sentinel_common import logging_utils as slog

CONTROL = "iam-quarantine"
PROTECT_TAG = "sentinel:protected"
QUARANTINE_TAG = "sentinel:quarantined"
TAG_RESPONSE = "sentinel:quarantine-response"
TAG_TIER = "sentinel:quarantine-tier"
TAG_TIME = "sentinel:quarantine-time"
TAG_EVENT = "sentinel:quarantine-event"
DENY_ALL_NAME = "SentinelQuarantineDenyAll"
DENY_TARGETED_NAME = "SentinelQuarantineTargeted"
QUARANTINE_POLICY_NAMES = {DENY_ALL_NAME, DENY_TARGETED_NAME}

_iam = None


def get_iam():
    global _iam
    if _iam is None:
        _iam = boto3.client("iam")
    return _iam


def _paginate(function, result_key, **kwargs):
    marker = None
    while True:
        params = dict(kwargs)
        if marker:
            params["Marker"] = marker
        response = function(**params)
        yield from response.get(result_key, [])
        if response.get("IsTruncated"):
            marker = response.get("Marker")
        else:
            break


def _as_document(doc):
    if isinstance(doc, str):
        from urllib.parse import unquote

        return json.loads(unquote(doc))
    return doc or {}


def lambda_handler(event, context):
    detail = event.get("detail") or {}
    params = detail.get("requestParameters") or {}
    ctx = {
        "event_name": detail.get("eventName", ""),
        "event_id": detail.get("eventID", ""),
        "event_time": detail.get("eventTime", ""),
        "source_ip": detail.get("sourceIPAddress", ""),
        "actor": identity.normalize_actor(detail.get("userIdentity")),
    }

    if detail.get("errorCode"):
        return {"status": "ignored_failed_call"}
    if ctx["actor"] and ctx["actor"] == os.environ.get("OWN_ROLE_ARN"):
        slog.log("info", "ignored event caused by sentinel itself", control=CONTROL, **ctx)
        return {"status": "ignored_self"}

    iam = get_iam()
    results = [_handle_role(iam, name, ctx, params) for name in _target_roles(iam, ctx["event_name"], params)]
    return {"status": "processed", "results": results}


def _target_roles(iam, event_name, params):
    if event_name in ("CreatePolicyVersion", "SetDefaultPolicyVersion"):
        arn = params.get("policyArn")
        if not arn:
            return []
        return [
            item["RoleName"]
            for item in _paginate(iam.list_entities_for_policy, "PolicyRoles", PolicyArn=arn, EntityFilter="Role")
        ]
    name = params.get("roleName")
    return [name] if name else []


def _handle_role(iam, role_name, ctx, params):
    authorized = identity.is_listed(ctx["actor"], util.env_list("AUTHORIZED_ACTOR_ARNS"))
    releaser = identity.is_listed(ctx["actor"], util.env_list("RELEASE_PRINCIPAL_ARNS"))

    protection_removed = ctx["event_name"] == "UntagRole" and PROTECT_TAG in (params.get("tagKeys") or [])

    # A release principal taking a role out of scope is allowed, but it must leave a record.
    if protection_removed and releaser:
        slog.emit_metric(CONTROL, "QuarantineReleased")
        slog.log("info", "protection removed by release principal", control=CONTROL, role=role_name, **ctx)
        alerts.send_alert(
            CONTROL, "info", f"Protection removed from {role_name} by release principal",
            {"role": role_name, "actor": ctx["actor"], "event_name": ctx["event_name"], "event_id": ctx["event_id"]},
        )
        return {"role": role_name, "status": "protection_released"}

    # The protection tag itself was removed. Sentinel cannot act on a role it no longer
    # covers, so the only possible response is a loud alert. CriticalViolation gives the
    # CloudWatch alarm a second, Lambda independent path to the same topic.
    if protection_removed:
        slog.emit_metric(CONTROL, "ProtectionRemoved")
        slog.emit_metric(CONTROL, "CriticalViolation")
        slog.log("warning", "protection tag removed", control=CONTROL, role=role_name, **ctx)
        alerts.send_alert(
            CONTROL,
            "critical",
            f"Protection tag removed from {role_name}",
            {"role": role_name, "actor": ctx["actor"], "source_ip": ctx["source_ip"],
             "event_time": ctx["event_time"], "event_id": ctx["event_id"],
             "action_taken": "alert only, role is no longer protected"},
        )
        return {"role": role_name, "status": "protection_removed_alerted"}

    try:
        role = iam.get_role(RoleName=role_name)["Role"]
    except ClientError as err:
        if err.response["Error"]["Code"] == "NoSuchEntity":
            return {"role": role_name, "status": "role_gone"}
        raise

    tags = {t["Key"]: t["Value"] for t in role.get("Tags", [])}
    if tags.get(PROTECT_TAG) != "true":
        return {"role": role_name, "status": "not_protected"}

    if _is_quarantine_tamper(ctx["event_name"], params):
        return _handle_tamper(iam, role_name, ctx, releaser)

    return _handle_drift(iam, role, ctx, authorized)


def _is_quarantine_tamper(event_name, params):
    if event_name == "DeleteRolePolicy":
        return params.get("policyName") in QUARANTINE_POLICY_NAMES
    if event_name == "UntagRole":
        return QUARANTINE_TAG in (params.get("tagKeys") or [])
    return False


def _handle_tamper(iam, role_name, ctx, releaser):
    if releaser:
        slog.emit_metric(CONTROL, "QuarantineReleased")
        slog.log("info", "quarantine released by authorized principal", control=CONTROL, role=role_name, **ctx)
        alerts.send_alert(
            CONTROL, "info", f"Quarantine change on {role_name} by release principal",
            {"role": role_name, "actor": ctx["actor"], "event_name": ctx["event_name"], "event_id": ctx["event_id"]},
        )
        return {"role": role_name, "status": "release_recorded"}

    # Unauthorized tampering is suspicious in its own right. Restore with the strictest response.
    slog.emit_metric(CONTROL, "TamperDetected")
    slog.emit_metric(CONTROL, "ViolationDetected")
    slog.emit_metric(CONTROL, "CriticalViolation")
    try:
        _apply_quarantine(iam, role_name, policy_eval.DENY_ALL, set(), policy_eval.CRITICAL, ctx)
    except ClientError as err:
        return _fail(role_name, ctx, err)
    seconds = util.seconds_since(ctx["event_time"])
    slog.emit_metric(CONTROL, "RemediationSucceeded")
    slog.emit_metric(CONTROL, "TimeToRemediateSeconds", seconds, "Seconds")
    slog.log("warning", "quarantine tamper reverted", control=CONTROL, role=role_name,
             seconds_to_remediate=seconds, **ctx)
    alerts.send_alert(
        CONTROL, "critical", f"Quarantine on {role_name} was tampered with and has been restored",
        {"role": role_name, "actor": ctx["actor"], "source_ip": ctx["source_ip"], "event_name": ctx["event_name"],
         "event_time": ctx["event_time"], "event_id": ctx["event_id"], "action_taken": "deny all re-applied"},
    )
    return {"role": role_name, "status": "tamper_restored"}


def _handle_drift(iam, role, ctx, authorized):
    role_name = role["RoleName"]
    findings = _evaluate_role(iam, role)

    if not findings:
        if ctx["event_name"] == "DeleteRolePermissionsBoundary":
            slog.emit_metric(CONTROL, "BoundaryRemoved")
            alerts.send_alert(
                CONTROL, "high", f"Permissions boundary removed from {role_name}",
                {"role": role_name, "actor": ctx["actor"], "source_ip": ctx["source_ip"],
                 "event_time": ctx["event_time"], "event_id": ctx["event_id"],
                 "action_taken": "alert only, no violating policy present"},
            )
            return {"role": role_name, "status": "boundary_removed_alerted"}
        slog.log("info", "role compliant, no action needed", control=CONTROL, role=role_name, **ctx)
        return {"role": role_name, "status": "compliant"}

    tier, response, services = policy_eval.summarize(findings)
    existing = _quarantine_policies(iam, role_name)

    if _already_covered(iam, role_name, existing, response, services):
        slog.log("info", "already quarantined, no action needed", control=CONTROL, role=role_name, **ctx)
        return {"role": role_name, "status": "already_quarantined"}

    slog.emit_metric(CONTROL, "ViolationDetected")
    if tier == policy_eval.CRITICAL:
        slog.emit_metric(CONTROL, "CriticalViolation")

    summary = {
        "role": role_name, "tier": tier, "findings": [f"{f['source']}: {f['reason']}" for f in findings],
        "actor": ctx["actor"], "source_ip": ctx["source_ip"], "event_name": ctx["event_name"],
        "event_time": ctx["event_time"], "event_id": ctx["event_id"],
    }

    if authorized:
        slog.emit_metric(CONTROL, "ExemptViolation")
        slog.log("warning", "violation by authorized actor, not quarantined", control=CONTROL, **summary)
        alerts.send_alert(CONTROL, "warning", f"Authorized actor created a violating grant on {role_name}",
                          {**summary, "action_taken": "none, actor is on the authorized list"})
        return {"role": role_name, "status": "exempt"}

    try:
        _apply_quarantine(iam, role_name, response, set(services), tier, ctx, existing)
    except ClientError as err:
        return _fail(role_name, ctx, err, summary)

    seconds = util.seconds_since(ctx["event_time"])
    slog.emit_metric(CONTROL, "RemediationSucceeded")
    slog.emit_metric(CONTROL, "TimeToRemediateSeconds", seconds, "Seconds")
    slog.log("warning", "role quarantined", control=CONTROL, response=response, seconds_to_remediate=seconds, **summary)
    alerts.send_alert(CONTROL, "critical" if tier == policy_eval.CRITICAL else "high",
                      f"Role {role_name} quarantined",
                      {**summary, "action_taken": response, "seconds_to_remediate": round(seconds, 1)})
    return {"role": role_name, "status": "quarantined", "response": response, "tier": tier}


def _fail(role_name, ctx, err, summary=None):
    slog.emit_metric(CONTROL, "RemediationFailed")
    slog.log("error", "remediation failed", control=CONTROL, role=role_name,
             error_code=err.response["Error"]["Code"], **ctx)
    alerts.send_alert(CONTROL, "critical", f"Sentinel FAILED to quarantine {role_name}",
                      {**(summary or {"role": role_name, "event_id": ctx["event_id"]}),
                       "error_code": err.response["Error"]["Code"]})
    raise err


def _evaluate_role(iam, role):
    name = role["RoleName"]
    account = os.environ.get("OWN_ROLE_ARN", "::::").split(":")[4]
    trusted = util.env_list("TRUSTED_ACCOUNT_IDS")
    findings = []

    def add(items, source):
        for item in items:
            findings.append({**item, "source": source})

    add(policy_eval.evaluate_trust_policy(_as_document(role.get("AssumeRolePolicyDocument")), account, trusted),
        "trust-policy")
    for policy_name in _paginate(iam.list_role_policies, "PolicyNames", RoleName=name):
        if policy_name in QUARANTINE_POLICY_NAMES:
            continue
        doc = iam.get_role_policy(RoleName=name, PolicyName=policy_name)["PolicyDocument"]
        add(policy_eval.evaluate_policy_document(_as_document(doc)), f"inline:{policy_name}")
    for attached in _paginate(iam.list_attached_role_policies, "AttachedPolicies", RoleName=name):
        arn = attached["PolicyArn"]
        version = iam.get_policy(PolicyArn=arn)["Policy"]["DefaultVersionId"]
        doc = iam.get_policy_version(PolicyArn=arn, VersionId=version)["PolicyVersion"]["Document"]
        add(policy_eval.evaluate_policy_document(_as_document(doc)), f"managed:{arn}")
    return findings


def _quarantine_policies(iam, role_name):
    names = set(_paginate(iam.list_role_policies, "PolicyNames", RoleName=role_name))
    return names & QUARANTINE_POLICY_NAMES


def _denied_actions(iam, role_name, policy_name):
    doc = _as_document(iam.get_role_policy(RoleName=role_name, PolicyName=policy_name)["PolicyDocument"])
    actions = set()
    for statement in doc.get("Statement", []):
        raw = statement.get("Action", [])
        actions.update(raw if isinstance(raw, list) else [raw])
    return actions


def _already_covered(iam, role_name, existing, response, services):
    if DENY_ALL_NAME in existing:
        return True
    if response == policy_eval.DENY_TARGETED and DENY_TARGETED_NAME in existing:
        needed = policy_eval.targeted_actions(services)
        return needed <= _denied_actions(iam, role_name, DENY_TARGETED_NAME)
    return False


def _apply_quarantine(iam, role_name, response, services, tier, ctx, existing=None):
    if response == policy_eval.DENY_ALL:
        name, document = DENY_ALL_NAME, policy_eval.build_deny_all_policy()
    else:
        actions = policy_eval.targeted_actions(services)
        if existing and DENY_TARGETED_NAME in existing:
            actions |= _denied_actions(iam, role_name, DENY_TARGETED_NAME)
        name = DENY_TARGETED_NAME
        document = policy_eval.build_deny_policy("SentinelQuarantineTargeted", actions)

    iam.put_role_policy(RoleName=role_name, PolicyName=name, PolicyDocument=json.dumps(document))
    iam.tag_role(
        RoleName=role_name,
        Tags=[
            {"Key": QUARANTINE_TAG, "Value": "true"},
            {"Key": TAG_RESPONSE, "Value": response},
            {"Key": TAG_TIER, "Value": tier},
            {"Key": TAG_TIME, "Value": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")},
            {"Key": TAG_EVENT, "Value": ctx["event_id"] or "unknown"},
        ],
    )
