"""S3 public access responder.

Trigger: bucket level CloudTrail events routed by EventBridge.

A bucket is compliant when all four Block Public Access flags are on. Remediation turns
them on, which neutralizes public policies and ACLs without deleting them (evidence is kept),
and tags the bucket sentinel:quarantined=true. Severity is critical only when the bucket
was actually exposed (public policy or public ACL grant), otherwise it is a hardening gap.

Buckets that are meant to be public (a website, say) opt out with sentinel:public-allowed=true.
"""

import os
from datetime import datetime, timezone

import boto3
from botocore.exceptions import ClientError

from sentinel_common import alerts, identity, util
from sentinel_common import logging_utils as slog

CONTROL = "s3-public-access"
QUARANTINE_TAG = "sentinel:quarantined"
EXEMPT_TAG = "sentinel:public-allowed"
BPA_FLAGS = ("BlockPublicAcls", "IgnorePublicAcls", "BlockPublicPolicy", "RestrictPublicBuckets")
PUBLIC_GROUPS = {
    "http://acs.amazonaws.com/groups/global/AllUsers",
    "http://acs.amazonaws.com/groups/global/AuthenticatedUsers",
}

_s3 = None


def get_s3():
    global _s3
    if _s3 is None:
        _s3 = boto3.client("s3")
    return _s3


def _code(err):
    return err.response["Error"]["Code"]


def inspect_bucket(s3, bucket):
    try:
        tags = {t["Key"]: t["Value"] for t in s3.get_bucket_tagging(Bucket=bucket)["TagSet"]}
    except ClientError as err:
        if _code(err) != "NoSuchTagSet":
            raise
        tags = {}
    try:
        bpa = s3.get_public_access_block(Bucket=bucket)["PublicAccessBlockConfiguration"]
    except ClientError as err:
        if _code(err) != "NoSuchPublicAccessBlockConfiguration":
            raise
        bpa = {}
    try:
        policy_public = bool(s3.get_bucket_policy_status(Bucket=bucket)["PolicyStatus"]["IsPublic"])
    except ClientError as err:
        if _code(err) != "NoSuchBucketPolicy":
            raise
        policy_public = False
    grants = s3.get_bucket_acl(Bucket=bucket).get("Grants", [])
    acl_public = any(g.get("Grantee", {}).get("URI") in PUBLIC_GROUPS for g in grants)
    missing = [flag for flag in BPA_FLAGS if not bpa.get(flag, False)]
    return {"tags": tags, "missing_flags": missing, "policy_public": policy_public, "acl_public": acl_public}


def lambda_handler(event, context):
    detail = event.get("detail") or {}
    bucket = (detail.get("requestParameters") or {}).get("bucketName")
    ctx = {
        "event_name": detail.get("eventName", ""),
        "event_id": detail.get("eventID", ""),
        "event_time": detail.get("eventTime", ""),
        "source_ip": detail.get("sourceIPAddress", ""),
        "actor": identity.normalize_actor(detail.get("userIdentity")),
    }
    if detail.get("errorCode") or not bucket:
        return {"status": "ignored"}
    if ctx["actor"] and ctx["actor"] == os.environ.get("OWN_ROLE_ARN"):
        slog.log("info", "ignored event caused by sentinel itself", control=CONTROL, bucket=bucket, **ctx)
        return {"status": "ignored_self"}

    s3 = get_s3()
    try:
        state = inspect_bucket(s3, bucket)
    except ClientError as err:
        if _code(err) == "NoSuchBucket":
            return {"bucket": bucket, "status": "bucket_gone"}
        raise

    if state["tags"].get(EXEMPT_TAG) == "true":
        # Record the exemption only when it actually let something through, so the
        # ExemptViolation trend shows real exposure that was allowed by design.
        if state["missing_flags"]:
            slog.emit_metric(CONTROL, "ExemptViolation")
            slog.log("warning", "exempt bucket is missing block public access", control=CONTROL, bucket=bucket,
                     missing_block_public_access_flags=state["missing_flags"], **ctx)
        else:
            slog.log("info", "bucket exempt from public access control", control=CONTROL, bucket=bucket, **ctx)
        return {"bucket": bucket, "status": "exempt"}
    if not state["missing_flags"]:
        slog.log("info", "bucket compliant, no action needed", control=CONTROL, bucket=bucket, **ctx)
        return {"bucket": bucket, "status": "compliant"}

    exposed = state["policy_public"] or state["acl_public"]
    severity = "critical" if exposed else "medium"
    slog.emit_metric(CONTROL, "ViolationDetected")
    if exposed:
        slog.emit_metric(CONTROL, "CriticalViolation")

    summary = {
        "bucket": bucket, "severity": severity, "exposed": exposed,
        "public_policy": state["policy_public"], "public_acl": state["acl_public"],
        "missing_block_public_access_flags": state["missing_flags"],
        "actor": ctx["actor"], "source_ip": ctx["source_ip"], "event_name": ctx["event_name"],
        "event_time": ctx["event_time"], "event_id": ctx["event_id"],
    }

    try:
        s3.put_public_access_block(
            Bucket=bucket,
            PublicAccessBlockConfiguration={flag: True for flag in BPA_FLAGS},
        )
        merged = {k: v for k, v in state["tags"].items() if not k.startswith("aws:")}
        merged.update(
            {
                QUARANTINE_TAG: "true",
                "sentinel:quarantine-time": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
                "sentinel:quarantine-event": ctx["event_id"] or "unknown",
            }
        )
        s3.put_bucket_tagging(
            Bucket=bucket, Tagging={"TagSet": [{"Key": k, "Value": v} for k, v in merged.items()]}
        )
    except ClientError as err:
        slog.emit_metric(CONTROL, "RemediationFailed")
        slog.log("error", "remediation failed", control=CONTROL, bucket=bucket, error_code=_code(err), **ctx)
        alerts.send_alert(CONTROL, "critical", f"Sentinel FAILED to secure bucket {bucket}",
                          {**summary, "error_code": _code(err)})
        raise

    seconds = util.seconds_since(ctx["event_time"])
    slog.emit_metric(CONTROL, "RemediationSucceeded")
    slog.emit_metric(CONTROL, "TimeToRemediateSeconds", seconds, "Seconds")
    slog.log("warning", "bucket secured", control=CONTROL, seconds_to_remediate=seconds, **summary)
    alerts.send_alert(CONTROL, severity, f"Bucket {bucket} secured",
                      {**summary, "action_taken": "block public access enabled, bucket tagged",
                       "seconds_to_remediate": round(seconds, 1)})
    return {"bucket": bucket, "status": "secured", "severity": severity}
