"""Alert delivery: SNS first, Slack as a best-effort second channel.

The Slack webhook lives in Secrets Manager as JSON: {"webhook_url": "https://hooks.slack.com/..."}.
It is never placed in environment variables, Terraform state, or logs.
"""

import json
import os
import urllib.request

import boto3

from sentinel_common import logging_utils as slog

_SLACK_PREFIX = "https://hooks.slack.com/"
_sns = None
_secrets = None
_webhook_cache = {"loaded": False, "url": None}


def _sns_client():
    global _sns
    if _sns is None:
        _sns = boto3.client("sns")
    return _sns


def _secrets_client():
    global _secrets
    if _secrets is None:
        _secrets = boto3.client("secretsmanager")
    return _secrets


def get_webhook_url():
    """Fetch and cache the Slack webhook. Returns None if it is not configured.

    Only a valid URL is cached. A missing or malformed secret is retried on the next alert,
    so populating the secret after deploy takes effect without waiting for a cold start.
    Alerts are rare, so the extra GetSecretValue call on the unhappy path is cheap.
    """
    if _webhook_cache["loaded"]:
        return _webhook_cache["url"]
    secret_arn = os.environ.get("SLACK_SECRET_ARN")
    if not secret_arn:
        return None
    try:
        raw = _secrets_client().get_secret_value(SecretId=secret_arn)["SecretString"]
        url = json.loads(raw).get("webhook_url", "")
    except Exception as err:  # secret not populated yet, no permission, bad JSON
        slog.log("warning", "slack webhook unavailable", error_type=type(err).__name__)
        return None
    if not url.startswith(_SLACK_PREFIX):
        slog.log("warning", "slack webhook ignored, unexpected URL prefix")
        return None
    _webhook_cache["url"] = url
    _webhook_cache["loaded"] = True
    return url


def _post_slack(url, text):
    request = urllib.request.Request(
        url,
        data=json.dumps({"text": text}).encode("utf-8"),
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    with urllib.request.urlopen(request, timeout=5) as response:  # noqa: S310 (prefix checked)
        response.read()


def send_alert(control, severity, title, fields):
    """Publish an alert. Never raises, so an alerting problem cannot mask a remediation."""
    subject = f"[{severity.upper()}] {title}"[:100]
    body = json.dumps({"control": control, "severity": severity, "title": title, **fields}, indent=2, default=str)

    topic_arn = os.environ.get("SNS_TOPIC_ARN")
    if topic_arn:
        try:
            _sns_client().publish(TopicArn=topic_arn, Subject=subject, Message=body)
        except Exception as err:
            slog.log("error", "sns publish failed", control=control, error_type=type(err).__name__)
            slog.emit_metric(control, "AlertFailed")

    url = get_webhook_url()
    if url:
        lines = [f"*{subject}*"] + [f"- {key}: {value}" for key, value in fields.items() if key != "findings"]
        try:
            _post_slack(url, "\n".join(lines))
        except Exception as err:
            slog.log("error", "slack post failed", control=control, error_type=type(err).__name__)
            slog.emit_metric(control, "AlertFailed")
