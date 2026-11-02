import json

import pytest

from sentinel_common import alerts

SECRET_ARN = "arn:aws:secretsmanager:us-east-1:111122223333:secret:sentinel/slack-webhook-AbCdEf"
GOOD_URL = "https://hooks.slack.com/services/T000/B000/XXXX"


class FakeSecrets:
    def __init__(self, values):
        # Each entry is either a SecretString or an exception to raise.
        self.values, self.calls = list(values), 0

    def get_secret_value(self, SecretId):
        self.calls += 1
        value = self.values.pop(0) if len(self.values) > 1 else self.values[0]
        if isinstance(value, Exception):
            raise value
        return {"SecretString": value}


class FakeSns:
    def __init__(self, fail=False):
        self.fail, self.published = fail, []

    def publish(self, **kwargs):
        if self.fail:
            raise RuntimeError("sns down")
        self.published.append(kwargs)


@pytest.fixture(autouse=True)
def reset_cache(monkeypatch):
    monkeypatch.setitem(alerts._webhook_cache, "loaded", False)
    monkeypatch.setitem(alerts._webhook_cache, "url", None)
    monkeypatch.setenv("SLACK_SECRET_ARN", SECRET_ARN)


def use_secrets(monkeypatch, fake):
    monkeypatch.setattr(alerts, "_secrets_client", lambda: fake)
    return fake


def test_valid_webhook_is_cached(monkeypatch):
    fake = use_secrets(monkeypatch, FakeSecrets([json.dumps({"webhook_url": GOOD_URL})]))
    assert alerts.get_webhook_url() == GOOD_URL
    assert alerts.get_webhook_url() == GOOD_URL
    assert fake.calls == 1


def test_unpopulated_secret_is_retried_on_next_alert(monkeypatch):
    # First call: the secret exists but has no value yet. Second call: an operator has set it.
    fake = use_secrets(monkeypatch, FakeSecrets([RuntimeError("ResourceNotFound"), json.dumps({"webhook_url": GOOD_URL})]))
    assert alerts.get_webhook_url() is None
    assert alerts.get_webhook_url() == GOOD_URL
    assert fake.calls == 2


def test_non_slack_url_is_rejected(monkeypatch):
    use_secrets(monkeypatch, FakeSecrets([json.dumps({"webhook_url": "https://attacker.example/collect"})]))
    assert alerts.get_webhook_url() is None


def test_no_secret_configured_returns_none(monkeypatch):
    monkeypatch.delenv("SLACK_SECRET_ARN")
    assert alerts.get_webhook_url() is None


def test_send_alert_publishes_to_sns_and_slack(monkeypatch):
    sns, posted = FakeSns(), []
    monkeypatch.setenv("SNS_TOPIC_ARN", "arn:aws:sns:us-east-1:111122223333:sentinel-alerts")
    monkeypatch.setattr(alerts, "_sns_client", lambda: sns)
    use_secrets(monkeypatch, FakeSecrets([json.dumps({"webhook_url": GOOD_URL})]))
    monkeypatch.setattr(alerts, "_post_slack", lambda url, text: posted.append((url, text)))

    alerts.send_alert("s3-public-access", "critical", "Bucket secured", {"bucket": "aether-reports"})

    assert sns.published[0]["Subject"] == "[CRITICAL] Bucket secured"
    assert json.loads(sns.published[0]["Message"])["bucket"] == "aether-reports"
    assert posted[0][0] == GOOD_URL


def test_send_alert_never_raises_and_counts_failure(monkeypatch):
    metrics = []
    monkeypatch.setenv("SNS_TOPIC_ARN", "arn:aws:sns:us-east-1:111122223333:sentinel-alerts")
    monkeypatch.setattr(alerts, "_sns_client", lambda: FakeSns(fail=True))
    monkeypatch.delenv("SLACK_SECRET_ARN")
    monkeypatch.setattr(alerts.slog, "emit_metric", lambda control, name, *a: metrics.append(name))

    alerts.send_alert("iam-quarantine", "critical", "x", {})

    assert metrics == ["AlertFailed"]
