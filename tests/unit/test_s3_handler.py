import pytest
from botocore.exceptions import ClientError

from s3_public_access import handler

OWN_ROLE = "arn:aws:iam::111122223333:role/sentinel-s3-public-access-role"
ALL_ON = {flag: True for flag in handler.BPA_FLAGS}
PUBLIC_GRANT = {"Grantee": {"URI": "http://acs.amazonaws.com/groups/global/AllUsers"}, "Permission": "READ"}


def err(code, op="op"):
    return ClientError({"Error": {"Code": code}}, op)


class FakeS3:
    def __init__(self, bpa=None, tags=None, policy_public=False, grants=None, missing=False):
        self.bpa, self.tags = bpa, dict(tags or {})
        self.policy_public, self.grants, self.missing = policy_public, grants or [], missing
        self.put_bpa, self.put_tags = [], []

    def _check(self):
        if self.missing:
            raise err("NoSuchBucket")

    def get_bucket_tagging(self, Bucket):
        self._check()
        if not self.tags:
            raise err("NoSuchTagSet")
        return {"TagSet": [{"Key": k, "Value": v} for k, v in self.tags.items()]}

    def get_public_access_block(self, Bucket):
        if self.bpa is None:
            raise err("NoSuchPublicAccessBlockConfiguration")
        return {"PublicAccessBlockConfiguration": self.bpa}

    def get_bucket_policy_status(self, Bucket):
        return {"PolicyStatus": {"IsPublic": self.policy_public}}

    def get_bucket_acl(self, Bucket):
        return {"Grants": self.grants}

    def put_public_access_block(self, Bucket, PublicAccessBlockConfiguration):
        self.put_bpa.append(PublicAccessBlockConfiguration)
        self.bpa = PublicAccessBlockConfiguration

    def put_bucket_tagging(self, Bucket, Tagging):
        self.put_tags.append({t["Key"]: t["Value"] for t in Tagging["TagSet"]})


@pytest.fixture
def alerts(monkeypatch):
    sent = []
    monkeypatch.setattr(handler.alerts, "send_alert", lambda control, severity, title, fields: sent.append((severity, title, fields)))
    monkeypatch.setenv("OWN_ROLE_ARN", OWN_ROLE)
    return sent


def run(monkeypatch, s3, event_name="PutBucketPolicy", actor="arn:aws:iam::111122223333:user/mallory", **extra):
    monkeypatch.setattr(handler, "get_s3", lambda: s3)
    detail = {"eventName": event_name, "eventID": "evt-9", "eventTime": "2026-11-01T12:00:00Z",
              "sourceIPAddress": "203.0.113.9", "userIdentity": {"type": "IAMUser", "arn": actor},
              "requestParameters": {"bucketName": "aether-reports"}, **extra}
    return handler.lambda_handler({"detail": detail}, None)


def test_public_bucket_is_secured_critical(monkeypatch, alerts):
    s3 = FakeS3(bpa={"BlockPublicAcls": False, "IgnorePublicAcls": False, "BlockPublicPolicy": False, "RestrictPublicBuckets": False},
                policy_public=True)
    result = run(monkeypatch, s3)
    assert result == {"bucket": "aether-reports", "status": "secured", "severity": "critical"}
    assert s3.put_bpa == [ALL_ON]
    assert s3.put_tags[0]["sentinel:quarantined"] == "true"
    assert alerts[0][0] == "critical" and alerts[0][2]["actor"].endswith("mallory")


def test_public_acl_counts_as_exposed(monkeypatch, alerts):
    s3 = FakeS3(bpa=None, grants=[PUBLIC_GRANT])
    assert run(monkeypatch, s3, event_name="PutBucketAcl")["severity"] == "critical"


@pytest.fixture
def metrics(monkeypatch):
    emitted = []
    monkeypatch.setattr(handler.slog, "emit_metric", lambda control, name, value=1, unit="Count": emitted.append(name))
    return emitted


# CloudTrail records the bucket level DeletePublicAccessBlock API as DeleteBucketPublicAccessBlock.
@pytest.mark.parametrize("event_name", ["DeleteBucketPublicAccessBlock", "DeletePublicAccessBlock"])
def test_missing_block_without_exposure_is_medium(monkeypatch, alerts, event_name):
    s3 = FakeS3(bpa=None)
    assert run(monkeypatch, s3, event_name=event_name)["severity"] == "medium"
    assert s3.put_bpa == [ALL_ON]


def test_existing_tags_are_preserved_and_aws_tags_dropped(monkeypatch, alerts):
    s3 = FakeS3(bpa=None, tags={"team": "payments", "aws:cloudformation:stack-name": "x"})
    run(monkeypatch, s3)
    assert s3.put_tags[0]["team"] == "payments"
    assert "aws:cloudformation:stack-name" not in s3.put_tags[0]


def test_compliant_bucket_needs_no_action(monkeypatch, alerts):
    s3 = FakeS3(bpa=ALL_ON)
    assert run(monkeypatch, s3)["status"] == "compliant"
    assert not s3.put_bpa and not alerts


def test_exempt_bucket_is_skipped_but_counted(monkeypatch, alerts, metrics):
    s3 = FakeS3(bpa=None, tags={"sentinel:public-allowed": "true"})
    assert run(monkeypatch, s3)["status"] == "exempt"
    assert not s3.put_bpa
    assert metrics == ["ExemptViolation"]


def test_exempt_bucket_that_is_compliant_emits_nothing(monkeypatch, alerts, metrics):
    s3 = FakeS3(bpa=ALL_ON, tags={"sentinel:public-allowed": "true"})
    assert run(monkeypatch, s3)["status"] == "exempt"
    assert metrics == []


def test_own_remediation_call_is_ignored(monkeypatch, alerts):
    s3 = FakeS3(bpa=None)
    assert run(monkeypatch, s3, actor=OWN_ROLE)["status"] == "ignored_self"


def test_deleted_bucket_is_handled(monkeypatch, alerts):
    assert run(monkeypatch, FakeS3(missing=True))["status"] == "bucket_gone"


def test_failure_alerts_and_raises(monkeypatch, alerts):
    s3 = FakeS3(bpa=None)

    def boom(**_):
        raise err("AccessDenied", "PutPublicAccessBlock")

    s3.put_public_access_block = boom
    with pytest.raises(ClientError):
        run(monkeypatch, s3)
    assert "FAILED" in alerts[0][1]
