import json

import pytest
from botocore.exceptions import ClientError

from iam_quarantine import handler

ACCOUNT = "111122223333"
OWN_ROLE = f"arn:aws:iam::{ACCOUNT}:role/sentinel-iam-quarantine-role"
DEPLOY_ROLE = f"arn:aws:iam::{ACCOUNT}:role/gha-deploy"
BREAK_GLASS = f"arn:aws:iam::{ACCOUNT}:role/break-glass"
ATTACKER = f"arn:aws:iam::{ACCOUNT}:role/compromised-ci"

ADMIN = {"Version": "2012-10-17", "Statement": [{"Effect": "Allow", "Action": "*", "Resource": "*"}]}
RDS_STAR = {"Version": "2012-10-17", "Statement": [{"Effect": "Allow", "Action": ["rds:*"], "Resource": "*"}]}
BENIGN = {"Version": "2012-10-17", "Statement": [{"Effect": "Allow", "Action": ["rds:DescribeDBInstances"], "Resource": "*"}]}
TRUST_OK = {"Statement": [{"Effect": "Allow", "Principal": {"Service": "lambda.amazonaws.com"}, "Action": "sts:AssumeRole"}]}


class FakeIam:
    def __init__(self, tags=None, inline=None, trust=None):
        self.tags = dict(tags if tags is not None else {"sentinel:protected": "true"})
        self.inline = dict(inline or {})
        self.trust = trust or TRUST_OK
        self.puts, self.tag_calls = [], []

    def get_role(self, RoleName):
        return {"Role": {"RoleName": RoleName, "AssumeRolePolicyDocument": self.trust,
                         "Tags": [{"Key": k, "Value": v} for k, v in self.tags.items()]}}

    def list_role_policies(self, RoleName, **_):
        return {"PolicyNames": sorted(self.inline), "IsTruncated": False}

    def get_role_policy(self, RoleName, PolicyName):
        return {"PolicyDocument": self.inline[PolicyName]}

    def list_attached_role_policies(self, RoleName, **_):
        return {"AttachedPolicies": [], "IsTruncated": False}

    def put_role_policy(self, RoleName, PolicyName, PolicyDocument):
        self.puts.append(PolicyName)
        self.inline[PolicyName] = json.loads(PolicyDocument)

    def tag_role(self, RoleName, Tags):
        self.tag_calls.append(Tags)
        self.tags.update({t["Key"]: t["Value"] for t in Tags})


@pytest.fixture
def env(monkeypatch):
    monkeypatch.setenv("OWN_ROLE_ARN", OWN_ROLE)
    monkeypatch.setenv("AUTHORIZED_ACTOR_ARNS", DEPLOY_ROLE)
    monkeypatch.setenv("RELEASE_PRINCIPAL_ARNS", BREAK_GLASS)
    monkeypatch.delenv("TRUSTED_ACCOUNT_IDS", raising=False)


@pytest.fixture
def alerts(monkeypatch):
    sent = []
    monkeypatch.setattr(handler.alerts, "send_alert", lambda control, severity, title, fields: sent.append((severity, title, fields)))
    return sent


def run(monkeypatch, iam, event_name="PutRolePolicy", actor=ATTACKER, params=None, **extra):
    monkeypatch.setattr(handler, "get_iam", lambda: iam)
    detail = {
        "eventName": event_name, "eventID": "evt-1", "eventTime": "2026-11-01T12:00:00Z",
        "sourceIPAddress": "203.0.113.9", "userIdentity": {"type": "IAMUser", "arn": actor},
        "requestParameters": params or {"roleName": "aether-app-reporting-role"}, **extra,
    }
    return handler.lambda_handler({"detail": detail}, None)


def test_admin_grant_gets_deny_all_and_tags(monkeypatch, env, alerts):
    iam = FakeIam(inline={"Attack": ADMIN})
    result = run(monkeypatch, iam)
    assert result["results"][0]["status"] == "quarantined"
    assert handler.DENY_ALL_NAME in iam.inline
    assert iam.tags["sentinel:quarantined"] == "true"
    assert iam.tags["sentinel:quarantine-event"] == "evt-1"
    assert alerts[0][0] == "critical"
    assert alerts[0][2]["actor"] == ATTACKER and alerts[0][2]["source_ip"] == "203.0.113.9"


def test_rds_wildcard_gets_targeted_deny_that_keeps_read_access(monkeypatch, env, alerts):
    iam = FakeIam(inline={"Attack": RDS_STAR})
    run(monkeypatch, iam)
    assert handler.DENY_TARGETED_NAME in iam.inline and handler.DENY_ALL_NAME not in iam.inline
    denied = iam.inline[handler.DENY_TARGETED_NAME]["Statement"][0]["Action"]
    assert "rds:ModifyDBSnapshotAttribute" in denied and "rds:DescribeDBInstances" not in denied
    assert alerts[0][0] == "high"


def test_second_invocation_is_idempotent(monkeypatch, env, alerts):
    iam = FakeIam(inline={"Attack": ADMIN})
    run(monkeypatch, iam)
    puts_after_first = len(iam.puts)
    again = run(monkeypatch, iam)
    assert again["results"][0]["status"] == "already_quarantined"
    assert len(iam.puts) == puts_after_first and len(alerts) == 1


def test_escalation_from_targeted_to_deny_all(monkeypatch, env, alerts):
    iam = FakeIam(inline={"Attack": RDS_STAR})
    run(monkeypatch, iam)
    iam.inline["Attack2"] = ADMIN
    run(monkeypatch, iam)
    assert handler.DENY_ALL_NAME in iam.inline


def test_benign_change_is_left_alone(monkeypatch, env, alerts):
    iam = FakeIam(inline={"Ok": BENIGN})
    assert run(monkeypatch, iam)["results"][0]["status"] == "compliant"
    assert not iam.puts and not alerts


def test_unprotected_role_is_ignored(monkeypatch, env, alerts):
    iam = FakeIam(tags={}, inline={"Attack": ADMIN})
    assert run(monkeypatch, iam)["results"][0]["status"] == "not_protected"
    assert not iam.puts


def test_own_actions_are_ignored(monkeypatch, env, alerts):
    iam = FakeIam(inline={"Attack": ADMIN})
    assert run(monkeypatch, iam, actor=OWN_ROLE)["status"] == "ignored_self"
    assert not iam.puts


def test_failed_api_calls_are_ignored(monkeypatch, env, alerts):
    iam = FakeIam(inline={"Attack": ADMIN})
    assert run(monkeypatch, iam, errorCode="AccessDenied")["status"] == "ignored_failed_call"


def test_authorized_actor_is_exempt_but_still_alerts(monkeypatch, env, alerts):
    iam = FakeIam(inline={"Attack": ADMIN})
    result = run(monkeypatch, iam, actor=DEPLOY_ROLE)
    assert result["results"][0]["status"] == "exempt"
    assert not iam.puts
    assert alerts[0][0] == "warning"


def test_external_trust_gets_deny_all(monkeypatch, env, alerts):
    trust = {"Statement": [{"Effect": "Allow", "Principal": {"AWS": "arn:aws:iam::999988887777:root"}, "Action": "sts:AssumeRole"}]}
    iam = FakeIam(trust=trust)
    run(monkeypatch, iam, event_name="UpdateAssumeRolePolicy")
    assert handler.DENY_ALL_NAME in iam.inline


def test_deleting_the_deny_policy_is_restored(monkeypatch, env, alerts):
    iam = FakeIam(inline={"Attack": ADMIN})
    run(monkeypatch, iam)
    del iam.inline[handler.DENY_ALL_NAME]
    result = run(monkeypatch, iam, event_name="DeleteRolePolicy", params={"roleName": "aether-app-reporting-role", "policyName": handler.DENY_ALL_NAME})
    assert result["results"][0]["status"] == "tamper_restored"
    assert handler.DENY_ALL_NAME in iam.inline


def test_removing_the_quarantine_tag_is_restored(monkeypatch, env, alerts):
    iam = FakeIam(inline={"Attack": ADMIN})
    run(monkeypatch, iam)
    iam.tags.pop("sentinel:quarantined")
    result = run(monkeypatch, iam, event_name="UntagRole", params={"roleName": "aether-app-reporting-role", "tagKeys": ["sentinel:quarantined"]})
    assert result["results"][0]["status"] == "tamper_restored"
    assert iam.tags["sentinel:quarantined"] == "true"


def test_release_principal_can_lift_quarantine(monkeypatch, env, alerts):
    iam = FakeIam(inline={"Attack": ADMIN})
    run(monkeypatch, iam)
    del iam.inline[handler.DENY_ALL_NAME]
    puts = len(iam.puts)
    result = run(monkeypatch, iam, event_name="DeleteRolePolicy", actor=BREAK_GLASS,
                 params={"roleName": "aether-app-reporting-role", "policyName": handler.DENY_ALL_NAME})
    assert result["results"][0]["status"] == "release_recorded"
    assert len(iam.puts) == puts


@pytest.fixture
def metrics(monkeypatch):
    emitted = []
    monkeypatch.setattr(handler.slog, "emit_metric", lambda control, name, value=1, unit="Count": emitted.append(name))
    return emitted


def test_removing_the_protection_tag_raises_an_alert(monkeypatch, env, alerts, metrics):
    iam = FakeIam(tags={})
    result = run(monkeypatch, iam, event_name="UntagRole", params={"roleName": "aether-app-reporting-role", "tagKeys": ["sentinel:protected"]})
    assert result["results"][0]["status"] == "protection_removed_alerted"
    assert alerts[0][0] == "critical"
    # The CloudWatch alarm path keys on CriticalViolation, so it must fire here too.
    assert "CriticalViolation" in metrics


def test_release_principal_removing_protection_is_recorded(monkeypatch, env, alerts, metrics):
    iam = FakeIam(tags={})
    result = run(monkeypatch, iam, event_name="UntagRole", actor=BREAK_GLASS,
                 params={"roleName": "aether-app-reporting-role", "tagKeys": ["sentinel:protected"]})
    assert result["results"][0]["status"] == "protection_released"
    assert alerts[0][0] == "info"
    assert "CriticalViolation" not in metrics


def test_role_created_with_open_trust_is_quarantined(monkeypatch, env, alerts):
    trust = {"Statement": [{"Effect": "Allow", "Principal": {"AWS": "*"}, "Action": "sts:AssumeRole"}]}
    iam = FakeIam(trust=trust)
    result = run(monkeypatch, iam, event_name="CreateRole")
    assert result["results"][0]["status"] == "quarantined"
    assert handler.DENY_ALL_NAME in iam.inline


def test_tagging_an_existing_violator_as_protected_quarantines_it(monkeypatch, env, alerts):
    iam = FakeIam(inline={"Legacy": ADMIN})
    result = run(monkeypatch, iam, event_name="TagRole")
    assert result["results"][0]["status"] == "quarantined"


def test_tamper_restore_counts_as_violation(monkeypatch, env, alerts, metrics):
    iam = FakeIam(inline={"Attack": ADMIN})
    run(monkeypatch, iam)
    del iam.inline[handler.DENY_ALL_NAME]
    metrics.clear()
    run(monkeypatch, iam, event_name="DeleteRolePolicy",
        params={"roleName": "aether-app-reporting-role", "policyName": handler.DENY_ALL_NAME})
    assert {"TamperDetected", "ViolationDetected", "CriticalViolation", "RemediationSucceeded"} <= set(metrics)


def test_boundary_removal_without_violation_alerts_only(monkeypatch, env, alerts):
    iam = FakeIam(inline={"Ok": BENIGN})
    result = run(monkeypatch, iam, event_name="DeleteRolePermissionsBoundary")
    assert result["results"][0]["status"] == "boundary_removed_alerted"
    assert not iam.puts


def test_failure_raises_so_lambda_retries_and_alerts(monkeypatch, env, alerts):
    iam = FakeIam(inline={"Attack": ADMIN})

    def boom(**_):
        raise ClientError({"Error": {"Code": "AccessDenied"}}, "PutRolePolicy")

    iam.put_role_policy = boom
    with pytest.raises(ClientError):
        run(monkeypatch, iam)
    assert "FAILED" in alerts[0][1]
