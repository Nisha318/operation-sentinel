from iam_quarantine import policy_eval as pe


def doc(*statements):
    return {"Version": "2012-10-17", "Statement": list(statements)}


def allow(action, resource="*", **extra):
    return {"Effect": "Allow", "Action": action, "Resource": resource, **extra}


def test_admin_star_is_critical_deny_all():
    findings = pe.evaluate_policy_document(doc(allow("*")))
    assert [f["tier"] for f in findings] == [pe.CRITICAL]
    assert pe.summarize(findings)[:2] == (pe.CRITICAL, pe.DENY_ALL)


def test_service_wildcard_is_high_targeted():
    findings = pe.evaluate_policy_document(doc(allow(["rds:*"])))
    tier, response, services = pe.summarize(findings)
    assert (tier, response, services) == (pe.HIGH, pe.DENY_TARGETED, ["rds"])


def test_specific_actions_on_star_are_fine():
    assert pe.evaluate_policy_document(doc(allow(["rds:DescribeDBInstances", "rds:Describe*"]))) == []


def test_service_wildcard_scoped_to_one_resource_is_fine():
    assert pe.evaluate_policy_document(doc(allow("rds:*", "arn:aws:rds:us-east-1:111122223333:cluster:reports"))) == []


def test_deny_statements_are_ignored():
    deny = {"Effect": "Deny", "Action": "*", "Resource": "*"}
    assert pe.evaluate_policy_document(doc(deny)) == []


def test_not_action_on_star_is_critical():
    statement = {"Effect": "Allow", "NotAction": "iam:*", "Resource": "*"}
    assert pe.evaluate_policy_document(doc(statement))[0]["tier"] == pe.CRITICAL


def test_single_statement_not_in_a_list_is_handled():
    assert pe.evaluate_policy_document({"Statement": allow("*")})[0]["tier"] == pe.CRITICAL


def test_condition_does_not_hide_a_broad_grant():
    statement = allow("*", Condition={"StringEquals": {"aws:RequestedRegion": "us-east-1"}})
    assert pe.evaluate_policy_document(doc(statement))[0]["tier"] == pe.CRITICAL


def test_critical_beats_high_and_deny_all_wins():
    findings = pe.evaluate_policy_document(doc(allow("rds:*"), allow("*")))
    assert pe.summarize(findings)[:2] == (pe.CRITICAL, pe.DENY_ALL)


def test_targeted_actions_for_rds_cover_snapshot_sharing():
    actions = pe.targeted_actions(["rds"])
    assert "rds:ModifyDBSnapshotAttribute" in actions
    assert "rds:DescribeDBInstances" not in actions


def test_unmapped_service_falls_back_to_service_wildcard():
    assert pe.targeted_actions(["dynamodb"]) == {"dynamodb:*"}


def trust(principal, **extra):
    return doc({"Effect": "Allow", "Action": "sts:AssumeRole", "Principal": principal, **extra})


def test_trust_open_to_anyone_is_critical():
    assert pe.evaluate_trust_policy(trust({"AWS": "*"}), "111122223333")[0]["tier"] == pe.CRITICAL
    assert pe.evaluate_trust_policy(trust("*"), "111122223333")[0]["tier"] == pe.CRITICAL


def test_trust_wildcard_with_condition_is_high():
    findings = pe.evaluate_trust_policy(trust({"AWS": "*"}, Condition={"StringEquals": {"aws:PrincipalOrgID": "o-1"}}), "111122223333")
    assert findings[0]["tier"] == pe.HIGH


def test_trust_external_account_is_high_deny_all():
    findings = pe.evaluate_trust_policy(trust({"AWS": "arn:aws:iam::999988887777:root"}), "111122223333")
    assert (findings[0]["tier"], findings[0]["response"]) == (pe.HIGH, pe.DENY_ALL)


def test_trust_own_and_listed_accounts_and_services_are_fine():
    assert pe.evaluate_trust_policy(trust({"AWS": "arn:aws:iam::111122223333:root"}), "111122223333") == []
    assert pe.evaluate_trust_policy(trust({"AWS": "999988887777"}), "111122223333", ["999988887777"]) == []
    assert pe.evaluate_trust_policy(trust({"Service": "lambda.amazonaws.com"}), "111122223333") == []
