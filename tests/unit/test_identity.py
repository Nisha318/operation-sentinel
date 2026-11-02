from sentinel_common import identity, util


def test_assumed_role_collapses_to_issuer_role_arn():
    ui = {
        "type": "AssumedRole",
        "arn": "arn:aws:sts::111122223333:assumed-role/deploy/session-1",
        "sessionContext": {"sessionIssuer": {"arn": "arn:aws:iam::111122223333:role/deploy"}},
    }
    assert identity.normalize_actor(ui) == "arn:aws:iam::111122223333:role/deploy"


def test_assumed_role_without_issuer_is_parsed_from_arn():
    ui = {"type": "AssumedRole", "arn": "arn:aws:sts::111122223333:assumed-role/deploy/session-1"}
    assert identity.normalize_actor(ui) == "arn:aws:iam::111122223333:role/deploy"


def test_iam_user_arn_is_returned_as_is():
    ui = {"type": "IAMUser", "arn": "arn:aws:iam::111122223333:user/alice"}
    assert identity.normalize_actor(ui) == "arn:aws:iam::111122223333:user/alice"


def test_is_listed_is_exact_match_only():
    allowed = ["arn:aws:iam::111122223333:role/deploy"]
    assert identity.is_listed("arn:aws:iam::111122223333:role/deploy", allowed)
    assert not identity.is_listed("arn:aws:iam::111122223333:role/deploy-evil", allowed)
    assert not identity.is_listed("", allowed)


def test_env_list_and_seconds_since(monkeypatch):
    monkeypatch.setenv("X", " a, b ,,c ")
    assert util.env_list("X") == ["a", "b", "c"]
    assert util.seconds_since("not a date") == 0.0
    assert util.seconds_since("2020-01-01T00:00:00Z") > 0
