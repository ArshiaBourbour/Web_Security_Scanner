from scanners.http_methods_checker import _classify


def test_none_status_is_unreachable():
    assert _classify(None) == "unreachable"


def test_405_is_disallowed():
    assert _classify(405) == "disallowed"


def test_501_is_disallowed():
    assert _classify(501) == "disallowed"


def test_200_is_allowed():
    assert _classify(200) == "allowed"


def test_301_redirect_is_allowed():
    assert _classify(301) == "allowed"


def test_399_boundary_is_allowed():
    assert _classify(399) == "allowed"


def test_400_is_unknown_not_allowed():
    # regression test: ambiguous statuses must NOT be treated as "confirmed allowed"
    assert _classify(400) == "unknown"


def test_404_is_unknown_not_allowed():
    # regression test: a 404 on a route means nothing about whether the
    # method itself is enabled at the server level
    assert _classify(404) == "unknown"


def test_403_is_unknown():
    assert _classify(403) == "unknown"
