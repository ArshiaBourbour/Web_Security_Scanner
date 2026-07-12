import re

from core.report_naming import safe_report_filename


def test_filename_ends_with_extension():
    name = safe_report_filename("https://example.com", "html")
    assert name.endswith(".html")


def test_filename_is_filesystem_safe():
    name = safe_report_filename("https://example.com:8080/path?query=1", "json")
    # no slashes, colons, question marks, etc. should survive into the filename
    assert re.match(r"^[a-zA-Z0-9._-]+$", name)


def test_filename_uses_host_not_full_url():
    name = safe_report_filename("https://example.com/some/deep/path", "pdf")
    assert name.startswith("example.com_")


def test_filename_handles_bare_host_without_scheme():
    name = safe_report_filename("example.com", "html")
    assert name.startswith("example.com_")


def test_different_extensions_produce_different_suffix():
    html_name = safe_report_filename("https://example.com", "html")
    json_name = safe_report_filename("https://example.com", "json")
    assert html_name.endswith(".html")
    assert json_name.endswith(".json")
