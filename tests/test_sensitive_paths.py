from core.sensitive_paths import looks_sensitive


def test_detects_admin_path():
    assert looks_sensitive("/admin/dashboard") is True


def test_detects_git_directory():
    assert looks_sensitive("/.git/config") is True


def test_detects_backup_file():
    assert looks_sensitive("/site-backup.sql") is True


def test_case_insensitive_matching():
    assert looks_sensitive("/ADMIN/PANEL") is True


def test_normal_path_not_flagged():
    assert looks_sensitive("/products/blue-shoes") is False


def test_empty_path_not_flagged():
    assert looks_sensitive("") is False
