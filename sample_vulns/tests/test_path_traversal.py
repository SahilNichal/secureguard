"""Tests for path_traversal.py — verify path validation."""
import os
import tempfile
import pytest


@pytest.fixture
def base_dir():
    """Create a temp directory with some files."""
    d = tempfile.mkdtemp()
    with open(os.path.join(d, "allowed.txt"), 'w') as f:
        f.write("allowed content")
    yield d
    import shutil
    shutil.rmtree(d)


def test_read_normal_file(base_dir):
    from sample_vulns.path_traversal import read_user_file
    content = read_user_file(base_dir, "allowed.txt")
    assert content == "allowed content"


def test_read_traversal_blocked(base_dir):
    """Path traversal with ../ should be blocked."""
    from sample_vulns.path_traversal import read_user_file
    with pytest.raises((ValueError, PermissionError, OSError)):
        read_user_file(base_dir, "../../etc/passwd")


def test_serve_traversal_blocked(base_dir):
    """serve_download should block ../ in filename."""
    from sample_vulns.path_traversal import serve_download
    result = serve_download(base_dir, "../../../etc/passwd")
    # Should either return None or raise an exception
    assert result is None or False, "Path traversal should be blocked"
