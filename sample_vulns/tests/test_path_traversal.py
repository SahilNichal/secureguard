"""Baseline behavior tests for path_traversal.py."""
import os
import tempfile

import pytest


@pytest.fixture
def base_dir():
    """Create a temp directory with some files."""
    d = tempfile.mkdtemp()
    with open(os.path.join(d, "allowed.txt"), "w") as f:
        f.write("allowed content")
    yield d
    import shutil
    shutil.rmtree(d)


def test_read_normal_file(base_dir):
    from sample_vulns.path_traversal import read_user_file

    content = read_user_file(base_dir, "allowed.txt")

    assert content == "allowed content"


def test_serve_existing_file(base_dir):
    from sample_vulns.path_traversal import serve_download

    result = serve_download(base_dir, "allowed.txt")

    assert result == b"allowed content"


def test_serve_missing_file_returns_none(base_dir):
    from sample_vulns.path_traversal import serve_download

    result = serve_download(base_dir, "missing.txt")

    assert result is None
