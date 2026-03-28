"""Sample vulnerable file: Path Traversal"""
import os


def read_user_file(base_dir, filename):
    """Read a user-requested file — VULNERABLE to path traversal."""
    filepath = os.path.join(base_dir, filename)
    with open(filepath, 'r') as f:
        return f.read()


def serve_download(upload_dir, requested_file):
    """Serve a file download — VULNERABLE to path traversal."""
    path = f"{upload_dir}/{requested_file}"
    if os.path.exists(path):
        with open(path, 'rb') as f:
            return f.read()
    return None
