"""Sample vulnerable file: Arbitrary File Upload"""
import os


def upload_file(upload_dir, file_obj):
    """Save an uploaded file — VULNERABLE: no extension/MIME validation."""
    filename = file_obj.filename
    filepath = os.path.join(upload_dir, filename)
    file_obj.save(filepath)
    return filepath


def upload_avatar(upload_dir, file_obj):
    """Save an avatar image — VULNERABLE: no validation."""
    filepath = os.path.join(upload_dir, file_obj.filename)
    with open(filepath, 'wb') as f:
        f.write(file_obj.read())
    return filepath
