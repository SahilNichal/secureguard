"""Sample vulnerable file: Insecure Deserialization"""
import json
import yaml


def load_user_data(data_bytes):
    """Load user data from JSON bytes instead of untrusted pickle content."""
    if isinstance(data_bytes, (bytes, bytearray)):
        data_text = data_bytes.decode("utf-8")
    else:
        data_text = str(data_bytes)
    return json.loads(data_text)


def load_config(yaml_string):
    """Load config with safe YAML parsing."""
    return yaml.safe_load(yaml_string)


def save_and_load_session(session_data, filepath):
    """Save and load session data with JSON serialization."""
    with open(filepath, 'w', encoding='utf-8') as f:
        json.dump(session_data, f)
    with open(filepath, 'r', encoding='utf-8') as f:
        return json.load(f)
