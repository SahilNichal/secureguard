"""Sample vulnerable file: Insecure Deserialization"""
import pickle
import yaml


def load_user_data(data_bytes):
    """Load user data — VULNERABLE: pickle.loads on untrusted data."""
    return pickle.loads(data_bytes)


def load_config(yaml_string):
    """Load config — VULNERABLE: yaml.load without safe_load."""
    return yaml.load(yaml_string)


def save_and_load_session(session_data, filepath):
    """Save/load session — VULNERABLE: pickle with untrusted file."""
    with open(filepath, 'wb') as f:
        pickle.dump(session_data, f)
    with open(filepath, 'rb') as f:
        return pickle.loads(f.read())
