"""Baseline behavior tests for insecure_deserialization.py."""


def test_load_user_data_reads_json_bytes():
    from sample_vulns.insecure_deserialization import load_user_data

    assert load_user_data(b'{"user": "alice", "role": "admin"}') == {
        "user": "alice",
        "role": "admin",
    }


def test_load_config_uses_safe_yaml():
    from sample_vulns.insecure_deserialization import load_config

    assert load_config("name: secureguard\nretries: 3\n") == {
        "name": "secureguard",
        "retries": 3,
    }


def test_save_and_load_session_round_trips_json(tmp_path):
    from sample_vulns.insecure_deserialization import save_and_load_session

    session_file = tmp_path / "session.json"
    session_data = {"user_id": 7, "roles": ["reader", "writer"]}

    assert save_and_load_session(session_data, session_file) == session_data
