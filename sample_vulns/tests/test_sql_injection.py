"""Baseline behavior tests for sql_injection.py."""
import os
import sqlite3
import tempfile

import pytest


@pytest.fixture
def db_path():
    """Create a temp SQLite database with test data."""
    fd, path = tempfile.mkstemp(suffix=".db")
    os.close(fd)
    conn = sqlite3.connect(path)
    cursor = conn.cursor()
    cursor.execute("CREATE TABLE users (id INTEGER PRIMARY KEY, username TEXT, name TEXT)")
    cursor.execute("INSERT INTO users VALUES (1, 'alice', 'Alice Smith')")
    cursor.execute("INSERT INTO users VALUES (2, 'bob', 'Bob Jones')")
    cursor.execute("INSERT INTO users VALUES (3, 'charlie', 'Charlie Brown')")
    conn.commit()
    conn.close()
    yield path
    os.unlink(path)


def test_get_user_normal(db_path):
    from sample_vulns.sql_injection import get_user

    result = get_user(db_path, "alice")

    assert result is not None
    assert result[1] == "alice"


def test_get_user_not_found(db_path):
    from sample_vulns.sql_injection import get_user

    result = get_user(db_path, "nonexistent")

    assert result is None


def test_search_users_normal(db_path):
    from sample_vulns.sql_injection import search_users

    results = search_users(db_path, "alice")

    assert len(results) >= 1
    assert any(row[2] == "Alice Smith" for row in results)


def test_delete_user_normal(db_path):
    from sample_vulns.sql_injection import delete_user

    delete_user(db_path, 1)

    conn = sqlite3.connect(db_path)
    cursor = conn.cursor()
    cursor.execute("SELECT COUNT(*) FROM users")
    count = cursor.fetchone()[0]
    conn.close()

    assert count == 2
