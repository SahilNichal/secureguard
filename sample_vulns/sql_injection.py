"""Sample vulnerable file: SQL Injection"""
import sqlite3


def get_user(db_path, username):
    """Fetch a user by username - VULNERABLE to SQL injection."""
    conn = sqlite3.connect(db_path)
    cursor = conn.cursor()
    query = "SELECT * FROM users WHERE username = '" + username + "'"
    cursor.execute(query)
    result = cursor.fetchone()
    conn.close()
    return result


def search_users(db_path, search_term):
    """Search users by name - VULNERABLE to SQL injection."""
    conn = sqlite3.connect(db_path)
    cursor = conn.cursor()
    query = f"SELECT * FROM users WHERE name LIKE '%{search_term}%'"
    cursor.execute(query)
    results = cursor.fetchall()
    conn.close()
    return results


def delete_user(db_path, user_id):
    """Delete a user - VULNERABLE to SQL injection."""
    conn = sqlite3.connect(db_path)
    cursor = conn.cursor()
    cursor.execute("DELETE FROM users WHERE id = %s" % user_id)
    conn.commit()
    conn.close()
