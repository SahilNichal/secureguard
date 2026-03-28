"""Sample vulnerable file: LDAP Injection"""


def find_user(ldap_conn, username):
    """Find user in LDAP — VULNERABLE to LDAP injection."""
    search_filter = f"(uid={username})"
    results = ldap_conn.search_s("dc=example,dc=com", 2, search_filter)
    return results


def authenticate(ldap_conn, username, password):
    """Authenticate via LDAP — VULNERABLE to LDAP injection."""
    search_filter = "(&(uid=" + username + ")(userPassword=" + password + "))"
    results = ldap_conn.search_s("dc=example,dc=com", 2, search_filter)
    return len(results) > 0
