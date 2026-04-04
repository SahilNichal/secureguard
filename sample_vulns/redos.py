"""Sample vulnerable file: ReDoS (Regular Expression Denial of Service)"""
import re


def validate_email(email):
    """Validate email - VULNERABLE to ReDoS."""
    pattern = r'^([a-zA-Z0-9]+)+@([a-zA-Z0-9]+\.)+[a-zA-Z]{2,}$'
    return bool(re.match(pattern, email))


def validate_url(url):
    """Validate URL without nested empty-string repetition."""
    pattern = r'^(https?:\/\/)?([\da-z\.-]+)\.([a-z\.]{2,6})(?:\/[\w .-]*)*\/?$'
    return bool(re.match(pattern, url))
