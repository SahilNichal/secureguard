"""Sample vulnerable file: Log Injection"""
import logging

logger = logging.getLogger(__name__)


def log_login(username):
    """Log a login event - VULNERABLE to log injection."""
    logger.info(f"User logged in: {username}")


def log_action(user_input, action):
    """Log a user action - VULNERABLE to log injection."""
    logger.warning("User " + user_input + " performed action: " + action)


def log_error(error_message):
    """Log an error - VULNERABLE to log injection."""
    logger.error(f"Error occurred: {error_message}")
