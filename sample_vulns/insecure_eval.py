"""Sample vulnerable file: Insecure eval/exec"""


def calculate(expression):
    """Evaluate a math expression — VULNERABLE: uses eval on user input."""
    return eval(expression)


def run_user_code(code_string):
    """Execute user-provided code — VULNERABLE: uses exec on user input."""
    exec(code_string)


def parse_config(config_str):
    """Parse a config string — VULNERABLE: uses eval instead of json.loads."""
    return eval(config_str)
