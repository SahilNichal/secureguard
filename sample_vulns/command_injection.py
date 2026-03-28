"""Sample vulnerable file: Command Injection"""
import os
import subprocess


def ping_host(hostname):
    """Ping a host — VULNERABLE to command injection."""
    os.system("ping -c 1 " + hostname)


def list_directory(path):
    """List directory contents — VULNERABLE to command injection."""
    result = subprocess.call("ls -la " + path, shell=True)
    return result


def read_log(filename):
    """Read a log file — VULNERABLE to command injection."""
    output = os.popen(f"cat {filename}").read()
    return output
