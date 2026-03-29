"""Tests for command_injection.py - verify shell=False and no os.system usage."""
import subprocess
import unittest
from unittest.mock import patch, MagicMock
import inspect
import ast


def test_ping_host_no_os_system():
    """ping_host should not use os.system."""
    from sample_vulns.command_injection import ping_host
    source = inspect.getsource(ping_host)
    assert 'os.system' not in source, "ping_host still uses os.system"


def test_ping_host_uses_subprocess_list():
    """ping_host should use subprocess with list args."""
    from sample_vulns.command_injection import ping_host
    source = inspect.getsource(ping_host)
    assert 'subprocess' in source or 'shlex' in source, "ping_host should use subprocess"
    assert 'shell=True' not in source, "ping_host should not use shell=True"


def test_list_directory_no_shell():
    """list_directory should not use shell=True."""
    from sample_vulns.command_injection import list_directory
    source = inspect.getsource(list_directory)
    assert 'shell=True' not in source, "list_directory still uses shell=True"


def test_read_log_no_os_popen():
    """read_log should not use os.popen."""
    from sample_vulns.command_injection import read_log
    source = inspect.getsource(read_log)
    assert 'os.popen' not in source, "read_log still uses os.popen"
