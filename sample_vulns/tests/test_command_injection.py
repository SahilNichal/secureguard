"""Baseline behavior tests for command_injection.py."""
import io


def test_ping_host_invokes_command(monkeypatch):
    """ping_host should attempt to invoke a ping-like command with the hostname."""
    calls = []

    def fake_system(command):
        calls.append(command)
        return 0

    monkeypatch.setattr("sample_vulns.command_injection.os.system", fake_system)

    from sample_vulns.command_injection import ping_host

    ping_host("example.com")

    assert calls
    assert "example.com" in calls[0]


def test_list_directory_returns_subprocess_result(monkeypatch):
    """list_directory should return the subprocess result code."""
    calls = []

    def fake_call(command, shell=False):
        calls.append((command, shell))
        return 0

    monkeypatch.setattr("sample_vulns.command_injection.subprocess.call", fake_call)

    from sample_vulns.command_injection import list_directory

    result = list_directory("/tmp")

    assert result == 0
    assert calls
    assert "/tmp" in calls[0][0]


def test_read_log_returns_file_content(monkeypatch):
    """read_log should return the command output as text."""
    class FakePopen:
        def read(self):
            return "line1\nline2\n"

    monkeypatch.setattr("sample_vulns.command_injection.os.popen", lambda command: FakePopen())

    from sample_vulns.command_injection import read_log

    output = read_log("/var/log/app.log")

    assert output == "line1\nline2\n"
