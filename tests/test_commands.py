from honeypot.commands import respond


def test_whoami_returns_root():
    assert respond("whoami") == "root\r\n"


def test_unknown_command_returns_not_found():
    assert respond("nmap") == "-bash: nmap: command not found\r\n"


def test_multiple_commands_separated_by_semicolon():
    assert respond("whoami; pwd") == "root\r\n/root\r\n"


def test_silent_command_returns_nothing():
    assert respond("cd /tmp") == ""
