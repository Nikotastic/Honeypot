import pytest

from honeypot.commands import Shell


@pytest.fixture
def shell() -> Shell:
    return Shell()


def test_whoami_returns_root(shell):
    assert shell.respond("whoami") == "root\r\n"


def test_unknown_command_returns_not_found(shell):
    assert shell.respond("nmap") == "-bash: nmap: command not found\r\n"


def test_multiple_commands_separated_by_semicolon(shell):
    assert shell.respond("whoami; pwd") == "root\r\n/root\r\n"


def test_cd_changes_directory(shell):
    shell.respond("cd /tmp")
    assert shell.respond("pwd") == "/tmp\r\n"
    assert shell.prompt() == "root@srv-prod-01:/tmp# "


def test_cd_to_missing_directory_fails(shell):
    assert "No such file or directory" in shell.respond("cd /nope")
    assert shell.cwd == "/root"


def test_cat_reads_file(shell):
    assert "db_user=admin" in shell.respond("cat notes.txt")


def test_ls_hides_dotfiles_unless_a_flag(shell):
    assert ".bashrc" not in shell.respond("ls")
    assert ".bashrc" in shell.respond("ls -a")


def test_sessions_do_not_share_state():
    first, second = Shell(), Shell()
    first.respond("cd /tmp")
    assert second.cwd == "/root"
