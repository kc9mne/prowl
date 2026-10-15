import pytest

from prowl import launch


def test_validate_rejects_bad_input():
    with pytest.raises(launch.LaunchError):
        launch.build("ssh", "not-an-ip", 22)
    with pytest.raises(launch.LaunchError):
        launch.build("ssh", "10.0.0.5", 70000)
    with pytest.raises(launch.LaunchError):
        launch.build("gopher", "10.0.0.5", 70)
    # shell metacharacters in username must be rejected
    with pytest.raises(launch.LaunchError):
        launch.build("ssh", "10.0.0.5", 22, username="root; rm -rf /")
    with pytest.raises(launch.LaunchError):
        launch.build("ssh", "10.0.0.5", 22, username="a`whoami`")


def test_ssh_argv_is_a_list_no_shell():
    plan = launch.build("ssh", "192.168.1.9", 2222, username="admin")
    assert plan["mode"] == "terminal"
    assert plan["argv"][0] == "ssh"
    assert "admin@192.168.1.9" in plan["argv"]
    assert "2222" in plan["argv"]
    # the whole thing is argv tokens, never a single shell string
    assert all(isinstance(a, str) for a in plan["argv"])


def test_ssh_password_never_in_argv(monkeypatch):
    # force the sshpass path
    monkeypatch.setattr(launch.shutil, "which", lambda name: "/usr/bin/sshpass" if name == "sshpass" else None)
    plan = launch.build("ssh", "10.0.0.5", 22, username="root", password="s3cr3t")
    assert plan["argv"][:2] == ["sshpass", "-e"]
    assert "s3cr3t" not in plan["argv"]
    assert plan["env"].get("SSHPASS") == "s3cr3t"


def test_ssh_password_without_sshpass_prompts(monkeypatch):
    monkeypatch.setattr(launch.shutil, "which", lambda name: None)
    plan = launch.build("ssh", "10.0.0.5", 22, username="root", password="s3cr3t")
    assert "s3cr3t" not in plan["argv"]
    assert plan["env"] == {}
    assert "sshpass" in plan["note"]


def test_web_and_smb_uris():
    assert launch.build("http", "10.0.0.5", 80)["uri"] == "http://10.0.0.5/"
    assert launch.build("https", "10.0.0.5", 8443)["uri"] == "https://10.0.0.5:8443/"
    smb = launch.build("smb", "10.0.0.5", 445)
    assert smb["mode"] == "uri" and "10.0.0.5" in smb["uri"]


def test_rdp_plan_shape():
    plan = launch.build("rdp", "10.0.0.5", 3389, username="corp\\\\joe".replace("\\\\", "\\"))
    assert plan["mode"] in ("terminal", "rdp-win")
