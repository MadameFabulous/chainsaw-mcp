"""Run deployment scripts against disposable files and command shims; never contact a node."""

import os
import shutil
import subprocess
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]


def test_render_sandbox():
    env = dict(os.environ, CHAINSAW_MCP_HOME="/home/test/app", MCP_HOST="100.64.0.1")
    unit = subprocess.check_output(
        ["bash", str(ROOT / "deploy/render-unit.sh")], env=env, text=True
    )
    for directive in (
        "ProtectSystem=strict",
        "ProtectHome=read-only",
        "PrivateTmp=true",
        "PrivateDevices=true",
        "PrivateUsers=true",
        "CapabilityBoundingSet=",
        "RestrictAddressFamilies=AF_UNIX AF_INET AF_INET6",
        "NoNewPrivileges=true",
        "MemoryMax=4G",
        "TasksMax=512",
        "ReadWritePaths=/home/test/app/.chainsaw-mcp/results /home/test/app/custom-rules",
    ):
        assert directive in unit
    assert "ReadOnlyPaths=/home/test/app/evidence" in unit
    reference = (ROOT / "deploy/systemd/mcp-chainsaw.service").read_text()
    for directive in ("ProtectSystem=strict", "ProtectHome=read-only", "PrivateDevices=true"):
        assert directive in reference


@pytest.fixture
def node(tmp_path):
    home = tmp_path / "home"
    home.mkdir()
    dest = home / "dev/app"
    dest.mkdir(parents=True)
    (dest / "old-code").write_text("old")
    (dest / ".deployed-revision").write_text("old-revision\n")
    for name in ("evidence", "custom-rules", ".chainsaw-mcp/results", "vendor/chainsaw"):
        (dest / name).mkdir(parents=True)
    (dest / "evidence/sample").write_text("evidence")
    (dest / ".env").write_text("secret-preserved")
    (dest / "vendor/chainsaw/chainsaw").write_text("#!/bin/sh\nexit 0\n")
    (dest / "vendor/chainsaw/chainsaw").chmod(0o755)
    incoming = home / "incoming"
    shutil.copytree(ROOT / "deploy", incoming / "deploy")
    (incoming / "new-code").write_text("new")
    for tree in (dest, incoming):
        (tree / "scripts").mkdir()
        (tree / "scripts/mcp-health.py").write_text(
            "import os, pathlib, sys\n"
            "sys.exit(1 if os.environ.get('FAIL') == 'health' "
            "and pathlib.Path('new-code').exists() else 0)\n"
        )
    bin_dir = home / ".local/bin"
    bin_dir.mkdir(parents=True)
    shim = """import os, pathlib, subprocess, sys, signal
home = pathlib.Path(os.environ['HOME'])
dest = home / 'dev/app'
name = pathlib.Path(sys.argv[0]).name
args = sys.argv[1:]
fail = os.environ.get('FAIL')
with (home / 'commands').open('a') as log:
    log.write(name + ' ' + ' '.join(args) + '\\n')
if name == 'uv':
    if fail == 'sync': sys.exit(7)
    venv = pathlib.Path('.venv/bin'); venv.mkdir(parents=True, exist_ok=True)
    app = venv / 'chainsaw-mcp'
    app.write_text(
        "#!" + sys.executable + "\\nimport sys, time\\n"
        'if "--check" not in sys.argv: time.sleep(120)\\n'
    )
    app.chmod(0o755)
elif name == 'tailscale': print('100.64.0.1')
elif name == 'systemctl':
    pidfile = home / 'pid'
    if 'stop' in args or 'restart' in args:
        if pidfile.exists():
            try: os.kill(int(pidfile.read_text()), signal.SIGTERM)
            except ProcessLookupError: pass
            pidfile.unlink()
    if 'restart' in args:
        if fail == 'restart' and (dest / 'new-code').exists(): sys.exit(8)
        cwd = home if fail == 'identity' and (dest / 'new-code').exists() else dest
        proc = subprocess.Popen([str(dest / '.venv/bin/chainsaw-mcp')], cwd=cwd,
                                stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
                                stderr=subprocess.DEVNULL, start_new_session=True)
        pidfile.write_text(str(proc.pid))
    if 'show' in args: print(pidfile.read_text() if pidfile.exists() else '0')
    if 'is-active' in args: sys.exit(0 if pidfile.exists() else 1)
    if 'daemon-reload' in args and fail == 'install' and (dest / 'new-code').exists():
        sys.exit(9)
"""
    for name in ("uv", "systemctl", "tailscale"):
        executable = bin_dir / name
        executable.write_text(f"#!{sys.executable}\n" + shim)
        executable.chmod(0o755)
    env = dict(os.environ, HOME=str(home), PATH=f"{bin_dir}:{os.environ['PATH']}")
    subprocess.run(["uv", "sync"], cwd=dest, env=env, check=True)
    unit = home / ".config/systemd/user/mcp-chainsaw.service"
    unit.parent.mkdir(parents=True)
    unit.write_text("old-unit")
    yield home, dest, incoming, unit, env
    if (home / "pid").exists():
        subprocess.run(["systemctl", "--user", "stop", "mcp-chainsaw.service"], env=env)


def run_install(node, failure=""):
    home, dest, incoming, unit, env = node
    return subprocess.run(
        ["bash", str(ROOT / "deploy/install-node.sh"), str(dest), "a" * 40, str(incoming)],
        env=dict(env, FAIL=failure),
        text=True,
        capture_output=True,
        timeout=20,
    )


def test_install_retains_previous_release(node):
    result = run_install(node)
    assert result.returncode == 0, result.stderr
    home, dest, incoming, unit, env = node
    previous = Path(str(dest) + ".previous")
    assert (previous / "old-code").read_text() == "old"
    assert (previous / ".venv/bin/chainsaw-mcp").exists()
    assert (dest / ".deployed-revision").read_text().strip() == "a" * 40
    assert (dest / "evidence/sample").read_text() == "evidence"
    assert (dest / ".env").read_text() == "secret-preserved"
    assert "verified process" in result.stdout


@pytest.mark.parametrize("host", ["100.64.0.1", "fd7a:115c:a1e0::1", "[fd7a:115c:a1e0::1]"])
def test_candidate_health_url_uses_a_valid_authority(node, host):
    home, dest, incoming, unit, env = node
    env.update(MCP_HOST=host, MCP_PORT="19098", MCP_PATH="/new-mcp")
    (incoming / "scripts/mcp-health.py").write_text(
        "from urllib.parse import urlsplit\n"
        "import pathlib, sys\n"
        "url = urlsplit(sys.argv[1])\n"
        "assert url.port == 19098\n"
        "assert url.path == '/new-mcp'\n"
        "pathlib.Path('probed-host').write_text(url.hostname)\n"
    )
    result = run_install(node)
    assert result.returncode == 0, result.stderr
    assert (dest / "probed-host").read_text() == host.strip("[]")
    assert (dest / ".deployed-revision").read_text().strip() == "a" * 40


@pytest.mark.parametrize("failure", ["sync", "install", "restart", "health", "identity"])
def test_failed_install_restores_release_unit_state_and_restarts(node, failure):
    result = run_install(node, failure)
    assert result.returncode != 0
    home, dest, incoming, unit, env = node
    assert (dest / "old-code").read_text() == "old"
    assert not (dest / "new-code").exists()
    assert (dest / ".deployed-revision").read_text() == "old-revision\n"
    assert unit.read_text() == "old-unit"
    assert (dest / "evidence/sample").read_text() == "evidence"
    assert (dest / ".env").read_text() == "secret-preserved"
    assert (home / "pid").exists()
    assert "rollback healthy" in result.stderr


def test_ship_requires_target(node):
    home, dest, incoming, unit, env = node
    env = {k: v for k, v in env.items() if not k.startswith("CHAINSAW_DEPLOY_")}
    result = subprocess.run(
        ["bash", str(ROOT / "deploy/deploy-node.sh")],
        env=env,
        capture_output=True,
        text=True,
        timeout=20,
    )
    assert result.returncode != 0
    assert "CHAINSAW_DEPLOY_NODE" in result.stderr
    assert (dest / "old-code").exists()


@pytest.mark.parametrize("failure", ["", "health", "transfer"])
def test_ship_runs_real_installer_with_fake_git_and_ssh(node, failure):
    home, dest, incoming, unit, env = node
    bin_dir = home / ".local/bin"
    for name, body in {
        "git": """import os, subprocess, sys
if sys.argv[1] == 'diff': sys.exit(0)
if sys.argv[1] == 'rev-parse': print('a' * 40)
if sys.argv[1] == 'archive':
    if os.environ.get('FAIL') == 'transfer': sys.exit(2)
    sys.exit(subprocess.call(['tar', '-c', '-C', os.environ['ARCHIVE'], '.']))
""",
        "ssh": """import subprocess, sys
sys.exit(subprocess.call(['bash', '-c', sys.argv[-1]]))
""",
    }.items():
        executable = bin_dir / name
        executable.write_text(f"#!{sys.executable}\n" + body)
        executable.chmod(0o755)
    result = subprocess.run(
        ["bash", str(ROOT / "deploy/deploy-node.sh")],
        env=dict(
            env,
            ARCHIVE=str(incoming),
            CHAINSAW_DEPLOY_NODE="node.example",
            CHAINSAW_DEPLOY_USER="svc",
            CHAINSAW_DEPLOY_DEST="dev/app",
            MCP_HOST="100.64.0.1",
            FAIL=failure,
        ),
        capture_output=True,
        text=True,
        timeout=20,
    )
    if failure:
        assert result.returncode != 0
        assert (dest / "old-code").exists()
        assert unit.read_text() == "old-unit"
    else:
        assert result.returncode == 0, result.stderr
        assert (Path(str(dest) + ".previous") / "old-code").exists()
        assert "verified process" in result.stdout


@pytest.mark.parametrize(
    ("previous_host", "expected"),
    [
        ("100.64.0.1", "http://100.64.0.1:18098/mcp"),
        ("fd7a:115c:a1e0::1", "http://[fd7a:115c:a1e0::1]:18098/mcp"),
        ("[fd7a:115c:a1e0::1]", "http://[fd7a:115c:a1e0::1]:18098/mcp"),
    ],
)
def test_rollback_probes_the_listener_of_the_restored_unit(node, previous_host, expected):
    home, dest, incoming, unit, env = node
    # The candidate moves the listener; its probe fails, so rollback must probe the old one.
    env.update(MCP_HOST="100.64.0.1", MCP_PORT="19000", MCP_PATH="/new-mcp")
    for tree in (dest, incoming):
        (tree / "scripts/mcp-health.py").write_text(
            f"import sys\nassert sys.argv[1] == {expected!r}, sys.argv[1]\n"
        )
    unit.write_text(
        "[Service]\n"
        "ExecStart=/app/.venv/bin/chainsaw-mcp --transport streamable-http "
        f"--host {previous_host} --port 18098 --path /mcp\n"
    )
    result = run_install(node)
    assert result.returncode != 0
    assert (dest / "old-code").exists()
    assert unit.read_text().startswith("[Service]")
    assert "rollback healthy" in result.stderr, result.stderr


def test_ship_forwards_the_memory_cap_across_the_ssh_boundary(node):
    home, dest, incoming, unit, env = node
    bin_dir = home / ".local/bin"
    for name, body in {
        "git": """import os, subprocess, sys
if sys.argv[1] == 'diff': sys.exit(0)
if sys.argv[1] == 'rev-parse': print('a' * 40)
if sys.argv[1] == 'archive':
    sys.exit(subprocess.call(['tar', '-c', '-C', os.environ['ARCHIVE'], '.']))
""",
        # A real remote shell does not inherit the workstation environment, so only what
        # deploy-node.sh forwards explicitly can reach render-unit.sh.
        "ssh": """import os, subprocess, sys
remote_env = {key: os.environ[key] for key in ('HOME', 'PATH')}
sys.exit(subprocess.call(['bash', '-c', sys.argv[-1]], env=remote_env))
""",
    }.items():
        executable = bin_dir / name
        executable.write_text(f"#!{sys.executable}\n" + body)
        executable.chmod(0o755)
    result = subprocess.run(
        ["bash", str(ROOT / "deploy/deploy-node.sh")],
        env=dict(
            env,
            ARCHIVE=str(incoming),
            CHAINSAW_DEPLOY_NODE="node.example",
            CHAINSAW_DEPLOY_USER="svc",
            CHAINSAW_DEPLOY_DEST="dev/app",
            MCP_HOST="100.64.0.1",
            MCP_MEMORY_MAX="8G",
        ),
        capture_output=True,
        text=True,
        timeout=20,
    )
    assert result.returncode == 0, result.stderr
    assert "MemoryMax=8G" in unit.read_text()
    assert "--host 100.64.0.1 " in unit.read_text()
