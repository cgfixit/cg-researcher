#!/usr/bin/env python3
"""Exercise uninstall path checks without touching services, Keychain or user files."""

import os, pathlib, subprocess, tempfile

script = pathlib.Path(__file__).with_name("uninstall.sh").resolve()
with tempfile.TemporaryDirectory(prefix="cg-uninstall-check-") as tmp:
    root = pathlib.Path(tmp)
    home = root / "user"
    home.mkdir()
    (home / "keep.txt").write_text("unrelated user data")
    (home / "child").mkdir()
    alias = root / "home-link"
    alias.symlink_to(home, target_is_directory=True)
    mock = root / "mock"
    mock.mkdir()
    for tool in ("launchctl", "security", "rm", "rmdir", "uname"):
        p = mock / tool
        p.write_text(
            "#!/bin/sh\n"
            + (
                "echo Darwin\n"
                if tool == "uname"
                else 'printf "%s\\n" "$0 $*" >> "$CG_CHECK_LOG"\nexit '
                + ("1" if tool == "security" else "0")
                + "\n"
            )
        )
        p.chmod(0o755)
    log = root / "calls"
    env = dict(
        os.environ,
        HOME=str(home),
        PATH=str(mock) + ":/usr/bin:/bin:/usr/sbin:/sbin",
        CG_CHECK_LOG=str(log),
    )
    failures = []
    for selected in [
        str(home) + "/",
        str(home) + "/.",
        str(home / "child") + "/..",
        str(alias),
        "/",
        str(root),
    ]:
        log.unlink(missing_ok=True)
        r = subprocess.run(
            ["/bin/bash", str(script), "--purge", "--yes"],
            env=dict(env, CG_HOME=selected),
            capture_output=True,
            text=True,
        )
        if r.returncode == 0 or log.exists():
            failures.append(
                (selected, r.returncode, log.read_text() if log.exists() else "")
            )
        assert (home / "keep.txt").read_text() == "unrelated user data"
    assert not failures, failures
    selected = home / "researcher"
    selected.mkdir()
    for path in [str(selected), "researcher"]:
        log.unlink(missing_ok=True)
        r = subprocess.run(
            ["/bin/bash", str(script), "--purge", "--yes"],
            cwd=home,
            env=dict(env, CG_HOME=path, CDPATH=str(home)),
            capture_output=True,
            text=True,
        )
        assert r.returncode == 0, r.stderr
        assert "rm -rf -- " + str(selected.resolve()) in log.read_text(), r.stdout
        assert "rm -f " + str(selected.resolve() / "bin/cg-researcher") in log.read_text()
        assert (home / "keep.txt").read_text() == "unrelated user data"
    print(
        "PASS: six unsafe aliases rejected before side effects; unrelated data preserved"
    )
    print("PASS: absolute and relative homes ignore exported CDPATH")

# Rendering a service for a relative home must retain the installer's directory.
import plistlib

installer = script.with_name("install.sh")
r = subprocess.run(
    ["/bin/bash", str(installer), "--print-plist"],
    env=dict(os.environ, CG_HOME="./relative-fixture"),
    capture_output=True,
    check=True,
)
args = plistlib.loads(r.stdout)["ProgramArguments"]
assert pathlib.Path(args[0]).is_absolute()
assert (
    pathlib.Path(args[0]) == pathlib.Path.cwd() / "relative-fixture/bin/cg-researcher"
)
assert pathlib.Path(args[2]) == pathlib.Path.cwd() / "relative-fixture"
print("PASS: relative installer home renders absolute launchd arguments")
