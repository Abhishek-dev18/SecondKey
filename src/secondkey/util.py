"""Small shared helpers: state directory, ids, subprocess wrapper."""

from __future__ import annotations

import getpass
import os
import secrets
import shutil
import subprocess
import time
from pathlib import Path
from typing import Mapping, Sequence


def home() -> Path:
    """Directory holding SecondKey state (database, audit log, snapshots)."""
    p = Path(os.environ.get("SECONDKEY_HOME") or Path.home() / ".secondkey")
    p.mkdir(parents=True, exist_ok=True)
    return p


def snapshot_root() -> Path:
    p = home() / "snapshots"
    p.mkdir(parents=True, exist_ok=True)
    return p


def new_id(prefix: str) -> str:
    return f"{prefix}_{secrets.token_hex(3)}"


def now() -> float:
    return time.time()


def whoami() -> str:
    for var in ("SECONDKEY_USER", "USER", "USERNAME"):
        if os.environ.get(var):
            return os.environ[var]
    try:
        return getpass.getuser()
    except Exception:  # pragma: no cover - platform specific
        return "unknown"


class CommandError(RuntimeError):
    def __init__(self, argv: Sequence[str], code: int, stderr: str):
        self.argv, self.code, self.stderr = list(argv), code, stderr
        super().__init__(f"{argv[0]} exited {code}: {stderr.strip()[:400]}")


def run(argv: Sequence[str], cwd: str | None = None, env: Mapping[str, str] | None = None,
        input: str | None = None, timeout: float = 600, check: bool = True) -> subprocess.CompletedProcess:
    """Run a command without a shell. Raises CommandError on failure when check=True."""
    if shutil.which(argv[0]) is None and not os.path.isabs(argv[0]):
        raise CommandError(argv, 127, f"{argv[0]}: command not found")
    proc = subprocess.run(list(argv), cwd=cwd, env=dict(env) if env is not None else None, input=input,
                          capture_output=True, text=True, timeout=timeout)
    if check and proc.returncode != 0:
        raise CommandError(argv, proc.returncode, proc.stderr or proc.stdout)
    return proc


def human_size(n: int) -> str:
    size = float(n)
    for unit in ("B", "KB", "MB", "GB"):
        if size < 1024 or unit == "GB":
            return f"{size:.0f} {unit}" if unit == "B" else f"{size:.1f} {unit}"
        size /= 1024
    return f"{n} B"  # pragma: no cover
