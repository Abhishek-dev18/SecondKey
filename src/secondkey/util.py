"""Small shared helpers: state directory, ids, subprocess wrapper."""

from __future__ import annotations

import getpass
import os
import re
import secrets
import shutil
import subprocess
import time
from pathlib import Path
from typing import Mapping, Sequence


def home() -> Path:
    """Directory holding SecondKey state (database, audit log, snapshots)."""
    p = Path(os.environ.get("SECONDKEY_HOME") or Path.home() / ".secondkey")
    if not p.exists():
        p.mkdir(parents=True, exist_ok=True)
    try:
        if p.stat().st_mode & 0o077:
            p.chmod(0o700)  # snapshots hold real data: owner only
    except OSError:
        pass
    return p


def snapshot_root() -> Path:
    p = home() / "snapshots"
    p.mkdir(mode=0o700, parents=True, exist_ok=True)
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


TOOL_HINTS = {
    "pg_dump": "install the PostgreSQL client tools (same major version as your server or newer), e.g. `brew install libpq` or `apt install postgresql-client-16`",
    "pg_restore": "install the PostgreSQL client tools (they include pg_restore)",
    "psql": "install the PostgreSQL client tools (they include psql)",
    "mysqldump": "install the MySQL client tools, e.g. `brew install mysql-client` or `apt install mysql-client`",
    "mysql": "install the MySQL client tools",
    "kubectl": "install kubectl and make sure your kubeconfig points at the cluster",
    "terraform": "install Terraform (or use `tofu`)",
    "aws": "install the AWS CLI v2 and configure credentials",
    "docker": "install Docker and make sure the daemon is running",
    "neonctl": "install the Neon CLI: `npm i -g neonctl` and run `neonctl auth`",
    "git": "install git",
}


class CommandError(RuntimeError):
    def __init__(self, argv: Sequence[str], code: int, stderr: str):
        self.argv, self.code, self.stderr = list(argv), code, stderr
        super().__init__(f"{argv[0]} exited {code}: {stderr.strip()[:400]}")


def run(argv: Sequence[str], cwd: str | None = None, env: Mapping[str, str] | None = None,
        input: str | None = None, timeout: float = 600, check: bool = True) -> subprocess.CompletedProcess:
    """Run a command without a shell. Raises CommandError on failure when check=True."""
    if shutil.which(argv[0]) is None and not os.path.isabs(argv[0]):
        hint = TOOL_HINTS.get(os.path.basename(argv[0]))
        raise CommandError(argv, 127, f"{argv[0]} not found on PATH" + (f"; {hint}" if hint else ""))
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


_REDACT = [
    (re.compile(r"(\b[a-z][a-z0-9+.-]*://[^:/@\s]+:)([^@\s]+)(@)", re.I), r"\1***\3"),        # scheme://user:pass@
    (re.compile(r"(\s-p)(?!\s)(\S+)"), r"\1***"),                                                # mysql -pSECRET
    (re.compile(r"(--password[= ])(\S+)", re.I), r"\1***"),
    (re.compile(r"\b([A-Z0-9_]*(?:PASSWORD|PASSWD|SECRET|TOKEN|API_KEY)[A-Z0-9_]*=)(\S+)"), r"\1***"),
]


def redact(text: str) -> str:
    """Mask credentials before a command is stored, logged or sent to Slack."""
    for rx, rep in _REDACT:
        text = rx.sub(rep, text)
    return text
