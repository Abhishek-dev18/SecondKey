"""AWS snapshots: EBS volumes, RDS instances and S3 prefixes, via the AWS CLI."""

from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any

from ..classify import Action
from ..policy import Policy
from ..store import Snapshot
from ..util import CommandError, human_size, run
from .base import Provider, RestoreError, SnapshotUnavailable


def _aws(target: dict[str, Any], *args: str, timeout: float = 120) -> str:
    argv = ["aws", *args]
    for key in ("region", "profile"):
        if target.get(key):
            argv += [f"--{key}", target[key]]
    try:
        return run(argv, timeout=timeout).stdout
    except CommandError as e:
        raise SnapshotUnavailable(f"aws {' '.join(args[:2])} failed: {e.stderr.strip()[:300]}") from e


def _s3_size(target: dict[str, Any]) -> tuple[int, int]:
    out = _aws(target, "s3", "ls", target["uri"], "--recursive", "--summarize", timeout=600)
    n = re.search(r"Total Objects:\s*(\d+)", out)
    b = re.search(r"Total Size:\s*(\d+)", out)
    return (int(n.group(1)) if n else 0), (int(b.group(1)) if b else 0)


class AWSProvider(Provider):
    name = "aws"

    def plan(self, action: Action, policy: Policy) -> list[str]:
        t = action.target
        if t["kind"] == "ebs":
            v = json.loads(_aws(t, "ec2", "describe-volumes", "--volume-ids", t["volume_id"], "--output", "json"))["Volumes"][0]
            return [f"EBS {t['volume_id']}: {v['Size']} GiB {v['VolumeType']} in {v['AvailabilityZone']} (an EBS snapshot is taken first)"]
        if t["kind"] == "rds":
            d = json.loads(_aws(t, "rds", "describe-db-instances", "--db-instance-identifier", t["instance"], "--output", "json"))["DBInstances"][0]
            return [f"RDS {t['instance']}: {d['Engine']} {d['DBInstanceClass']}, {d['AllocatedStorage']} GiB "
                    "(a manual DB snapshot is taken first; this can take several minutes)"]
        n, size = _s3_size(t)
        if size > policy.max_file_snapshot_bytes:
            raise SnapshotUnavailable(f"{human_size(size)} in {t['uri']} is over the {human_size(policy.max_file_snapshot_bytes)} file snapshot limit")
        return [f"{t['uri']}: {n:,} objects, {human_size(size)} (downloaded locally first)"]

    def take(self, action: Action, dest: Path, policy: Policy) -> tuple[str, dict[str, Any]]:
        t, sid = action.target, dest.name
        if t["kind"] == "ebs":
            v = json.loads(_aws(t, "ec2", "describe-volumes", "--volume-ids", t["volume_id"], "--output", "json"))["Volumes"][0]
            snap = json.loads(_aws(t, "ec2", "create-snapshot", "--volume-id", t["volume_id"], "--description",
                                   f"secondkey {sid} before delete-volume", "--output", "json"))
            return f"EBS snapshot {snap['SnapshotId']} of {t['volume_id']}", {
                **t, "snapshot_id": snap["SnapshotId"], "az": v["AvailabilityZone"], "volume_type": v["VolumeType"], "size": v["Size"]}
        if t["kind"] == "rds":
            ident = f"secondkey-{sid.replace('_', '-')}"
            _aws(t, "rds", "create-db-snapshot", "--db-instance-identifier", t["instance"], "--db-snapshot-identifier", ident,
                 "--output", "json")
            _aws(t, "rds", "wait", "db-snapshot-available", "--db-snapshot-identifier", ident, timeout=840)
            return f"RDS snapshot {ident} of {t['instance']}", {**t, "db_snapshot": ident}
        n, size = _s3_size(t)
        if size > policy.max_file_snapshot_bytes:
            raise SnapshotUnavailable("S3 prefix is over the file snapshot limit")
        local = dest / "s3"
        local.mkdir()
        if t.get("recursive"):
            _aws(t, "s3", "sync", t["uri"], str(local), "--only-show-errors", timeout=3600)
        else:
            _aws(t, "s3", "cp", t["uri"], str(local / Path(t["uri"]).name), "--only-show-errors", timeout=3600)
        return f"{t['uri']} ({n:,} objects, {human_size(size)})", {**t, "objects": n, "bytes": size}

    def describe_restore(self, snap: Snapshot, mode: str | None = None) -> list[str]:
        m = snap.meta
        if m["kind"] == "ebs":
            return [f"create a new {m['size']} GiB {m['volume_type']} volume from {m['snapshot_id']} in {m['az']}",
                    "it gets a new volume id; attach it to the instance yourself"]
        if m["kind"] == "rds":
            return [f"restore DB instance {m['instance']} from snapshot {m['db_snapshot']} (takes several minutes)",
                    "instance class and networking use defaults unless you change them afterwards"]
        return ([f"recreate bucket {m['uri'].split('/')[2]}"] if m.get("bucket_delete") else []) + \
               [f"upload {m['objects']:,} saved objects back to {m['uri']}"]

    def restore(self, snap: Snapshot, mode: str | None = None, force: bool = False) -> list[str]:
        m = snap.meta
        try:
            if m["kind"] == "ebs":
                v = json.loads(_aws(m, "ec2", "create-volume", "--snapshot-id", m["snapshot_id"], "--availability-zone", m["az"],
                                    "--volume-type", m["volume_type"], "--output", "json"))
                return [f"new volume {v['VolumeId']} created from {m['snapshot_id']} in {m['az']}; attach it to the instance"]
            if m["kind"] == "rds":
                _aws(m, "rds", "restore-db-instance-from-db-snapshot", "--db-instance-identifier", m["instance"],
                     "--db-snapshot-identifier", m["db_snapshot"], "--output", "json")
                return [f"RDS instance {m['instance']} is being restored from {m['db_snapshot']} (check the console for status)"]
            local = Path(snap.path) / "s3"
            if m.get("bucket_delete"):
                bucket = "s3://" + m["uri"].split("/")[2]
                run(["aws", "s3", "mb", bucket, *(["--region", m["region"]] if m.get("region") else [])], check=False)
            if m.get("recursive"):
                _aws(m, "s3", "sync", str(local), m["uri"], "--only-show-errors", timeout=3600)
            else:
                _aws(m, "s3", "cp", str(next(local.iterdir())), m["uri"], "--only-show-errors", timeout=3600)
            return [f"{m['objects']:,} objects uploaded back to {m['uri']}"]
        except SnapshotUnavailable as e:
            raise RestoreError(str(e)) from e
