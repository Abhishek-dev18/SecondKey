"""kubectl and terraform are stubbed with small fake binaries on PATH."""

import os
import stat

import yaml

from secondkey.cli import main as cli
from secondkey.snapshots.k8s import clean, get_args
from secondkey.store import Store

from .conftest import call_hook, decision_of

DEPLOY = """apiVersion: apps/v1
kind: Deployment
metadata:
  name: payments
  namespace: prod
  uid: 123
  resourceVersion: "999"
  creationTimestamp: "2026-01-01T00:00:00Z"
  annotations:
    kubectl.kubernetes.io/last-applied-configuration: "{}"
spec:
  replicas: 3
status:
  readyReplicas: 3
"""


def fake_bin(dirpath, name, script):
    p = dirpath / name
    p.write_text("#!/bin/sh\n" + script)
    p.chmod(p.stat().st_mode | stat.S_IEXEC)


def test_get_args():
    assert get_args(["delete", "deploy", "api", "-n", "prod", "--force", "--grace-period", "0"]) == \
        ["get", "deploy", "api", "-n", "prod", "-o", "yaml"]
    assert get_args(["delete", "-f", "app.yaml", "--wait=false"]) == ["get", "-f", "app.yaml", "-o", "yaml"]


def test_clean_strips_volatile_fields():
    doc = clean(yaml.safe_load(DEPLOY))
    item = doc["items"][0]
    assert "status" not in item and "uid" not in item["metadata"] and "annotations" not in item["metadata"]
    assert item["spec"]["replicas"] == 3


def test_kubectl_delete_snapshot_and_restore(tmp_path, monkeypatch):
    bin_dir = tmp_path / "bin"
    bin_dir.mkdir()
    log = tmp_path / "kubectl.log"
    fake_bin(bin_dir, "kubectl", f'echo "$@" >> {log}\nif [ "$1" = get ]; then cat <<\'EOF\'\n{DEPLOY}EOF\nfi\n'
                                 f'if [ "$1" = apply ]; then echo "deployment.apps/payments created"; fi\n')
    monkeypatch.setenv("PATH", f"{bin_dir}{os.pathsep}{os.environ['PATH']}")
    cmd = "kubectl delete deploy payments -n prod"
    r = call_hook(cmd, tmp_path)
    assert "Deployment/payments" in r["permissionDecisionReason"]
    rid = r["permissionDecisionReason"].split("(request ")[1].split(")")[0]
    cli(["approve", rid])
    assert decision_of(call_hook(cmd, tmp_path)) == "allow"
    snap = Store().snapshots_for(rid)[0]
    saved = yaml.safe_load(open(os.path.join(snap.path, "resources.yaml")))
    assert saved["items"][0]["metadata"]["name"] == "payments"
    assert cli(["undo", snap.id, "--yes"]) == 0
    assert "apply -f" in log.read_text()


def test_terraform_destroy_is_backed_up_and_undo_is_honest(tmp_path, monkeypatch, capsys):
    bin_dir = tmp_path / "bin"
    bin_dir.mkdir()
    fake_bin(bin_dir, "terraform", 'if [ "$1" = state ] && [ "$2" = pull ]; then echo \'{"version":4,"resources":[{"type":"aws_s3_bucket"}]}\'; fi\n')
    monkeypatch.setenv("PATH", f"{bin_dir}{os.pathsep}{os.environ['PATH']}")
    r = call_hook("terraform destroy -auto-approve", tmp_path)
    assert "can't be un-destroyed" in r["permissionDecisionReason"]
    rid = r["permissionDecisionReason"].split("(request ")[1].split(")")[0]
    cli(["approve", rid])
    call_hook("terraform destroy -auto-approve", tmp_path)
    snap = Store().snapshots_for(rid)[0]
    assert os.path.exists(os.path.join(snap.path, "terraform.tfstate"))
    assert cli(["undo", snap.id, "--yes"]) == 1          # refuses to fake it
    assert "terraform apply" in capsys.readouterr().err
