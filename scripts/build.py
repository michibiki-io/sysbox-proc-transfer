#!/usr/bin/env python3
"""Build the paired artifacts using only Docker/buildx and Python's standard library."""
import argparse
import hashlib
import json
from pathlib import Path
import re
import subprocess
import tempfile

ROOT = Path(__file__).resolve().parents[1]
LOCK = ROOT / "build/sources.lock.json"
COMPONENT_ARGS = {"root": "ROOT_REV", "fs": "FS_REV", "runc": "RUNC_REV",
                  "ipc": "IPC_REV", "libs": "LIBS_REV", "fuse": "FUSE_REV"}


def sha256(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def load_lock():
    lock = json.loads(LOCK.read_text())
    if lock["schema_version"] != 1 or set(lock["components"]) != set(COMPONENT_ARGS):
        raise ValueError("unsupported source lock")
    for component in lock["components"].values():
        if not re.fullmatch(r"[0-9a-f]{40}", component["revision"]):
            raise ValueError("source revision must be an immutable commit")
    if not re.fullmatch(r"golang:1\.27\.2-trixie@sha256:[0-9a-f]{64}", lock["builder"]):
        raise ValueError("builder must be digest pinned")
    if lock["generator"] != "github.com/golang/protobuf/protoc-gen-go@v1.3.5":
        raise ValueError("legacy IPC generator required")
    for name, digest in lock["source_sha256"].items():
        if sha256(ROOT / name) != digest:
            raise ValueError(f"source integrity mismatch: {name}")
    return lock


def build_command(lock, output, platform=None):
    command = ["docker", "buildx", "build", "--file", "build/Dockerfile",
               "--target", "export", "--output", f"type=local,dest={output}"]
    if platform:
        command += ["--platform", platform]
    arguments = {"BUILDER_IMAGE": lock["builder"], "PROTOC_GEN_GO": lock["generator"]}
    arguments.update({argument: lock["components"][name]["revision"]
                      for name, argument in COMPONENT_ARGS.items()})
    for name, value in arguments.items():
        command += ["--build-arg", f"{name}={value}"]
    return command + ["."]


def elf_architecture(path):
    with path.open("rb") as stream:
        header = stream.read(20)
    if len(header) < 20 or header[:4] != b"\x7fELF" or header[5] not in (1, 2):
        raise ValueError("expected an ELF output")
    machine = int.from_bytes(header[18:20], "little" if header[5] == 1 else "big")
    return {183: "arm64", 62: "amd64"}.get(machine, f"elf-machine-{machine}")


def manifest(lock, output):
    names = ("sysbox-fs", "proc-mount-helper", "sysfs-mount-helper")
    architectures = {elf_architecture(output / name) for name in names}
    if len(architectures) != 1:
        raise ValueError("paired outputs have different architectures")
    inputs = sorted(set(lock["source_sha256"]) |
                    {"build/Dockerfile", "build/sources.lock.json", "scripts/build.py", "tests/upstream/proc_policy_test.go"})
    return {"schema_version": 1, "architecture": architectures.pop(),
            "sources": lock["components"], "builder": lock["builder"],
            "generator": lock["generator"],
            "input_sha256": {name: sha256(ROOT / name) for name in inputs},
            "output_sha256": {name: sha256(output / name) for name in names}}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, default=Path("dist"))
    parser.add_argument("--platform", help="one Docker target platform; default is native")
    args = parser.parse_args()
    if args.platform and ("," in args.platform or not re.fullmatch(r"linux/[a-z0-9]+(?:/[a-z0-9]+)?", args.platform)):
        parser.error("provide one Linux platform")
    lock = load_lock()
    output = args.output.resolve()
    output.mkdir(parents=True, exist_ok=True)
    # Export to a fresh directory so failed builds cannot mix artifacts from different builds.
    with tempfile.TemporaryDirectory(prefix="proc-transfer-build-") as work:
        staging = Path(work)
        subprocess.run(build_command(lock, staging, args.platform), cwd=ROOT, check=True)
        record = manifest(lock, staging)
        for name in record["output_sha256"]:
            (output / name).write_bytes((staging / name).read_bytes())
            (output / name).chmod(0o755)
        (output / "manifest.json").write_text(json.dumps(record, indent=2, sort_keys=True) + "\n")
    print("Built paired artifacts and manifest.json")


if __name__ == "__main__":
    main()
