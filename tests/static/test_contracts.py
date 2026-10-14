"""Focused packaging contracts; no privileged runtime or network operations."""
import ast
import importlib.util
import json
from pathlib import Path
import re
import shutil
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[2]
spec = importlib.util.spec_from_file_location("build_tool", ROOT / "scripts/build.py")
build = importlib.util.module_from_spec(spec)
spec.loader.exec_module(build)
PUBLIC_FILES = {
    "LICENSE", "LICENSES/Apache-2.0.txt", "THIRD_PARTY_NOTICES.md", "README.md",
    "docs/design.md", "docs/security-model.md", "docs/compatibility.md",
    "helper/proc-mount-helper.c", "patches/proc-transfer.patch",
    "build/Dockerfile", "build/sources.lock.json", "scripts/build.py",
    "tests/runtime/verify.c", "tests/runtime/verify-sys.py", "tests/runtime/verify.sh",
    "tests/runtime/stress-proc.py", "tests/runtime/helper-rejections.py", "tests/static/test_contracts.py",
    ".gitignore", ".dockerignore", ".github/workflows/test.yml",
}


class Contracts(unittest.TestCase):
    def test_baseline_and_build_pins(self):
        lock = build.load_lock()  # Validates immutable baseline hashes, digest and revisions.
        dockerfile = (ROOT / "build/Dockerfile").read_text()
        command = build.build_command(lock, Path("artifacts"))
        args = dict(command[i + 1].split("=", 1) for i, value in enumerate(command)
                    if value == "--build-arg")
        declared = set(re.findall(r"^ARG (\w+)$", dockerfile, re.M))
        self.assertEqual(declared, set(args))
        self.assertEqual(args["BUILDER_IMAGE"], lock["builder"])
        self.assertIn("FROM ${BUILDER_IMAGE} AS build", dockerfile)
        self.assertIn('go install "${PROTOC_GEN_GO}"', dockerfile)
        for name, argument in build.COMPONENT_ARGS.items():
            component = lock["components"][name]
            self.assertEqual(args[argument], component["revision"])
            component_name = "sysbox" if name == "root" else "sysbox-" + name
            self.assertEqual(component["repository"],
                             "https://github.com/nestybox/" + component_name + ".git")
            revision_check = 'git rev-parse HEAD' if name == "root" else f'git -C {component_name} rev-parse HEAD'
            self.assertIn(f'"$({revision_check})" = "${argument}"', dockerfile)
        self.assertIn(f'--branch {lock["upstream_tag"]} {lock["components"]["root"]["repository"]}', dockerfile)
        self.assertIn("git submodule update --init --recursive", dockerfile)
        self.assertLess(dockerfile.index("make -C /src/sysbox/sysbox-ipc"),
                        dockerfile.index("go build"))
        self.assertNotIn("--platform", command)
        self.assertIn("linux/arm64", build.build_command(lock, Path("artifacts"), "linux/arm64"))
        self.assertEqual(command[-1], ".")

    def test_export_manifest(self):
        lock = build.load_lock()
        with tempfile.TemporaryDirectory() as work:
            output = Path(work)
            # Minimal ELF headers let us exercise metadata without building or executing binaries.
            header = bytearray(20)
            header[:4] = b"\x7fELF"
            header[5] = 1
            header[18:20] = (183).to_bytes(2, "little")
            for name in ("sysbox-fs", "proc-mount-helper"):
                (output / name).write_bytes(header + name.encode())
            record = build.manifest(lock, output)
            self.assertEqual(record["architecture"], "arm64")
            self.assertEqual(set(record["output_sha256"]), {"sysbox-fs", "proc-mount-helper"})
            for name, digest in record["output_sha256"].items():
                self.assertEqual(digest, build.sha256(output / name))
            self.assertNotIn(work, json.dumps(record))
            self.assertNotIn(str(ROOT), json.dumps(record))
            header[18:20] = (62).to_bytes(2, "little")
            (output / "proc-mount-helper").write_bytes(header)
            with self.assertRaisesRegex(ValueError, "different architectures"):
                build.manifest(lock, output)

    def test_public_content_scope(self):
        # Inspect publication candidates only; do not open private agent or credential directories.
        result = subprocess.run(["git", "ls-files", "--cached", "--others", "--exclude-standard", "-z"],
                                cwd=ROOT, check=True, capture_output=True)
        names = set(result.stdout.decode().strip("\0").split("\0"))
        self.assertEqual(names, PUBLIC_FILES)
        forbidden = [r"/(?:home|Users)/", r"https?://[^\s/]*\.(?:internal|local)(?:/|\b)",
                     r"\b10(?:\.\d{1,3}){3}\b", r"\b192\.168(?:\.\d{1,3}){2}\b",
                     r"\b172\.(?:1[6-9]|2\d|3[01])(?:\.\d{1,3}){2}\b",
                     r"-----BEGIN (?:OPENSSH|RSA|EC|PRIVATE).*KEY-----",
                     r"[s]ystemctl\s", r"[s]ervices\.sysbox", r"[t]alosctl\s",
                     r"[d]ocker:[^\s]*dind", r"[c]onfig\.sh\s+[^\n]*--(?:url|token)"]
        for name in names:
            path = ROOT / name
            self.assertFalse(path.is_symlink(), name)
            data = path.read_bytes()
            self.assertFalse(data.startswith(b"\x7fELF"), name)
            content = data.decode("utf-8")
            for pattern in forbidden:
                self.assertIsNone(re.search(pattern, content), name)
        # A bounded file set excludes OS deployment, orchestration, credentials and raw evidence.

    def test_build_context_allowlist(self):
        rules = (ROOT / ".dockerignore").read_text().splitlines()
        self.assertEqual(rules[0], "**")
        included = {rule[1:] for rule in rules[1:] if rule.startswith("!")}
        copied = set(re.findall(r"^COPY (?!\-\-)(\S+) ",
                                (ROOT / "build/Dockerfile").read_text(), re.M))
        self.assertEqual(copied, {"helper/proc-mount-helper.c", "patches/proc-transfer.patch"})
        expected = copied | {"build/Dockerfile", "build/", "helper/", "patches/"}
        self.assertEqual(included, expected)
        self.assertTrue(all(not any(c in rule for c in "*?") for rule in included))
        # Documents, tests, git metadata and output cannot enter the compilation context.

    def test_script_syntax(self):
        subprocess.run(["bash", "-n", str(ROOT / "tests/runtime/verify.sh")], check=True)
        for name in PUBLIC_FILES:
            if name.endswith(".py"):
                ast.parse((ROOT / name).read_text(), filename=name)

    def test_runtime_runner_contract(self):
        script = (ROOT / "tests/runtime/verify.sh").read_text()
        original = ('bwrap --die-with-parent --unshare-all --share-net \\\n'
                    '  --ro-bind / / --dev-bind /dev /dev --proc /proc -- /bin/true')
        self.assertIn(original, script)
        # Invalid/missing operator inputs must stop before compilation or bwrap execution.
        for arguments in ([], ["pid:[1]"], ["invalid", "user:[1]"]):
            result = subprocess.run(["bash", str(ROOT / "tests/runtime/verify.sh"), *arguments],
                                    capture_output=True, timeout=5)
            self.assertNotEqual(result.returncode, 0)
        self.assertNotIn("1001", script)
        self.assertNotIn("apt-get", script)

    @unittest.skipUnless(shutil.which("cc"), "C compiler unavailable")
    def test_compile_and_invalid_launch(self):
        with tempfile.TemporaryDirectory() as work:
            for source, name in (("helper/proc-mount-helper.c", "helper"),
                                 ("tests/runtime/verify.c", "verify")):
                subprocess.run(["cc", "-O2", "-Wall", "-Wextra", "-Werror",
                                str(ROOT / source), "-o", str(Path(work) / name)], check=True)
            # No inherited contract FDs: direct invocation is unauthorized, even under root.
            result = subprocess.run([str(Path(work) / "helper"), "0", "0", "0"],
                                    close_fds=True, capture_output=True, timeout=5)
            self.assertNotEqual(result.returncode, 0)
            self.assertIn(b"proc-transfer:", result.stderr)
            self.assertTrue(b"root launcher" in result.stderr or b"namespace types" in result.stderr)


if __name__ == "__main__":
    unittest.main()
