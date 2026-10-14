"""Run as the caller inside a provisioned Sysbox container; exercise proc mounts and nsenter reaping."""
import concurrent.futures
import subprocess
import time

command = [
    "bwrap", "--die-with-parent", "--unshare-all", "--share-net",
    "--ro-bind", "/", "/", "--dev-bind", "/dev", "/dev", "--proc", "/proc",
    "--", "/bin/true",
]

def check(index):
    subprocess.run(["/bin/cat", "/proc/uptime"], check=True, capture_output=True, timeout=30)
    result = subprocess.run(command, capture_output=True, timeout=30)
    if result.returncode:
        return index, result.returncode, result.stderr.decode(errors="replace")
    return None

started = time.monotonic()
with concurrent.futures.ThreadPoolExecutor(max_workers=8) as pool:
    failures = [result for result in pool.map(check, range(500)) if result]
for failure in failures[:10]:
    print("FAIL", failure)
assert not failures, f"{len(failures)} proc mounts failed"
print(f"PASS 500 unchanged bwrap proc mounts, 8 workers, concurrent nsenter/FUSE reaping; {time.monotonic()-started:.1f}s")
