#!/usr/bin/env bash
set -euo pipefail
[[ $# == 2 ]] || { echo 'Usage: verify.sh HOST_PID_NAMESPACE HOST_USER_NAMESPACE' >&2; exit 2; }
host_pid=$1
host_user=$2
[[ $host_pid =~ ^pid:\[[0-9]+\]$ && $host_user =~ ^user:\[[0-9]+\]$ ]]
[[ $(id -u) != 0 ]]
[[ $(readlink /proc/self/ns/user) != "$host_user" ]]
script_dir=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
work=$(mktemp -d)
trap 'rm -rf -- "$work"' EXIT
printf 'Outer user namespace: %s; host user namespace: %s\n' "$(readlink /proc/self/ns/user)" "$host_user"
cat /proc/self/uid_map /proc/self/gid_map
cc -O2 -Wall -Wextra -Werror "$script_dir/verify.c" -o "$work/verify"
"$work/verify" capture "$work/proc-manifest"
/usr/bin/python3 "$script_dir/verify-sys.py" capture "$work/sys-manifest"
bwrap --die-with-parent --unshare-all --share-net \
  --ro-bind / / --dev-bind /dev /dev --proc /proc -- /bin/true
echo 'PASS original caller bwrap --proc command'
bwrap --die-with-parent --unshare-all --share-net \
  --ro-bind / / --dev-bind /dev /dev --proc /proc --cap-add CAP_SYS_ADMIN -- \
  "$work/verify" sandbox "$work/proc-manifest" "$host_pid"
bwrap --die-with-parent --unshare-all --share-net \
  --ro-bind / / --dev-bind /dev /dev --ro-bind /sys /sys --proc /proc --cap-add CAP_SYS_ADMIN -- \
  /usr/bin/python3 "$script_dir/verify-sys.py" check "$work/sys-manifest"
bwrap --die-with-parent --unshare-all --share-net \
  --ro-bind / / --dev-bind /dev /dev --tmpfs /tmp \
  --ro-bind "$work" "$work" \
  --dir /tmp/proc --proc /proc --cap-add CAP_SYS_ADMIN -- \
  "$work/verify" readonly /tmp/proc "$work/proc-manifest"

# Actual nonleader notification/helper path, with a separate observer in the
# requester's Mount namespace and an unchanged leader Mount namespace.
# Keep the outer proc mount attributes for the captured protection policy;
# the unchanged readonly-root bwrap invocation is verified above.
cc -O2 -Wall -Wextra -Werror -pthread "$script_dir/thread-proc.c" -o "$work/thread-proc"
for mode in readwrite readonly; do
  bwrap --die-with-parent --unshare-all --share-net \
    --bind / / --dev-bind /dev /dev --tmpfs /tmp \
    --ro-bind "$work" "$work" --cap-add CAP_SYS_ADMIN -- \
    "$work/thread-proc" /tmp/thread-proc "$mode"
done
