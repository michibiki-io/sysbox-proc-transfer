# Runtime regressions / 実行時回帰検査

## Contents / 目次

- [English](#english): [Actual Sysbox path](#actual-sysbox-path), [Deterministic checkpoints](#deterministic-checkpoints), [Proc protection baseline](#proc-protection-baseline), [Portable sysfs oracle](#portable-sysfs-oracle)
- [日本語](#日本語): [実際の Sysbox 経路](#実際の-sysbox-経路), [決定的な確認地点](#決定的な確認地点), [proc 保護の事前記録](#proc-保護の事前記録), [移植可能な sysfs 検査](#移植可能な-sysfs-検査)

- [New sysfs and network checks](#new-sysfs-and-network-checks) / [新規 sysfs と Network の検査](#新規-sysfs-と-network-の検査)

## English

### Actual Sysbox path

The historical binary pair passed the arm64 validation recorded in [compatibility](../../docs/compatibility.md). In the provisioned arm64 Sysbox environment, run as the existing non-root caller:

```sh
bash tests/runtime/verify.sh "$HOST_PID_NAMESPACE" "$HOST_USER_NAMESPACE"
python3 tests/runtime/stress-proc.py
```

The unchanged bwrap command and existing policy checks remain. The runner also builds `thread-proc.c` and runs read-write/read-only cases. It asserts TID != TGID and different leader/requester Mount namespaces. The syscall takes the actual Sysbox listener and production helper path; there is no synthetic listener or test helper in this probe. A separate observer in the requester's namespace checks sandbox PID identity, every captured outer proc submount's identity/read-only policy, masks and detach locks. The leader's target must remain unchanged. The read-write case requires a writable outer `/proc` root; registered read-only submount protections remain enabled. The probe fails if read-only inheritance prevents a read-write root rather than clearing that policy. Dependencies must already be installed; no host provisioning is performed.

### Proc protection baseline

Issue #7 changes the verifier only. `verify.sh` captures the outer `/proc` baseline before bwrap and passes that same file to `sandbox` and `readonly`. The readonly invocation is now `verify readonly TARGET MANIFEST`; capture and sandbox arguments are unchanged. Keep `verify.c` and `verify.sh` from the same checksum-locked revision and recapture on each run; old manifests are rejected.

The fixed catalog has seven required entries: `uptime`, `bus`, `fs`, `irq`, `interrupts`, `keys` and `timer_list`, including the three required masks. `/proc/keys` depends on `CONFIG_KEYS` but deliberately remains required along with the existing masks: an absent mask cannot satisfy the existing protection validation, so a kernel without it fails this fixture. This does not imply that every valid kernel has `/proc/keys`. Only the four optional entries `asound`, `sysrq-trigger`, `swaps` and `sys` may be absent. `asound` depends on `CONFIG_SND_PROC_FS`; Linux v6.18 builds `sysrq.o` only with `CONFIG_MAGIC_SYSRQ` ([tty Makefile](https://github.com/torvalds/linux/blob/v6.18/drivers/tty/Makefile)), and `swapfile.o` only with `CONFIG_SWAP` ([mm Makefile](https://github.com/torvalds/linux/blob/v6.18/mm/Makefile)); [swapfile.c](https://github.com/torvalds/linux/blob/v6.18/mm/swapfile.c) registers `/proc/swaps`. The [proc Makefile](https://github.com/torvalds/linux/blob/v6.18/fs/proc/Makefile) builds `proc_sysctl.o` only with `CONFIG_PROC_SYSCTL`; the disabled `proc_sys_init` stub in [internal.h](https://github.com/torvalds/linux/blob/v6.18/fs/proc/internal.h) leaves `/proc/sys` potentially absent. No ALSA, module loading or host reconfiguration is required. Capture writes one newline-terminated row per candidate: `NAME present DEV INO FLAGS` (unsigned decimal values), or `NAME absent` only on stat ENOENT for an optional entry. An optional entry still needs an explicit row; omitting it fails. Other source inspection errors fail before opening the output file.

Both consumers parse the entire manifest before mounting or attempting detach/remount operations. Input is limited to 4096 bytes, 255 bytes per row excluding newline, and exactly 11 unique catalog rows. Repeated, leading and trailing ASCII spaces are accepted within these bounds; capture emits canonical single-space separators. Empty, incomplete, duplicate, unknown, malformed, NUL-containing, overlong, unterminated and numerically overflowing input fails. All required entries and the existing minimum of three checked protections remain enforced. Expected absence must still be observed as stat ENOENT in each consumer; successful lookup, permission errors and other inspection failures fail. Previously present entries must remain observable.

Readonly requires ST_RDONLY on the new root and every present entry. Sandbox retains PID/User namespace reporting, PID isolation, seccomp and observer capability checks, present-entry device/inode identity, captured read-only policy, detach denial, read-only remount denial and the three required empty masks. An absent row never ends inspection of later entries. The original non-root bwrap invocation and caller privileges are unchanged.

Run the unprivileged focused regression separately:

```sh
python3 tests/static/test_proc_verifier.py -v
```

It compiles the actual `verify.c` entry points with syscall stubs in `tests/unit/proc-verifier.c`; the shipped runtime verifier has no bypass mode. It exercises all 16 present/absent combinations of the four optional entries through both consumers and capture roundtrips, capture errors for each optional, malformed input before any mount operations, inspection failures and lost/writable protections, including every original check after absent `asound`. Downstream checksum consumers can fetch these three files in the same relative layout and execute the Python file without the build harness. `verify.sh` additionally requires `verify-sys.py` and `thread-proc.c` as before.

These simulated checks do not establish real mount behavior. Run the corrected `verify.sh` in the authorized disposable Sysbox environment and report passed, failed and unrun checks for that exact revision. On 2026-10-16 the corrected four-optional-entry runner passed in a disposable arm64/Linux 7.1.0/Sysbox 0.7.1/bubblewrap 0.9.0 environment as UID/GID 1001 with CapEff 0, NoNewPrivs 1 and seccomp mode 2/filter count 1. The original bwrap, sandbox protections, existing sys binds, recursive readonly and nonleader RW/RO checks passed. All four optional entries (`asound`, `sysrq-trigger`, `swaps` and `sys`) were present on that kernel; absent cases are covered only by the focused simulation, while runtime validation on an actual absent-entry kernel and real amd64/Talos 6.18.18 remains unrun and is tracked downstream. CI status is recorded against each PR head. Historical runtime successes above are separate evidence.

### Deterministic checkpoints

This second harness runs from trusted parent-user root, with Python 3.12+, namespace access and `CAP_SYS_PTRACE` for `pidfd_getfd`. It creates only its own sandbox through an operator-provided exec prefix. It never alters daemon configuration. Compile the two test binaries for the runtime architecture. The requester binary must be visible at the supplied path inside the test container; the test helper runs only in the trusted launcher environment:

```sh
cc -O2 -Wall -Wextra -Werror tests/unit/helper-checkpoint.c -o "$CHECKPOINT_HELPER"
cc -O2 -Wall -Wextra -Werror -pthread tests/runtime/checkpoint-requester.c -o "$CHECKPOINT_REQUESTER"
python3 tests/runtime/checkpoints.py \
  --outer-pid "$OUTER_INIT_PID" --uid "$CALLER_UID" --gid "$CALLER_GID" \
  --helper "$CHECKPOINT_HELPER" --requester "$CHECKPOINT_REQUESTER" \
  --requester-kind nonleader --stage staging --action thread-exit \
  --exec nsenter --target "$OUTER_INIT_PID" \
    --user --mount --pid --net --ipc --uts --cgroup --root --wd \
    --setuid "$CALLER_UID" --setgid "$CALLER_GID" \
    /usr/bin/env PATH=/usr/bin:/bin
```

Use a dedicated container and dynamically obtained mapped caller IDs; do not hard-code UID/GID mappings. Actor control uses private FIFOs in the disposable sandbox and does not depend on exec-prefix stdin. The fixture must start from a trusted launcher without an inherited notification listener: Linux rejects a second `NEW_LISTENER` on a thread with `EBUSY`. The namespace-entry prefix above joins the dedicated container without inheriting its runtime filter; it changes no running process or daemon policy. Only this direct-helper fixture uses that prefix. The actual Sysbox path above retains the production seccomp profile. This test helper includes the production C source with pauses around its actual pidfd polls. **Never deploy the checkpoint helper as the production helper.** Its control socket is test-only and it is excluded from the paired production export. The requester uses a real `getpid` seccomp notification copied through `pidfd_getfd`; this is direct-helper coverage, not evidence for the actual Sysbox daemon dispatch. The Go upstream tests separately exercise the production launch function with a real notification.

Run this complete matrix (32 invocations), one fresh sandbox per case:

| Requester | Stages | Actions |
|---|---|---|
| leader | launch, staging, transfer, commit | interrupt, thread-exit, process-exit, exec |
| nonleader | launch, staging, transfer, commit | interrupt, thread-exit, process-exit, exec |

`launch` verifies the harness pinning order and kernel invalidation after pinning; it creates no helper and checks no mutation. It does not call the production Go launch gate. The real-notification Go test separately checks that `runProcTransfer` does not invoke its launch callback for an invalid original ID. `staging` pauses before the first helper poll; `transfer` pauses before the final poll; `commit` pauses after the final successful poll. The signal-interrupted thread stays alive. Thread-only exit follows interruption and leaves another thread alive. Nonleader exit makes its thread pidfd readable; premature leader exit remains unreadable while the group survives, as verified by the local kernel test. A process-exit kills only the harness's pinned actor; an independent observer survives in its Mount namespace. Exec replaces the requester from another thread: nonleader pidfd becomes readable, leader pidfd remains live. A persistent sandbox supervisor keeps PID 1 alive in all cases.

At staging/transfer, detected exit must return ESRCH with unchanged target. Interrupt, leader thread-exit and leader exec at these stages must commit the protected tree while the original notification rejects a success response with ENOENT. At commit, all actions force a commit race; the surviving observer must confirm intended PID identity, all registered submount identities, masks, recursive read-only attributes and detach locks. The original invalid notification must reject success. Missing checkpoints, ioctl/namespace errors, observer failures and cleanup timeouts fail the test; there is no skip-to-pass fallback. Helpers must be reaped within 30 seconds after launch (25 second daemon limit plus 5 second observation allowance); the local unit suite separately tests the 20 second alarm and parent-death child cleanup. The harness closes its owned descriptors and kills only pinned, uniquely tagged actors/supervisor/observer.

The whole-process/thread exit cases before staging/transfer prove failure cleanup. The post-poll cases prove retained protection despite an allowed race. Notification validation and commit are not atomic; see [design](../../docs/design.md). Run the historical `helper-rejections.py` modes as well. Keep raw logs and namespace identifiers local; public evidence records only architecture, kernel/runtime versions and pass/fail outcomes.

### New sysfs and network checks

These checks require an already provisioned disposable Sysbox container and configured trusted sysfs helper. They retain the production listener. Install dependencies in the disposable image before testing. Place this repository at `/tmp/issue5-repo` in that image (the surviving observer uses that fixed test-only oracle path). Compile `thread-sysfs.c` outside the bwrap tmpfs, then bind both the executable and repository into its private `/tmp`:

```sh
cc -O2 -Wall -Wextra -Werror -pthread tests/runtime/thread-sysfs.c -o "$SYSFS_PROBE"
for net in shared-net new-net; do
  for mode in readwrite readonly; do
    bwrap --die-with-parent --unshare-all --share-net \
      --bind / / --dev-bind /dev /dev --tmpfs /tmp \
      --ro-bind /tmp/issue5-repo /tmp/issue5-repo \
      --ro-bind "$SYSFS_PROBE" "$SYSFS_PROBE" --cap-add CAP_SYS_ADMIN --cap-add CAP_NET_ADMIN -- \
      "$SYSFS_PROBE" /tmp/thread-sysfs "$mode" "$net"
  done
done
bwrap --die-with-parent --unshare-all \
  --bind / / --dev-bind /dev /dev --cap-add CAP_SYS_ADMIN --cap-add CAP_NET_ADMIN -- \
  /usr/bin/python3 tests/runtime/sysfs-interleave.py /sys
```

Also run the same four probe cases as inner UID/GID0 mapped to outer caller IDs:

```sh
unshare --user --map-root-user --mount --pid --fork -- \
  "$SYSFS_PROBE" /tmp/issue5-root-probe readwrite shared-net
```

Use a fresh caller-owned target path for each shared/new-net and RW/RO case and remove the empty leader-side directory afterward. Record `id`, uid_map/gid_map and capability/NNP/seccomp state within that same entry path. The unchanged bwrap fixture deliberately keeps its existing caller UID map; this additional probe covers the root mapping without changing that invocation. A `/dev/null` mask can become inaccessible under the mandatory recursive nodev floor: the observer requires unchanged identity and either empty reads or EACCES with nodev, never readable contents.

CAP_SYS_ADMIN and CAP_NET_ADMIN here are **child User namespace** capabilities for the surviving observer and its owned network fixtures, never outer Pod or initial-host capabilities. The fresh-Net nonleader creates `issue5-tid` only in its private Network and requires the leader’s interface membership and indices to remain unchanged. The nonleader probe checks a separate thread Mount/Network namespace, source identities, all security floors, detach/move and RO-remount denial. Its independent observer compares class/net and protected devices/virtual/net with netlink, per-interface ifindex/mtu, symlink targets, raw getdents and high-level enumeration. `sysfs-interleave.py` primes a nonzero offset on a shared directory handle in its own disposable child-owned parent Network, then repeatedly switches between two owned Network namespaces with different interface names/MTUs and shared-namespace positive/negative lookup and attribute priming. Only disposable fixture interfaces may be changed.

Use `tests/unit/sysfs-checkpoint.c`, `tests/runtime/checkpoint-sysfs.c` and `checkpoints.py --filesystem sysfs` for the same 32-case direct-helper race matrix. Bind `/tmp/issue5-repo` into that sandbox too. FD7 is Network. The synthetic notification remains a direct fixture, separate from the real mount probe. Use `helper-rejections.py --filesystem sysfs` for existing modes plus wrong-network, deeper-user and backing-symlink. The last mode calls the real backing helper directly: final `lo/subsystem` Readlink succeeds, while Lookup/Open through that link fail with ELOOP. Run `sysfs-write-policy.py` as outer mapped root and capable direct-child root, each allowing the script to create and prove ownership of a fresh private Network; it checks nobody Lookup/Getattr, write denial and unchanged MTU. A child UID map may start at outer UID0; the fixture requires a bounded map rather than mistaking that for initial-host User authority. No failed source acquisition may be skipped.

For complete policy coverage, provision the disposable container with non-default masked files, RO paths and a nested protected mount before registration, then compare all sources with the capable observer. Do not remove policy to make a probe pass. Test masked contents and write denial separately from missing paths. Compile the test-only `sysfs-failure-helper.c` with trusted `TEST_HELPER` and `TEST_TRIGGER` absolute paths and use it only in a separate disposable daemon. `sysfs-failures.py` opens the network directory before creating the task-owned switch, then requires EIO from raw getdents and high-level enumeration and unchanged target on failed actual mount. The switch must address the same task-owned file from the helper host view and caller container view. Do not change a consumer daemon.

Record outer/setup/inner maps, ownership, capability/NNP/seccomp/filter state, kernel/architecture/runtime versions, request flags and hashes of unpatched/patched binaries. The Linux 6.18.18-talos amd64 gate is deferred/unrun; supplemental arm64/Linux 7.1/bwrap 0.9 results are not Talos support. Existing proc and `/sys` bind acceptance remain independent. Rootful Docker/privileged child/kind smoke must be recorded as separate paths.

Combine network-nested protections with negative and rejected lookups: register an OCI mask on `/sys/devices/virtual/net/lo/ifalias` and a readonly self-bind on `lo/statistics` in the disposable container, then run `python3 tests/runtime/sysfs-dentry-protection.py` as the capable mapped direct-child observer in its own Mount namespace. It creates only its own transfer target, probes deeper User namespaces and a fresh child-owned Network whose loopback is renamed, then checks both original and transferred mount IDs/identities/floors and detach/remount denial. A separately configured task-only failure helper may use `--failure-switch /tmp/issue5-dentry-switch`; the switch must resolve to the same new task-owned file in helper and caller views. Failure must remain explicit EIO while protection dentries survive. Never run this with an existing consumer daemon or on host interfaces.

For setup-error injection in a disposable container configured with the test failure helper, run `python3 tests/runtime/sysfs-failures.py <task-switch-path> 2` (ENOENT) or `20` (ENOTDIR). Both require raw getdents and high-level enumeration to fail with EIO; a normal helper's genuinely absent resource must retain ENOENT. With no numeric argument the injected setup error is EIO. The switch is task-owned and removed in cleanup.

Virtual-net READDIR regenerates its byte stream for each request. Nonzero-offset continuation is consistent only in the same Network while the listing stays unchanged. Sharing a handle across Networks or changing the listing makes old byte cookies undefined: continuation can be empty, truncated or rejected with EIO. Rewind with `lseek(fd, 0, SEEK_SET)`/`rewinddir` before reading the new view. The shared-handle continuation check proves absence of foreign names only; after rewind, the fixture requires the complete current name set.

### Portable sysfs oracle

Issue #9 changes runtime tests only; production helpers, patches and the upstream ABI stay unchanged. Keep `sysfs_oracle.py` beside the four `sysfs-*.py` callers (`network`, `interleave`, `write-policy`, `dentry-protection`). Thread and checkpoint/lifecycle observers reach the same CLI through the existing repository bind; no runtime source rewriting is needed.

`RTM_GETLINK` in the observer's current Network independently supplies every interface name, ifindex and MTU. The owned virtual-only fixtures compare complete high-level and raw getdents sets in both `class/net` and `devices/virtual/net` with that snapshot. Additional default interfaces are allowed and all their metadata is checked. Only the exact `bonding_masters` entry may be excluded, only when it is a regular file and absent from the netlink interface set. Its presence is optional in either registered FUSE alias. Unknown entries, malformed types, symlinks, path/traversal errors and failed netlink observations fail; an interface named `bonding_masters` cannot hide as an attribute. Interface class symlinks, subsystem links, negative lookups and namespace/cache isolation remain checked. Hardware devices, interface counts and module loading are not prerequisites for these virtual-only fixtures.

Raw enumeration parses every bounded record and continues to EOF, including after rewind. A shared FD's stale nonzero cookie may yield a partial/empty list or EIO; every returned entry must still belong to the current Network, and other errors such as EINVAL fail. Interleave preserves parent veth/shared-FD priming, controlled names/MTUs and absent parent/other-child names, while validating all default interfaces. The dentry absent-interface phase uses this oracle after loopback rename and retains `lo` non-enumerability and original/transferred protection checks.

Before **any writable open**, write-policy requires root with bounded UID and GID maps, creates a new Network with `unshare(CLONE_NEWNET)`, checks a distinct Network identity, and compares its `NS_GET_USERNS` owner FD with the unchanged current User identity. Failure refuses the test before opens. Interface count never proves ownership. It then requires nobody UID/GID65534, denied WRONLY/RDWR/TRUNC opens through both views, and unchanged loopback MTU in sysfs and independent rtnetlink. Additional defaults are allowed. In an already registered disposable mapped-root Sysbox container with the trusted helper configured, run both caller contexts (the script creates its own Net):

```sh
python3 tests/runtime/sysfs-write-policy.py
unshare --user --map-root-user -- python3 tests/runtime/sysfs-write-policy.py
```

Both contexts need permission to create their owned Network and query its owner. The second command requires the already supported direct-child User graph. Do not run these commands as initial-host root. Use the probe/interleave commands above and the documented dentry/checkpoint prerequisites for actual-path runtime validation. Run the unprivileged focused checks without Sysbox separately:

```sh
python3 tests/static/test_sysfs_oracle.py -v
python3 -m unittest discover -s tests/static -p test_contracts.py -v
python3 -m unittest discover -s tests/static -p test_sysfs.py -v
```

These fixtures inject independent snapshots/readers and exercise real getdents parsing on temporary directories; they do not establish real FUSE or mount behavior. Report PASS/FAIL/UNRUN for each exact revision. Actual Sysbox probes, interleave, write-policy and checkpoint runtime cases are UNRUN without a configured Sysbox/helper fixture; dentry protections additionally require a registered outer mask/read-only fixture; error injection requires a separately configured failure helper. Missing fixtures are not kernel/hardware failures. Prior operator diagnostic runs (including corrected-oracle Talos results) are inherited diagnostic evidence, not an official pass of this checkout.

Downstream **MUST** pin the immutable full commit containing this change and its source inventory, including the shared module and regressions. A commit cannot embed its own future SHA: on the final clean checkout resolve `git rev-parse HEAD`, pin that resulting full SHA, verify `build/sources.lock.json` with `scripts/build.py`'s `load_lock()` and run the strict `test_contracts.py` inventory check. Fetch all public files at that same SHA in their relative layout. For paired builds retain the generated `manifest.json` input/output hashes and that checkout SHA. A branch name, historical binary release or diagnostic source edit does not identify these tests.

## 日本語

### 実際の Sysbox 経路

過去の binary pair は [動作条件](../../docs/compatibility.md) に記載する arm64 検証を通過しました。
構成済みの arm64 Sysbox 環境で、既存の一般ユーザーとして実行します。

```sh
bash tests/runtime/verify.sh "$HOST_PID_NAMESPACE" "$HOST_USER_NAMESPACE"
python3 tests/runtime/stress-proc.py
```

変更なしの bwrap command と既存の保護検査を維持します。
runner は `thread-proc.c` もビルドし、read-write と read-only を検査します。
TID と TGID の違い、leader と要求元の Mount namespace の違いを確認します。
syscall は実際の Sysbox listener と production helper を通り、この検査に合成 listener や検査専用 helper は使いません。
要求元と同じ namespace の別 process が、sandbox PID identity、取得した外側 proc submount すべての identity と read-only policy、mask、detach lock を確認します。
leader の target は不変であることを要求します。
read-write ケースには書き込み可能な外側 `/proc` root が必要で、登録済み submount の read-only 保護は維持します。
read-only の継承で root が書き込み不能になる場合は、その policy を解除せず検査を失敗させます。
依存物は事前に導入し、ホストの構築は行いません。

### proc 保護の事前記録

Issue #7 は検査プログラムだけを変更します。
`verify.sh` は bwrap の前に外側 `/proc` の事前記録を取得し、同じファイルを `sandbox` と `readonly` に渡します。
readonly の呼び出しは `verify readonly TARGET MANIFEST` となり、capture と sandbox の引数は変わりません。
`verify.c` と `verify.sh` は同じ checksum 固定 revision から取得し、実行ごとに記録を作り直します。旧形式の記録は拒否します。

固定候補のうち `uptime`、`bus`、`fs`、`irq`、`interrupts`、`keys`、`timer_list` の7件は、既存の3 mask を含む必須項目です。
`/proc/keys` は `CONFIG_KEYS` に依存しますが、既存の mask とともに意図的に必須としています。
不在の mask は既存の保護検証を満たせないため、その kernel ではこの fixture が失敗します。
すべての有効な kernel に `/proc/keys` が存在するという意味ではありません。
任意項目の `asound`、`sysrq-trigger`、`swaps`、`sys` の4件だけ不在を許容します。
`asound` は `CONFIG_SND_PROC_FS` に依存します。
Linux v6.18 の [tty Makefile](https://github.com/torvalds/linux/blob/v6.18/drivers/tty/Makefile) は `CONFIG_MAGIC_SYSRQ` のときだけ `sysrq.o` をビルドします。
[mm Makefile](https://github.com/torvalds/linux/blob/v6.18/mm/Makefile) は `CONFIG_SWAP` のときだけ `swapfile.o` をビルドし、[swapfile.c](https://github.com/torvalds/linux/blob/v6.18/mm/swapfile.c) が `/proc/swaps` を登録します。
[proc Makefile](https://github.com/torvalds/linux/blob/v6.18/fs/proc/Makefile) は `CONFIG_PROC_SYSCTL` のときだけ `proc_sysctl.o` をビルドし、無効時には [internal.h](https://github.com/torvalds/linux/blob/v6.18/fs/proc/internal.h) の `proc_sys_init` が空の stub となるため、`/proc/sys` は不在になり得ます。
ALSA の導入、module の読み込み、ホスト設定変更は要求しません。
capture は各候補を改行で終わる一行に記録し、存在する場合は `NAME present DEV INO FLAGS`（符号なし十進数）、任意項目の stat が ENOENT の場合だけ `NAME absent` とします。
任意項目も明示的な行が必要で、省略すると失敗します。
それ以外の取得エラーは出力ファイルを開く前に失敗させます。

両 consumer は mount、detach、remount 操作の前に記録全体を検証します。
入力は全体で4096 byte、一行は改行を除き255 byte 以下とし、11候補を一度ずつ網羅する必要があります。
この上限内で ASCII 空白の連続、行頭と行末の ASCII 空白を許容し、capture は区切りを単一空白にした正規形を出力します。
空、不足、重複、未知、不正、NUL を含む入力、長さ超過、末尾改行の欠落、数値の overflow は失敗とします。
必須項目と既存の保護対象3件以上という下限を維持します。
不在の記録は各 consumer でも stat の ENOENT と一致する必要があり、存在、権限エラー、その他の観測失敗は失敗とします。
存在した項目の消失も失敗とします。

readonly は新しい root と存在する全項目の ST_RDONLY を要求します。
sandbox は PID/User namespace の表示、PID の隔離、seccomp、observer capability、存在する各項目の device/inode identity、事前記録の read-only policy、detach 拒否、read-only remount 拒否、必須3 mask の空読み取りを維持します。
不在行で後続の検査を打ち切りません。
元の一般ユーザーの bwrap command と caller の権限は変わりません。

権限を必要としない回帰検査は次のように単独実行できます。

```sh
python3 tests/static/test_proc_verifier.py -v
```

`tests/unit/proc-verifier.c` の syscall stub と実際の `verify.c` の entry point をコンパイルし、出荷する runtime verifier に検査を回避する mode は追加しません。
任意4項目の存在と不在の全16組み合わせを両 consumer と capture roundtrip で確認し、各任意項目の capture エラー、mount 操作前の不正入力拒否、観測エラー、保護対象の消失と書き込み可能化、不在の `asound` より後の従来の全検査を確認します。
下流はこの3ファイルを同じ相対配置で checksum 固定して取得し、build harness なしで Python ファイルを実行できます。
`verify.sh` は従来どおり `verify-sys.py` と `thread-proc.c` も必要です。

模擬検査だけでは実際の mount 動作を検証できません。
修正版の `verify.sh` を許可された使い捨て Sysbox 環境で実行し、対象 revision の成功、失敗、未実行を区別して報告します。
任意4項目の分類を修正した runner を 2026-10-16 に、使い捨ての arm64／Linux 7.1.0／Sysbox 0.7.1／bubblewrap 0.9.0 環境で検証しました。
UID/GID 1001、CapEff 0、NoNewPrivs 1、seccomp mode 2・filter 1 の条件で、元の bwrap、sandbox 保護、既存 sys bind、再帰的 readonly、非 leader の RW/RO が成功しました。
この kernel では任意4項目 `asound`、`sysrq-trigger`、`swaps`、`sys` がすべて存在しました。不在のケースは対象を絞った模擬検査だけで確認しています。
実際に任意項目が不在の kernel と実 amd64／Talos 6.18.18 での runtime 検証は未実行で、下流で追跡します。
CI は各 PR head に対応付けて記録します。前述の過去の結果は別の証跡です。

### 決定的な確認地点

二つ目の検査は、Python 3.12 以降、namespace へのアクセス、`pidfd_getfd` 用の `CAP_SYS_PTRACE` を持つ、親 User namespace の root として実行します。
運用者が指定する exec command で自身の sandbox だけを作成し、daemon の設定は変更しません。
実行環境の architecture 向けに二つの検査 binary をビルドします。
requester は指定 path でテストコンテナから見える必要があります。
検査 helper は信頼された起動元だけで実行します。

```sh
cc -O2 -Wall -Wextra -Werror tests/unit/helper-checkpoint.c -o "$CHECKPOINT_HELPER"
cc -O2 -Wall -Wextra -Werror -pthread tests/runtime/checkpoint-requester.c -o "$CHECKPOINT_REQUESTER"
python3 tests/runtime/checkpoints.py \
  --outer-pid "$OUTER_INIT_PID" --uid "$CALLER_UID" --gid "$CALLER_GID" \
  --helper "$CHECKPOINT_HELPER" --requester "$CHECKPOINT_REQUESTER" \
  --requester-kind nonleader --stage staging --action thread-exit \
  --exec nsenter --target "$OUTER_INIT_PID" \
    --user --mount --pid --net --ipc --uts --cgroup --root --wd \
    --setuid "$CALLER_UID" --setgid "$CALLER_GID" \
    /usr/bin/env PATH=/usr/bin:/bin
```

専用コンテナを使い、caller ID は動的に取得します。
UID/GID map を固定しません。
actor の制御には一時 sandbox 内の private FIFO を使います。
exec command の stdin には依存しません。
Linux は同じ thread への二つ目の `NEW_LISTENER` を `EBUSY` で拒否するため、この検査用 process は既存の通知 listener を継承しない信頼された起動元から作ります。
上記の namespace entry は専用コンテナに入り、runtime の filter を継承しませんが、稼働中 process や daemon の policy は変更しません。
この起動方法は helper の直接検査だけで使い、前節の実際の Sysbox 経路では production の seccomp profile を保持します。
検査 helper は production C source を取り込み、実際の pidfd poll の前後で停止します。
**検査 helper を production helper として導入しません。**
制御 socket は検査専用で、production の対の export には含めません。
requester は実際の `getpid` seccomp 通知を作り、`pidfd_getfd` で listener を渡します。
これは helper の直接検査で、Sysbox daemon の実経路の証拠ではありません。
Go の検査は、実際の通知を使って production の起動前関数を別途検査します。

次の全組み合わせ（32 回）を、それぞれ新しい sandbox で実行します。

| 要求元 | 確認地点 | 操作 |
|---|---|---|
| leader | launch、staging、transfer、commit | interrupt、thread-exit、process-exit、exec |
| 非 leader | launch、staging、transfer、commit | interrupt、thread-exit、process-exit、exec |

`launch` は検査プログラムの FD 固定順序と固定後の kernel の通知失効を確認し、helper 未起動と target 不変を要求します。
この分岐は production の Go 関数を呼ばず、実通知を使う Go 検査が、失効した元の ID で `runProcTransfer` が起動 callback を呼ばないことを別途確認します。
`staging` は最初の poll 前、`transfer` は最後の poll 前、`commit` は最後の poll 成功後に停止します。
signal で通知を中断した thread は生存します。
thread-exit は通知の中断後に thread だけを終了し、別 thread を残します。
非 leader の pidfd は読み取り可能になりますが、leader の先行終了では group が生存する間は読み取り不能のままです。
ローカルの kernel 検査もこの条件を確認します。
process-exit は検査が固定した自身の actor だけを終了し、独立した observer は同じ Mount namespace に残ります。
別 thread の exec は、非 leader の pidfd を読み取り可能にし、leader の pidfd は生存を示します。
sandbox の supervisor は全ケースで PID 1 を生存させます。

staging と transfer で終了を検出した場合は、ESRCH と target 不変を要求します。
この二地点の interrupt、leader の thread-exit、leader の exec は、保護済み tree の commit と、元の通知への成功の ENOENT による拒否を要求します。
commit では全操作で競合を強制し、存続する observer が PID identity、全保護 submount の identity、mask、再帰的 read-only 属性、detach lock を確認します。
失効した元の通知への成功は拒否されなければなりません。
確認地点の欠落、ioctl/namespace error、observer の失敗、後始末の timeout は検査の失敗とし、skip による合格はありません。
helper は起動後 30 秒以内（daemon の 25 秒と観測の余裕 5 秒）に回収します。
ローカルの unit suite は 20 秒の alarm と親終了時の child の後始末を別途確認します。
所有 FD を閉じ、固定した固有の actor、supervisor、observer だけを終了させます。

staging と transfer 前の終了検査は、失敗時の後始末を確認します。
poll 後の検査は、許容する競合でも保護を保持することを確認します。
通知の確認と commit は原子的ではありません。
[設計](../../docs/design.md) を参照し、既存の `helper-rejections.py` の全モードも実行します。
生ログと namespace 識別子はローカルに保持し、公開する証跡は architecture、kernel/runtime の版、合否に限定します。

### 新規 sysfs と Network の検査

構成済みの隔離 Sysbox コンテナと、信頼された sysfs helper の設定を使います。
production listener を保持し、依存物は隔離 image に事前に用意します。
observer が参照する検査専用 path `/tmp/issue5-repo` にリポジトリを配置します。
前掲 command は binary とリポジトリを bwrap の private `/tmp` へ bind し、共有 Network と新設 Network、RW と RO を検査します。
追加する capability は child User namespace 内の observer と自身の Network fixture 用であり、outer Pod や初期ホストの権限ではありません。

同じ四条件を `unshare --user --map-root-user --mount --pid --fork` からも実行し、inner UID/GID0 が outer caller に対応することを確認します。
各条件で固有の target を使い、leader 側に残る空の directory を終了後に削除します。
元の bwrap 呼び出しは維持し、この追加経路の map、capability、NNP、seccomp を別途記録します。
必須の再帰的 nodev により `/dev/null` mask が読み取り不能になる場合、observer は同じ identity と nodev による EACCES を要求します。
読み取りが成功する場合は空であることを要求し、内容の露出は許可しません。

非 leader probe は thread 固有 Mount/Network、全 source identity と保護属性、detach/move、RO 解除拒否を確認します。
独立 observer は netlink と class/net、保護された devices/virtual/net、ifindex/mtu、symlink、raw getdents、高水準列挙を照合します。
fresh-Net の非 leader は private Network にだけ `issue5-tid` を作成し、leader の interface 一覧と ifindex が不変であることを検査します。
`sysfs-interleave.py` は自身の child User が所有する Network で共有 directory handle の非 zero offset を先行取得し、異なる名前と MTU の二つの Network namespace を交互に読み、共有側の正と負の lookup、属性 cache の先行取得も検査します。
変更対象は自身の隔離 fixture の interface だけです。

直接起動の競合検査には `sysfs-checkpoint.c`、`checkpoint-sysfs.c`、`checkpoints.py --filesystem sysfs` を使い、同じ32条件を検査します。
この sandbox にも `/tmp/issue5-repo` を bind します。
FD7 は Network で、合成通知の直接 fixture と実 mount probe の証跡を分けます。
拒否検査は `helper-rejections.py --filesystem sysfs` の既存条件と wrong-network、deeper-user、backing-symlink を使います。
backing-symlink は実 helper で末尾の Readlink 成功と、そのリンクを通る Lookup/Open の ELOOP を確認します。
`sysfs-write-policy.py` は外側 mapped root と capable な直下の子 root で、スクリプト自身が新設して所有関係を証明する private Network を使い、nobody 所有、書き込み拒否、MTU 不変を確認します。
source の取得失敗を省略しません。

非既定の mask、RO path、入れ子の保護 mount は登録前に隔離コンテナへ構成します。
全 source を capable observer と照合し、mask 内容、書き込み拒否、実際に存在しない path を別々に検査します。
合否を通すために policy を解除しません。
検査専用 `sysfs-failure-helper.c` に信頼された `TEST_HELPER` と `TEST_TRIGGER` の絶対パスをコンパイル時に渡し、別の隔離 daemon だけで使います。
`sysfs-failures.py` は directory を正常に開いた後、同じ検査専用 switch file を作り、raw getdents と高水準列挙の EIO、新規 mount の target 不変を要求します。
consumer daemon は変更しません。

outer、setup、inner の map、所有関係、capability/NNP/seccomp/filter、実バージョン、flags、成果物 hash を記録します。
amd64/Linux 6.18.18-talos の gate は deferred/unrun とし、arm64/Linux 7.1/bwrap 0.9 の補助結果で対応済みとは扱いません。
既存 proc と `/sys` bind の受け入れ条件は独立して保持します。
Docker、privileged child、kind の smoke は別経路の結果として記録します。

network 配下の保護と、不在・拒否 Lookup を組み合わせて検査します。隔離コンテナの登録前に `lo/ifalias` の OCI mask と `lo/statistics` の readonly self-bind を用意し、自身の Mount namespace に属する capable mapped な直下の子 observer から `python3 tests/runtime/sysfs-dentry-protection.py` を実行します。自身の転送 target、深い User、loopback を rename した新しい child-owned Network だけを使い、外側と転送 tree の mount ID、identity、保護属性、detach／remount 拒否を確認します。別の task 専用 failure helper では `--failure-switch /tmp/issue5-dentry-switch` を使用でき、helper と caller から同じ新しい task 所有 file が見える必要があります。明示的な EIO と保護 dentry の維持を要求し、既存 consumer daemon と host interface は対象にしません。

test failure helper を設定した使い捨てコンテナで、`python3 tests/runtime/sysfs-failures.py <task-switch-path> 2`（ENOENT）または `20`（ENOTDIR）を実行すると、setup の失敗を注入します。どちらも raw getdents と高水準列挙の EIO を要求し、正常な helper の真の不在 resource は ENOENT を維持します。数値引数を省くと EIO を注入します。switch は task 専用で、終了時に削除します。

virtual-net の READDIR は要求ごとに byte stream を再生成します。非0 offset の継続が一貫するのは、同じ Network で一覧が不変の場合だけです。Network をまたぐ handle 共有や一覧変更後の古い byte cookie の結果は未定義で、空、切り詰め、EIO となりえます。新しい view は `lseek(fd, 0, SEEK_SET)`／`rewinddir` で先頭へ戻して読みます。共有 handle の継続検査は他 Network の名前が出ないことだけを確認し、巻き戻し後は現在の名前集合との完全一致を要求します。

### 移植可能な sysfs 検査

Issue #9 は runtime テストだけを変更し、production helper、patch、upstream ABI を維持します。
`sysfs_oracle.py` は4つの呼び出し元 `sysfs-network.py`、`sysfs-interleave.py`、`sysfs-write-policy.py`、`sysfs-dentry-protection.py` と同じ場所に配置します。
thread と checkpoint／lifecycle の observer も、既存の repository bind を通して同じ CLI を呼び出します。
実行時のソース書き換えは不要です。

観測元の現在の Network で `RTM_GETLINK` を取得し、全 interface の名前、ifindex、MTU を独立した比較基準とします。
所有する仮想 interface だけの fixture では、`class/net` と `devices/virtual/net` の高水準列挙と raw getdents の全件集合を照合します。
追加の default interface を許容し、全件の metadata を検査します。
`bonding_masters` だけは、通常ファイルであり netlink の interface 集合に含まれない場合に限り、属性として除外します。
この属性は登録済み FUSE のどちらの alias でも存在を必須としません。
未知の entry、不正な型や symlink、path 解決や traversal のエラー、netlink 観測失敗は検査失敗とします。
同名の実 interface を属性として隠すことはできません。
class の symlink、subsystem link、負の lookup、namespace と cache の分離の検査を維持します。
仮想 interface の fixture に hardware、固定 interface 数、module 読み込みは要求しません。

raw 列挙は各 record の境界を検査し、巻き戻し後も EOF まで全件を読みます。
共有 FD の古い非0 cookie は部分一覧、空、EIO を許容しますが、返った全 entry が現在の Network に属する必要があります。
EINVAL など他のエラーは失敗とします。
interleave は親 veth と共有 FD の先行取得、制御した名前と MTU、親と別の子の名前の不在を維持し、default interface も全件検査します。
dentry の absent-interface phase も loopback rename 後に同じ oracle を使い、`lo` の列挙拒否と元／転送 tree の保護検査を維持します。

write-policy は書き込み用 open の前に、UID/GID map が有限範囲の root であることを確認し、`unshare(CLONE_NEWNET)` で Network を新設します。
Network identity が変わったこと、`NS_GET_USERNS` の owner FD が不変の現在の User identity と一致することを確認します。
失敗時は open 前に検査を拒否し、interface 数を所有の証明に使いません。
両 view の nobody UID/GID65534、WRONLY／RDWR／TRUNC open の拒否、sysfs と独立した rtnetlink の loopback MTU 不変を確認します。
追加の default interface を許容します。
信頼する helper を設定済みで、登録済みの使い捨て mapped-root Sysbox コンテナ内から、両方の caller 条件で実行します。
Network はスクリプトが新設します。

```sh
python3 tests/runtime/sysfs-write-policy.py
unshare --user --map-root-user -- python3 tests/runtime/sysfs-write-policy.py
```

両条件で、自身の Network の新設と owner の照会を許可されている必要があります。
2番目の command は対応済みの直下の子 User graph を要求します。
初期ホストの root として実行しません。
実経路の検証には、前掲の probe／interleave command と、dentry／checkpoint の前提条件を使います。
Sysbox を必要としない focused 検査は別途実行します。

```sh
python3 tests/static/test_sysfs_oracle.py -v
python3 -m unittest discover -s tests/static -p test_contracts.py -v
python3 -m unittest discover -s tests/static -p test_sysfs.py -v
```

模擬検査は独立した snapshot と reader を注入し、一時 directory で実際の getdents parser も確認しますが、実 FUSE や mount の動作を証明しません。
対象 revision ごとに PASS／FAIL／UNRUN を記録します。
構成済み Sysbox/helper fixture がない場合、実 Sysbox probe、interleave、write-policy、checkpoint runtime は UNRUN とします。
dentry 保護には登録済み outer mask／read-only fixture、エラー注入には別途構成した failure helper も必要です。
fixture の不足を kernel や hardware の失敗と扱いません。
補正 oracle による過去の Talos 結果を含む運用者の診断結果は、継承した診断証跡であり、この checkout の公式成功とは区別します。

下流は、この修正を含む不変の full commit と source inventory を必ず固定します。
共有 module と回帰テストも対象です。
commit 自身に将来の SHA は埋め込めないため、最終的な clean checkout で `git rev-parse HEAD` を実行し、その full SHA を固定します。
`build/sources.lock.json` は `scripts/build.py` の `load_lock()` で照合し、厳格な `test_contracts.py` の inventory 検査も実行します。
全公開ファイルを同じ SHA から相対配置を維持して取得します。
対の build では生成した `manifest.json` の入出力 hash と checkout SHA を保持します。
branch 名、過去の binary release、診断用のソース修正だけでは、このテストを特定できません。
