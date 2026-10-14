# Issue #3 runtime regressions / Issue #3 の実行時回帰検査

## Contents / 目次

- [English](#english): [Actual Sysbox path](#actual-sysbox-path), [Deterministic checkpoints](#deterministic-checkpoints)
- [日本語](#日本語): [実際の Sysbox 経路](#実際の-sysbox-経路), [決定的な確認地点](#決定的な確認地点)

- [New sysfs and network checks](#new-sysfs-and-network-checks) / [新規 sysfs と Network の検査](#新規-sysfs-と-network-の検査)

## English

### Actual Sysbox path

The updated binary pair passed the arm64 validation recorded in [compatibility](../../docs/compatibility.md). In the provisioned arm64 Sysbox environment, run as the existing non-root caller:

```sh
bash tests/runtime/verify.sh "$HOST_PID_NAMESPACE" "$HOST_USER_NAMESPACE"
python3 tests/runtime/stress-proc.py
```

The unchanged bwrap command and existing policy checks remain. The runner also builds `thread-proc.c` and runs read-write/read-only cases. It asserts TID != TGID and different leader/requester Mount namespaces. The syscall takes the actual Sysbox listener and production helper path; there is no synthetic listener or test helper in this probe. A separate observer in the requester's namespace checks sandbox PID identity, every captured outer proc submount's identity/read-only policy, masks and detach locks. The leader's target must remain unchanged. The read-write case requires a writable outer `/proc` root; registered read-only submount protections remain enabled. The probe fails if read-only inheritance prevents a read-write root rather than clearing that policy. Dependencies must already be installed; no host provisioning is performed.

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

Use `tests/unit/sysfs-checkpoint.c`, `tests/runtime/checkpoint-sysfs.c` and `checkpoints.py --filesystem sysfs` for the same 32-case direct-helper race matrix. Bind `/tmp/issue5-repo` into that sandbox too. FD7 is Network. The synthetic notification remains a direct fixture, separate from the real mount probe. Use `helper-rejections.py --filesystem sysfs` for existing modes plus wrong-network, deeper-user and backing-symlink. The last mode calls the real backing helper directly: final `lo/subsystem` Readlink succeeds, while Lookup/Open through that link fail with ELOOP. Run `sysfs-write-policy.py` as outer mapped root and capable direct-child root, each in a fresh private loopback-only Network; it checks nobody Lookup/Getattr, write denial and unchanged MTU. A child UID map may start at outer UID0; the fixture requires a bounded map rather than mistaking that for initial-host User authority. No failed source acquisition may be skipped.

For complete policy coverage, provision the disposable container with non-default masked files, RO paths and a nested protected mount before registration, then compare all sources with the capable observer. Do not remove policy to make a probe pass. Test masked contents and write denial separately from missing paths. Compile the test-only `sysfs-failure-helper.c` with trusted `TEST_HELPER` and `TEST_TRIGGER` absolute paths and use it only in a separate disposable daemon. `sysfs-failures.py` opens the network directory before creating the task-owned switch, then requires EIO from raw getdents and high-level enumeration and unchanged target on failed actual mount. The switch must address the same task-owned file from the helper host view and caller container view. Do not change a consumer daemon.

Record outer/setup/inner maps, ownership, capability/NNP/seccomp/filter state, kernel/architecture/runtime versions, request flags and hashes of unpatched/patched binaries. The Linux 6.18.18-talos amd64 gate is deferred/unrun; supplemental arm64/Linux 7.1/bwrap 0.9 results are not Talos support. Existing proc and `/sys` bind acceptance remain independent. Rootful Docker/privileged child/kind smoke must be recorded as separate paths.

## 日本語

### 実際の Sysbox 経路

更新した binary pair は [動作条件](../../docs/compatibility.md) に記載する arm64 検証を通過しました。
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
`sysfs-write-policy.py` は外側 mapped root と capable な直下の子 root で、それぞれ新しい loopback のみの Network を使い、nobody 所有、書き込み拒否、MTU 不変を確認します。
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
