# Issue #3 runtime regressions / Issue #3 の実行時回帰検査

## Contents / 目次

- [English](#english): [Actual Sysbox path](#actual-sysbox-path), [Deterministic checkpoints](#deterministic-checkpoints)
- [日本語](#日本語): [実際の Sysbox 経路](#実際の-sysbox-経路), [決定的な確認地点](#決定的な確認地点)

## English

### Actual Sysbox path

The updated binary pair passed the arm64 validation recorded in [compatibility](../../docs/compatibility.md). In the provisioned arm64 Sysbox environment, run as the existing non-root caller:

```sh
bash tests/runtime/verify.sh "$HOST_PID_NAMESPACE" "$HOST_USER_NAMESPACE"
python3 tests/runtime/stress-proc.py
```

The unchanged bwrap command and existing policy checks remain. The runner also builds `thread-proc.c` and runs read-write/read-only cases. It asserts TID != TGID and different leader/requester Mount namespaces. The syscall takes the actual Sysbox listener and production helper path; there is no synthetic listener or test helper in this probe. A separate observer in the requester's namespace checks sandbox PID identity, every captured outer proc submount's identity/read-only policy, masks and detach locks. The leader's target must remain unchanged. Dependencies must already be installed; no host provisioning is performed.

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

`launch` invalidates after descriptor pinning and asserts no helper exists and no mutation. `staging` pauses before the first helper poll; `transfer` pauses before the final poll; `commit` pauses after the final successful poll. The signal-interrupted thread stays alive. Thread-only exit follows interruption and leaves another thread alive. Nonleader exit makes its thread pidfd readable; premature leader exit remains unreadable while the group survives, as verified by the local kernel test. A process-exit kills only the harness's pinned actor; an independent observer survives in its Mount namespace. Exec replaces the requester from another thread: nonleader pidfd becomes readable, leader pidfd remains live. A persistent sandbox supervisor keeps PID 1 alive in all cases.

At staging/transfer, detected exit must return ESRCH with unchanged target. Interrupt, leader thread-exit and leader exec at these stages must commit the protected tree while the original notification rejects a success response with ENOENT. At commit, all actions force a commit race; the surviving observer must confirm intended PID identity, all registered submount identities, masks, recursive read-only attributes and detach locks. The original invalid notification must reject success. Missing checkpoints, ioctl/namespace errors, observer failures and cleanup timeouts fail the test; there is no skip-to-pass fallback. Helpers must be reaped within 30 seconds after launch (25 second daemon limit plus 5 second observation allowance); the local unit suite separately tests the 20 second alarm and parent-death child cleanup. The harness closes its owned descriptors and kills only pinned, uniquely tagged actors/supervisor/observer.

The whole-process/thread exit cases before staging/transfer prove failure cleanup. The post-poll cases prove retained protection despite an allowed race. Notification validation and commit are not atomic; see [design](../../docs/design.md). Run the historical `helper-rejections.py` modes as well. Keep raw logs and namespace identifiers local; public evidence records only architecture, kernel/runtime versions and pass/fail outcomes.

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

`launch` は FD 固定後に通知を失効させ、helper の未起動と target 不変を要求します。
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
