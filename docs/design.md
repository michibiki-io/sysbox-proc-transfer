# Design / 設計

## Contents / 目次

- [English](#english): [Transfer](#transfer), [Internal contract](#internal-contract)
- [日本語](#日本語): [転送](#転送), [内部契約](#内部契約)

## English

### Transfer

The patch selects a mapped identity for namespace entry when a nested user namespace omits UID/GID zero. It changes the nsexec C code linked into `sysbox-fs`, without requiring a replacement standalone runtime or manager. The nested proc path is enabled by `SYSBOX_PROC_TRANSFER_HELPER`. Requests in the registered outer user namespace continue through the original path.

The existing `createProcPayload` policy normalization runs before the nested branch, so a read-only `/proc` superblock adds `MS_RDONLY` to the same mount payload passed to the helper.

For an eligible nested request, `sysbox-fs` authenticates capabilities and credentials against the registered container, pins namespaces, target directory, outer root and requester pidfd, and supplies registered protection sources. Namespace/root/target lookup and pidfd acquisition all use the notification TID, never a substituted TGID. Inside the synchronous child-reaper guard, after pinning every descriptor, `runProcTransfer` validates the original listener/ID via `SECCOMP_IOCTL_NOTIF_ID_VALID` immediately before helper launch. The C worker enters the mapped outer User namespace as mapped root, then the outer Mount namespace and container root. All mounting uses mapped-user privileges. It remains in the ancestor host PID namespace, invisible in the sandbox procfs, and selects the sandbox PID namespace via procfs `pidns` FD configuration.

A private staging Mount namespace and bounded tmpfs hold a new proc tree. Registered protected mounts are cloned from the outer container, attached and checked for source identity/read-only retention. A sacrificial child User/Mount namespace locks the submounts and transfers a detached tree back to the worker. The worker reaps the child, discards staging, enters the target Mount namespace and checks requester liveness immediately before transfer. The final `move_mount` attaches the locked tree to the pinned target. Earlier failures leave the target unchanged.

The patch also guards synchronous helper waiters against global nsenter reaping and treats transient seccomp listener `POLLERR` as nonterminal. Timeout, parent death signals, pidfd checks and synchronous waits bound lifecycle handling.


The protocol is unchanged: no seccomp listener is passed to the helper. Checkpoints are:

| Checkpoint | Actor and condition | Detected failure |
|---|---|---|
| Pre-launch, after all requester/protection FDs are pinned | Daemon: original notification ID valid | No child launch or target mutation; an internal EIO response is discarded by invalid-ID revalidation rather than delivered to the requester; deferred FD closes |
| Pre-staging, after target/type/namespace validation and before mapped-user entry | Helper: FD 10 poll shows no thread exit | ESRCH (EBADF for invalid FD); exit destroys owned descriptors, no target mutation |
| Pre-transfer, after locker reaping/staging discard and target Mount namespace entry | Helper: final FD 10 poll shows no thread exit | Same failure and cleanup, no target mutation |
| Before response | Upstream daemon: original ID still valid, then kernel notification send | Invalid ID suppresses success; send also rejects a raced invalid ID |

A nonleader thread pidfd becomes readable when its selected thread exits while other threads can remain alive; a process pidfd waits for the last thread. Kernel `pidfd_poll` also delays a prematurely exited leader while its group survives, even for `PIDFD_THREAD`; the local SYS_exit regression explicitly covers this case. Acquisition of an actual thread and poll readiness are separate properties ([kernel pidfd_poll](https://github.com/torvalds/linux/blob/v6.17/fs/pidfs.c#L232-L250)). Another thread's exec kills a nonleader requester and makes that pidfd readable. If the requester was the leader, the execing thread inherits the leader identity and the leader pidfd can remain live. A signal can interrupt a notification while its thread remains alive. Signal invalidation, premature leader exit and leader replacement are detected by notification validation, not by a readable pidfd.

Notification invalidation races with commit from the **pre-launch ID check** onward, including all staging. Observable nonleader/whole-process exit races with commit after the **final helper poll**. Premature leader exit, like leader replacement, can remain undetectable throughout the interval after the pre-launch notification check. Neither check is atomic with `move_mount`. Post-launch invalidation with a live pidfd can commit a protected tree. Exit after the final poll can also commit. The upstream response check and kernel send prevent success being delivered to the invalid original notification; they do not roll back a committed mount. Every committed tree still represents the pinned sandbox PID namespace and carries the registered masks, read-only policy and detach locks.

Helper alarms expire 20 seconds after the most recent `guard()`; the daemon caps helper execution at 25 seconds from command preparation. Parent death kills worker/locker; waits reap the locker synchronously and the daemon waits for its worker before closing its FDs. Private namespaces/detached trees disappear when the last owned descriptor/process exits. These are scheduling-dependent bounds, not hard deadlines for uninterruptible kernel operations. Regression deadlines allow 5 seconds for reap/observation (30 seconds after launch); tests fail on timeout, missing checkpoint or leaked worker.

`tests/unit/helper-checkpoint.c` builds a **test-only** helper translation unit that pauses before the first poll (S), before the final poll (T), and after the final successful poll (C). It calls the production helper's real namespace, mount, protection and liveness operations. Its private socket is supplied by the trusted harness, never by production arguments/environment. It is excluded from the production build/export. Do not install it as the daemon helper. `tests/runtime/checkpoints.py` uses its own disposable sandbox, real seccomp listener and thread pidfd; it checks an independent surviving observer in the target Mount namespace. This is direct-helper coverage, separate from `thread-proc.c`'s actual Sysbox path and the Go pre-launch production function test.

For each requester kind (leader/nonleader), run each checkpoint (launch/staging/transfer/commit) with interrupt, thread-exit, process-exit and exec. At launch the harness verifies pinning order and kernel invalidation, leaves the target unchanged and creates no helper. This branch does not invoke the production Go gate; the real-notification Go test separately verifies that `runProcTransfer` suppresses its launch callback for an invalid original ID. At S/T a detected thread/process exit, including nonleader thread-exit/exec, must fail with ESRCH and leave the target unchanged. At S/T an interrupt, premature leader exit or leader-replacing exec leaves the pidfd unreadable: the tree must commit with all protections and an invalid original ID must reject success. At C all actions force the accepted race: the observer must verify a committed protected tree and success to the invalid ID must be rejected. No timing-based probabilistic outcome counts as a pass.

### Internal contract

The helper is a trusted internal synchronous interface, not a general mount service. Arguments are decimal mapped outer UID, mapped outer GID, mount flags, then zero to 128 relative protection paths. The daemon requires at least one registered protection source. Descriptors are supplied through `exec.Cmd.ExtraFiles` in this exact order:

| FD | Meaning |
|---|---|
| 3 | Registered outer User namespace |
| 4 | Registered outer Mount namespace |
| 5 | Requester User namespace |
| 6 | Requester Mount namespace |
| 7 | Requester PID namespace |
| 8 | Pinned target directory |
| 9 | Pinned outer container root |
| 10 | Requester thread pidfd (`PIDFD_THREAD`, actual notifying TID) |
| 11 onward | Registered protected source mounts, matching path arguments |

The helper checks namespace types, direct-child User namespace relationship, Mount/PID ownership, trusted parent-user launcher, directory type and requester liveness. Only trusted proc metadata is opened before mapped-user entry; its private FD is closed before entering the requester Mount namespace. Exit status conveys an errno when possible; the daemon returns failure rather than reporting a successful transfer. Build and distribute the patched daemon and helper together; this FD/argument contract is not a versioned public API.

## 日本語

### 転送

patch は nested User namespace に UID/GID zero がない場合、namespace entry に mapped identity を選びます。
変更する nsexec C コードは `sysbox-fs` にリンクされる部分です。
単体 runtime や manager の置き換えは不要です。
nested proc 処理は `SYSBOX_PROC_TRANSFER_HELPER` で有効にします。
登録済みの外側 User namespace の request は従来の処理を使います。

既存の `createProcPayload` の policy 判定を nested 分岐より先に実行します。
`/proc` superblock が read-only の場合は、helper に渡す同じ mount payload の flag に `MS_RDONLY` が追加されます。

対象となる nested request では、`sysbox-fs` が capability と credential を登録済みコンテナに照合します。
namespace、target directory、outer root、requester pidfd を固定し、登録済みの保護 source を渡します。
namespace、root、target、pidfd はすべて通知元 TID を使い、TGID へ置き換えません。
すべての FD を固定した後、同期 child の回収を保護する区間内で、`runProcTransfer` が元の listener/ID を `SECCOMP_IOCTL_NOTIF_ID_VALID` で確認して helper を起動します。
C worker は外側の mapped User namespace に mapped root として入り、外側の Mount namespace と container root に入ります。
mount はすべて mapped User namespace の権限で行います。
worker は祖先のホスト PID namespace に留まり、sandbox の procfs には見えません。
procfs の `pidns` FD 設定で sandbox の PID namespace を指定します。

private staging Mount namespace と容量制限した tmpfs に新しい proc tree を構築します。
外側コンテナの登録済み保護 mount を clone して取り付け、source identity と read-only の維持を検査します。
一時的な child User/Mount namespace で submount を lock し、detached tree を worker に返します。
worker は child を reap して staging を破棄し、target Mount namespace に入った直後に requester の生存を確認します。
最後の `move_mount` で固定した target に locked tree を取り付けます。
それ以前の失敗では target を変更しません。

patch は同期 helper の wait を global nsenter reaping から保護し、一時的な seccomp listener の `POLLERR` を終了条件にしません。
timeout、parent death signal、pidfd 検査、同期 wait で lifecycle を制御します。


FD 契約は変わりません。
helper に seccomp listener は渡しません。
確認地点は次のとおりです。

| 確認地点 | 実行主体と条件 | 検出した失敗の結果 |
|---|---|---|
| 起動前、要求元と保護 source の全 FD 固定後 | daemon：元の通知 ID の有効性 | child と target の変更はなし。内部 EIO 応答は失効 ID の再確認で破棄し、要求元へ送信しない。defer で FD を閉じる |
| staging 前、target と namespace の検査後、mapped User namespace に入る前 | helper：FD 10 の poll で thread が終了していないこと | ESRCH。不正な FD は EBADF。終了時に所有 FD を閉じ、target は変更しない |
| 転送前、locker 回収と staging 破棄後、target Mount namespace に入った後 | helper：最後の FD 10 の poll で thread が終了していないこと | 同じ失敗と後始末。target は変更しない |
| 応答前 | upstream daemon：元の ID の有効性と、その後の kernel への通知送信 | 失効した ID への成功を抑止。送信との競合でも kernel が拒否 |

非 leader の thread pidfd は選択した thread の終了で読み取り可能になります。
同じ process の別 thread は生存していてもかまいません。
process pidfd は最後の thread の終了を待ちます。
kernel の `pidfd_poll` は、leader が先に終了しても group が生存する間は、`PIDFD_THREAD` でも読み取り可能にしません。
ローカルの SYS_exit 回帰検査はこの条件を確認します。
thread の取得と poll の通知条件は別の性質です（[kernel pidfd_poll](https://github.com/torvalds/linux/blob/v6.17/fs/pidfs.c#L232-L250)）。
別 thread の exec は非 leader の要求元を終了させ、その pidfd を読み取り可能にします。
要求元が leader の場合、exec した thread が leader の識別子を引き継ぎ、pidfd が生存を示すことがあります。
signal による通知の中断でも thread は生存できます。
signal による失効、leader の先行終了、leader の置き換えは、pidfd の読み取り可能性ではなく通知の有効性検査で検出します。

通知失効と commit の競合区間は、**起動前の ID 確認**の直後から staging 全体を含みます。
poll で検出できる非 leader と全 process の終了について、commit との競合区間は **helper の最後の poll**の直後からです。
leader の先行終了は置き換えと同様に、起動前の通知確認後の区間全体で poll による検出ができない場合があります。
これらの検査と `move_mount` は原子的ではありません。
起動後の通知失効や、最後の poll 後の終了で、保護済み tree が commit される場合があります。
応答前の確認と kernel の送信処理は、失効した元の通知へ成功が届くことを防ぎますが、成立した mount は取り消しません。
成立する tree は固定した sandbox PID namespace を表し、登録済み mask、read-only 属性、detach lock を保持します。

helper の alarm は最後の `guard()` から 20 秒、daemon の実行 timeout は command 準備から 25 秒です。
親の終了で worker と locker を終了させ、locker は同期回収し、daemon は worker を待って FD を閉じます。
最後の所有 FD と process が終了すると private namespace と detached tree は解放されます。
これはスケジューリングに依存する上限で、割り込み不能な kernel 処理の厳密な期限ではありません。
回帰検査は回収と観測に 5 秒の余裕（起動後 30 秒）を設け、timeout、確認地点の欠落、worker の残存で失敗します。

`tests/unit/helper-checkpoint.c` は検査専用の helper を作ります。
最初の poll 前（S）、最後の poll 前（T）、最後の成功した poll 後（C）で停止し、production helper の namespace、mount、保護、生存確認をそのまま実行します。
private socket は信頼された検査プログラムが渡し、production の引数や環境変数では制御できません。
production の build と export から除外しており、daemon の helper として導入しません。
`tests/runtime/checkpoints.py` は自身の一時 sandbox と実際の seccomp listener、thread pidfd を使い、存続する target Mount namespace の別 process から検査します。
これは helper の直接検査です。
`thread-proc.c` の実際の Sysbox 経路や、Go による production の起動前関数の検査とは区別します。

leader と非 leader のそれぞれについて、起動前、staging 前、転送前、commit 直前を、interrupt、thread-exit、process-exit、exec で検査します。
起動前のケースは検査プログラムの FD 固定順序と kernel の通知失効を確認し、helper 未起動と target 不変を要求します。
この分岐では production の Go 関数を呼びません。
実通知を使う Go 検査が、失効した元の ID で `runProcTransfer` が起動 callback を呼ばないことを別途確認します。
S/T で終了を検出した場合（非 leader の exec を含む）は ESRCH と target 不変を要求します。
S/T の interrupt、leader の先行終了、leader を置き換える exec は pidfd が読み取り不能のままのため、全保護を保持した commit と、失効した元の ID への成功の拒否を要求します。
C は全操作で競合を強制し、別 process による保護済み tree の確認と、失効 ID への成功の拒否を要求します。
確率的な timing の結果では合格にしません。

### 内部契約

helper は信頼された内部の同期インターフェースです。
引数は十進数の outer mapped UID、GID、mount flags と、最大 128 個の相対 protection path です。
daemon は少なくとも一つの登録済み保護 source を要求します。
`exec.Cmd.ExtraFiles` で渡す descriptor の順序は次のとおりです。

| FD | 意味 |
|---|---|
| 3 | 登録済み outer User namespace |
| 4 | 登録済み outer Mount namespace |
| 5 | Requester User namespace |
| 6 | Requester Mount namespace |
| 7 | Requester PID namespace |
| 8 | 固定した target directory |
| 9 | 固定した outer container root |
| 10 | Requester thread pidfd (`PIDFD_THREAD`, actual notifying TID) |
| 11 以降 | path 引数と対応する登録済み保護 source mount |

helper は namespace type、直接の child User namespace 関係、Mount/PID の所有関係、信頼された parent-user launcher、directory type、requester の生存を検査します。
mapped User namespace に入る前に開くのは信頼された proc metadata のみです。
その private FD は requester Mount namespace に入る前に閉じます。
可能な場合は終了 status で errno を伝え、daemon は転送失敗を成功として返しません。
patched daemon と helper は対としてビルドし、配布します。
FD と引数の契約は版管理された public API ではありません。
