# Design / 設計

## Contents / 目次

- [English](#english): [Transfer](#transfer), [Internal contract](#internal-contract)
- [日本語](#日本語): [転送](#転送), [内部契約](#内部契約)

- [Sysfs transfer and FUSE backing](#sysfs-transfer-and-fuse-backing) / [sysfs 転送と FUSE backing](#sysfs-転送と-FUSE-backing)

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

### Sysfs transfer and FUSE backing

`patches/sysfs-transfer.patch` applies after the proc patch to the same pinned trees. New mounts in the registered outer User namespace retain upstream dispatch. Enabled nested requests require a direct child User namespace owning the requester Mount namespace; Network must be owned by outer or child User. The C helper verifies each relationship through nsfs FDs before mapped entry, and enters only outer User/Mount and actual requester Network. All sysfs and scratch mounts execute in mapped outer authority.

The separate sysfs protocol uses FD3 outer User, FD4 outer Mount, FD5 requester User, FD6 requester Mount, **FD7 requester Network**, FD8 target, FD9 outer root, FD10 actual TID `PIDFD_THREAD`, and FD11+ sources. Arguments are mapped UID, GID, flags and relative protection paths. Proc FD7 remains PID. Acquisition anchors requester and outer `/proc` task directories, opens `PIDFD_THREAD` before reading requester namespaces/root, and uses rooted `openat2` for container paths. The existing trusted pre-exec creation-time update snapshots every `/sys` mount, including OCI masks/RO and nested submounts. It orders parents before children, verifies source mount IDs, pinned source device/inode identities in the C worker, and monotonic RO/nosuid/nodev/noexec floors. Missing required sources fail, with their errno. Recursive source clones retain nested mounts. Fresh transfer/backing requires a registered `sysfs` filesystem root with mountinfo Root `/`; whole-root masks and restricted subtree binds fail with ENOTSUP before target mutation. More than 128 sources fails closed.

A bounded private tmpfs in an outer-derived private Mount namespace holds fresh sysfs constructed in the actual Network namespace. Protected sources are attached with identity/floor verification. Requested or inherited root RO is recursive. Child User/Mount separation locks the completed tree before the mapped outer worker transfers it to the pinned target. The same post-pinning production notification gate used by proc runs inside the reaper guard immediately before launch. There is no fallback. Thread poll and notification validation are separate from commit; the proc checkpoint table and residual race boundaries also apply here. A race-committed tree remains protected.

For FUSE virtual-net operations the same helper has a separate backing mode: after UID/GID/flags, `--lookup=devices/virtual/net/...` or `--open=devices/virtual/net/...` precedes source paths; FD8 is an internal socket. It also accepts registered-outer callers in outer or direct-child-owned Network namespaces, verifying the owner parent for the latter; initial-host or deeper owners are rejected. Before the final creation-time update, trusted runtime bootstrap reads retain upstream handling. The fresh backing view starts from registered outer Mount, omits only the registered virtual-parent FUSE emulation mount to prevent recursion, and retains all other masks/RO sources. After mounting read-only it drops to caller mapped UID/GID, clears capabilities and opens a single resource using `RESOLVE_BENEATH | RESOLVE_NO_MAGICLINKS | RESOLVE_NO_SYMLINKS`. Final symlinks are inspected via O_PATH; traversal of raw symlink targets is refused. Only that resource FD returns through SCM_RIGHTS. No tree FD, write FD, caller-root mkdir or visible temporary directory is exposed. Each operation pins Network and thread lifetime anew, with no userspace cache. A separate metadata-only exception serves host UID/GID0 requests from this daemon’s own pinned threads/direct inode worker and mapped construction helpers before capability clearing, only for registered protection mount boundaries and their ancestors. An atomically published immutable snapshot avoids reentering the container lock held by upstream inode collection. These synthetic attributes allow trusted source FD traversal; they expose no resource contents, enumeration, symlink target or writable FD and perform no mounts. The native source mount ID and helper FD identity remain mandatory. An OCI readonly self-bind of this same network FUSE passthrough is a special backing case: cloning it would recursively invoke the same handler. Its registered source FD, mount ID and readonly floor are still required; `@ro:` marks only that verified self-alias for raw per-request backing with equivalent readonly/nosuid/nodev/noexec attributes. Transfer mode keeps the original alias mount and identity. Other network FUSE overlays fail with ENOTSUP; arbitrary aliases are not projected. Container callers cannot enter this exception.

Network Lookup bypasses path-only nodeDB even for outer callers. A separate registry retains only FUSE protocol identity and covered inode kind, needed to keep native protection submounts attached to their original dentries. Every lookup returns a fresh, authorized attribute snapshot; Getattr and IO always use the actual caller. Identity entries are released on Forget and contain no reusable network view. The opt-in pinned-library identity hook keeps those IDs stable without serving cached attributes. Entry and attribute TTLs are zero; the pinned FUSE library also bypasses its per-handle directory-data cache for these nodes; Getattr refreshes with the actual FUSE request PID rather than Attr's old snapshot. Existing DirectIO read policy remains. ReadDir operational errors retain errno rather than becoming ENOENT and a libc false empty success. Genuine missing paths keep ENOENT. Virtual-net Lookup/Getattr normalize host-side fstat UID/GID to host root so `SkipIdRemap` preserves nobody ownership inside mapped containers; writable opens are explicitly denied. Existing FUSE default permissions and emulation remain. An anchored task directory prevents lookup from switching to a recycled TID, but concurrent exec/setns and the final liveness-to-use window remain non-atomic.

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

### sysfs 転送と FUSE backing

`patches/sysfs-transfer.patch` は、同じ固定ソースに proc patch の後で適用します。
登録済み外側 User の新規 mount は upstream の dispatch を維持します。
対象は外側 User の直下の子と、その子が所有する Mount、外側または子が所有する Network です。
helper は mapped entry の前に nsfs FD で関係を確認し、outer User/Mount と実 requester Network だけに入ります。
sysfs と scratch の全 mount は mapped 権限で行います。

sysfs の FD3–6、8–10 は proc と同じ役割ですが、**FD7 は Network** です。
proc FD7 の PID 契約は変更しません。
FD11 以降は登録済み保護 source で、引数は mapped UID、GID、flags、相対保護 path です。
新規 transfer/backing は、登録済みの filesystem type が `sysfs`、mountinfo Root が `/` の場合だけ許可します。
`/sys` 全体の mask と部分 tree の bind は、target を変更する前に ENOTSUP で拒否します。
初期 exec 前の既存 creation-time updateに kernel metadata だけを読む parser が `/sys` 配下の OCI mask、read-only、入れ子 submount をすべて取得します。
親から子の順に並べ、取得時に mount ID、固定 source の device/inode、RO/nosuid/nodev/noexec の下限を照合します。
必要 source の欠落は元の errno で失敗し、128 件を超える場合も拒否します。
再帰的 clone は source 内の submount を保持します。

外側 Mount から派生した private namespace の容量制限付き tmpfs で、実 Network に対応する sysfs を構築します。
source の identity と保護属性を確認し、継承または要求した RO を再帰的に適用します。
child User/Mount で完成 tree を lock した後、mapped worker が固定 target に転送します。
全 FD 固定後、reaper guard 内で proc と同じ通知確認関数を呼んでから起動します。
fallback はありません。
通知確認、生存確認、commit は原子的ではなく、proc の確認地点と競合区間を共有します。
競合して成立する mount にも保護を保持します。

FUSE virtual-net は backing mode を使います。
UID/GID/flags の後に `--lookup=devices/virtual/net/...` または `--open=devices/virtual/net/...` を渡し、FD8 は内部 socket になります。
外側またはその直下の子が所有する Network に入った登録済み外側 caller も扱い、後者は owner の親を確認します。
初期ホストや深い子の所有関係は拒否します。
最終 creation-time update 前の runtime bootstrap 読み取りは upstream の処理を維持します。
backing は登録済み外側 Mount から構築し、再帰を防ぐため登録済み virtual 親の FUSE emulation mount だけを除きます。
その他の mask と RO source は維持します。
RO 構築後に caller の mapped UID/GID へ移行し、capability を消し、範囲内の resource 一つだけを安全な rooted lookup で開きます。
最終 symlink は O_PATH で調べ、raw symlink のたどり先は開きません。
SCM_RIGHTS で resource FD だけを返し、tree FD、write FD、caller root への一時書き込みは提供しません。
操作ごとに Network と thread を固定し、userspace cache は使いません。
登録済み保護 source の mount 境界とその祖先だけに、内部の metadata 専用例外を設けます。
host UID/GID0 で daemon 自身の固定 thread または直下の inode worker または capability を消す前の mapped helper の構築処理から来た要求を限定して扱います。
不変 snapshot を atomic に公開し、upstream inode 収集が保持する container lock への再入を避けます。
返すのは合成した directory 属性だけで、内容、列挙、symlink の先、write FD を公開せず、mount も行いません。
最後の native source は mount ID と固定 FD の identity で照合し、container caller はこの例外に入りません。
同じ network FUSE passthrough の OCI readonly self-bind は、clone すると同じ handler を再帰呼び出しするため、backing だけで例外として扱います。
登録済み source FD、mount ID、readonly 属性を確認し、`@ro:` で指定した self-alias を requester の raw backing に同等の readonly/nosuid/nodev/noexec で投影します。
転送 tree は元の alias mount と identity を保持し、その他の network FUSE overlay は ENOTSUP で拒否します。
要求元と外側の `/proc` task directory を固定し、namespace/root の読み取り前に thread pidfd を取得します。
task directory は再利用された TID への切り替えを防ぎますが、exec/setns や最終生存確認後の競合は原子的に防げません。

外側 caller を含め network Lookup は path 単位の nodeDB を使いません。
別の registry は FUSE の protocol identity と被覆 inode の種別だけを保持し、native 保護 submount が元の dentry に対応し続けるようにします。
lookup は毎回、権限を確認した新しい属性を返し、Getattr と IO は実 caller を使います。
Forget で identity を解放し、Network view を再利用しません。
entry と属性 TTL は zero とし、固定した FUSE library の handle 単位 directory cache も迂回します。
Getattr は実 FUSE requester を使って再取得します。
Lookup/Getattr は host 側 fstat の UID/GID を host root に正規化し、SkipIdRemap による mapped container 内の nobody 所有を保持します。
書き込み用 Open は明示的に拒否し、既存の DirectIO、default permissions、emulation を維持します。
ReadDir の内部失敗は errno を保持し、libc が空の成功と扱う ENOENT に変換しません。
実際に存在しない path の ENOENT は維持します。
