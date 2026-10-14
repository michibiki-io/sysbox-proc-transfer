# Design / 設計

## Contents / 目次

- [English](#english): [Transfer](#transfer), [Internal contract](#internal-contract)
- [日本語](#日本語): [転送](#転送), [内部契約](#内部契約)

## English

### Transfer

The patch selects a mapped identity for namespace entry when a nested user namespace omits UID/GID zero. It changes the nsexec C code linked into `sysbox-fs`, without requiring a replacement standalone runtime or manager. The nested proc path is enabled by `SYSBOX_PROC_TRANSFER_HELPER`. Requests in the registered outer user namespace continue through the original path.

For an eligible nested request, `sysbox-fs` authenticates capabilities and credentials against the registered container, pins namespaces, target directory, outer root and requester pidfd, and supplies registered protection sources. The C worker enters the mapped outer User namespace as mapped root, then the outer Mount namespace and container root. All mounting uses mapped-user privileges. It remains in the ancestor host PID namespace, invisible in the sandbox procfs, and selects the sandbox PID namespace via procfs `pidns` FD configuration.

A private staging Mount namespace and bounded tmpfs hold a new proc tree. Registered protected mounts are cloned from the outer container, attached and checked for source identity/read-only retention. A sacrificial child User/Mount namespace locks the submounts and transfers a detached tree back to the worker. The worker reaps the child, discards staging, checks requester liveness and enters the target Mount namespace. The final `move_mount` attaches the locked tree to the pinned target. Earlier failures leave the target unchanged.

The patch also guards synchronous helper waiters against global nsenter reaping and treats transient seccomp listener `POLLERR` as nonterminal. Timeout, parent death signals, pidfd checks and synchronous waits bound lifecycle handling.

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
| 10 | Requester pidfd |
| 11 onward | Registered protected source mounts, matching path arguments |

The helper checks namespace types, direct-child User namespace relationship, Mount/PID ownership, trusted parent-user launcher, directory type and requester liveness. Only trusted proc metadata is opened before mapped-user entry; its private FD is closed before entering the requester Mount namespace. Exit status conveys an errno when possible; the daemon returns failure rather than reporting a successful transfer. Build and distribute the patched daemon and helper together; this FD/argument contract is not a versioned public API.

## 日本語

### 転送

patch は nested User namespace に UID/GID zero がない場合、namespace entry に mapped identity を選びます。
変更する nsexec C コードは `sysbox-fs` にリンクされる部分です。
単体 runtime や manager の置き換えは不要です。
nested proc 処理は `SYSBOX_PROC_TRANSFER_HELPER` で有効にします。
登録済みの外側 User namespace の request は従来の処理を使います。

対象となる nested request では、`sysbox-fs` が capability と credential を登録済みコンテナに照合します。
namespace、target directory、outer root、requester pidfd を固定し、登録済みの保護 source を渡します。
C worker は外側の mapped User namespace に mapped root として入り、外側の Mount namespace と container root に入ります。
mount はすべて mapped User namespace の権限で行います。
worker は祖先のホスト PID namespace に留まり、sandbox の procfs には見えません。
procfs の `pidns` FD 設定で sandbox の PID namespace を指定します。

private staging Mount namespace と容量制限した tmpfs に新しい proc tree を構築します。
外側コンテナの登録済み保護 mount を clone して取り付け、source identity と read-only の維持を検査します。
一時的な child User/Mount namespace で submount を lock し、detached tree を worker に返します。
worker は child を reap して staging を破棄し、requester の生存を確認して target Mount namespace に入ります。
最後の `move_mount` で固定した target に locked tree を取り付けます。
それ以前の失敗では target を変更しません。

patch は同期 helper の wait を global nsenter reaping から保護し、一時的な seccomp listener の `POLLERR` を終了条件にしません。
timeout、parent death signal、pidfd 検査、同期 wait で lifecycle を制御します。

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
| 10 | Requester pidfd |
| 11 以降 | path 引数と対応する登録済み保護 source mount |

helper は namespace type、直接の child User namespace 関係、Mount/PID の所有関係、信頼された parent-user launcher、directory type、requester の生存を検査します。
mapped User namespace に入る前に開くのは信頼された proc metadata のみです。
その private FD は requester Mount namespace に入る前に閉じます。
可能な場合は終了 status で errno を伝え、daemon は転送失敗を成功として返しません。
patched daemon と helper は対としてビルドし、配布します。
FD と引数の契約は版管理された public API ではありません。
