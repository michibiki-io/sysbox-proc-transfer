# Security model / 安全性の設計

## Contents / 目次

- [English](#english): [Authorization](#authorization), [Protection and limits](#protection-and-limits)
- [日本語](#日本語): [認証](#認証), [保護と制約](#保護と制約)

## English

### Authorization

The baseline trusts the `sysbox-fs` launcher, its helper executable/environment and registered container metadata. It does not trust sandbox-supplied paths or proc views. The daemon requires container root `/`, empty proc mount data, an absolute target, requester `CAP_SYS_ADMIN`, credentials within the registered UID/GID ranges, and no immutable mountpoint overlap. Caller IDs are derived dynamically from registered maps; the interface does not authorize arbitrary IDs outside them.

The helper requires a root launcher in the parent User namespace of the registered outer namespace. Requester User namespace must be a direct child of that outer namespace, and must own the requester Mount/PID namespaces. Descriptors pin the target and source objects. `openat2` resolution uses `RESOLVE_IN_ROOT | RESOLVE_NO_MAGICLINKS` under the relevant container roots. Protection sources come from the registered outer container, not the requester's possibly overmounted view.

The worker clears inherited supplementary groups, enters the mapped outer User namespace as root there, checks a nonzero outer mapping and chroots through the pinned outer root. It does not retain initial-host-User namespace privileges for mounting. It stays in the ancestor host PID namespace, so sandbox procfs cannot expose the worker. The sandbox keeps its User/PID/Mount isolation and seccomp filtering.

### Protection and limits

Registered proc mounts, read-only paths and masked paths are deduplicated and cloned recursively. Missing registered source paths are skipped; malformed paths and a request with no available protection sources are rejected. The worker compares device/inode identity and read-only retention, locks protected submounts through a child User namespace, and performs final attachment only after successful staging and child reaping. Read-only requests apply recursive read-only attributes.

The implemented flag whitelist is `MS_RDONLY | MS_NOSUID | MS_NODEV | MS_NOEXEC | MS_RELATIME | MS_STRICTATIME | MS_SILENT | MS_LAZYTIME`. Unknown bits are rejected. New proc mounts always receive nosuid/nodev/noexec attributes. Whitelist membership does not imply that every combination succeeds: `MS_STRICTATIME` fails on the validated baseline. Proc root ownership is deliberately not rewritten with initial-user capabilities; a single-UID sandbox can see the overflow UID while process entries retain mapped ownership.

Parent death signals, helper alarm, daemon timeout, nondumpable workers, requester pidfd checks, private staging and synchronous reaping limit lifecycle and exposure. Unsupported APIs fail before final commit. These mechanisms are preserved from the validated implementation; packaging is not a comprehensive security audit. The portable tests check existing protection behavior, unauthorized direct launch, and the included namespace/liveness/flag rejection cases; they are not an exhaustive attack suite. See [compatibility](compatibility.md) for prior failure-condition results and unverified kernel requirements.

## 日本語

### 認証

基準実装は `sysbox-fs` launcher、helper executable と環境変数、登録済みコンテナ metadata を信頼します。
sandbox が指定する path や proc view は信頼しません。
daemon は container root `/`、空の proc mount data、絶対 target path、requester の `CAP_SYS_ADMIN`、登録済み UID/GID 範囲内の credential、immutable mountpoint と重ならないことを要求します。
caller ID は登録済み map から動的に導き、その範囲外の任意 ID は許可しません。

helper は、登録済み outer User namespace の親 User namespace に属する root launcher を要求します。
requester User namespace は outer の直接の child であり、requester Mount/PID namespace を所有する必要があります。
descriptor で target と source を固定します。
`openat2` は各 container root に対して `RESOLVE_IN_ROOT | RESOLVE_NO_MAGICLINKS` を使います。
保護 source は requester の上書き可能な view から取得せず、登録済み outer container から取得します。

worker は継承した supplementary group を消し、outer mapped User namespace の root に移行します。
非 zero の outer mapping を確認し、固定した outer root を使って chroot します。
mount のために初期ホスト User namespace の権限を保持しません。
祖先のホスト PID namespace に留まるため、sandbox procfs に worker は見えません。
sandbox の User/PID/Mount 隔離と seccomp filtering は維持します。

### 保護と制約

登録済み proc mount、read-only path、masked path は重複を除き、再帰的に clone します。
存在しない登録済み source path は省略します。
不正な path と、利用できる保護 source が一つもない request は拒否します。
worker は device/inode と read-only の維持を照合し、child User namespace で保護 submount を lock します。
staging と child reaping が成功してから最終取り付けを行います。
read-only request では属性を再帰的に適用します。

実装の flag whitelist は `MS_RDONLY | MS_NOSUID | MS_NODEV | MS_NOEXEC | MS_RELATIME | MS_STRICTATIME | MS_SILENT | MS_LAZYTIME` です。
未知の bit は拒否し、新しい proc mount には常に nosuid/nodev/noexec 属性を付けます。
whitelist に含まれる全組み合わせの成功を保証するものではありません。
`MS_STRICTATIME` は検証済み環境で失敗します。
proc root の所有者を初期 User namespace の権限で書き換えません。
単一 UID の sandbox では overflow UID として見える場合がありますが、process entry は mapped ownership を保持します。

parent death signal、helper alarm、daemon timeout、nondumpable worker、requester pidfd 検査、private staging、同期 reaping で lifecycle と露出を制御します。
未対応 API では最終 commit 前に失敗します。
これらは検証済み実装から維持した機構であり、今回の整理は完全な安全性監査ではありません。
移植可能な検査は既存保護の動作、不正な直接起動、収録した namespace・生存・flag の拒否条件を確認します。
網羅的な攻撃試験ではありません。
過去の失敗条件の結果と未検証の kernel 条件は [動作条件](compatibility.md) を参照してください。
