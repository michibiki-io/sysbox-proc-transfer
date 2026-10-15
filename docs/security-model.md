# Security model / 安全性の設計

## Contents / 目次

- [English](#english): [Authorization](#authorization), [Protection and limits](#protection-and-limits)
- [日本語](#日本語): [認証](#認証), [保護と制約](#保護と制約)

- [Sysfs authority and limits](#sysfs-authority-and-limits) / [sysfs の権限と制約](#sysfs-の権限と制約)

## English

### Authorization

The baseline trusts the `sysbox-fs` launcher, its helper executable/environment and registered container metadata. It does not trust sandbox-supplied paths or proc views. The daemon requires container root `/`, empty proc mount data, an absolute target, requester `CAP_SYS_ADMIN`, credentials within the registered UID/GID ranges, and no immutable mountpoint overlap. Caller IDs are derived dynamically from registered maps; the interface does not authorize arbitrary IDs outside them.

The helper requires a root launcher in the parent User namespace of the registered outer namespace. Requester User namespace must be a direct child of that outer namespace, and must own the requester Mount/PID namespaces. Descriptors pin the target and source objects. `openat2` resolution uses `RESOLVE_IN_ROOT | RESOLVE_NO_MAGICLINKS` under the relevant container roots. Protection sources come from the registered outer container, not the requester's possibly overmounted view.

The worker clears inherited supplementary groups, enters the mapped outer User namespace as root there, checks a nonzero outer mapping and chroots through the pinned outer root. It does not retain initial-host-User namespace privileges for mounting. It stays in the ancestor host PID namespace, so sandbox procfs cannot expose the worker. The sandbox keeps its User/PID/Mount isolation and seccomp filtering.

### Protection and limits

Registered proc mounts, read-only paths and masked paths are deduplicated and cloned recursively. Missing registered source paths are skipped; malformed paths and a request with no available protection sources are rejected. The worker compares device/inode identity and read-only retention, locks protected submounts through a child User namespace, and performs final attachment only after successful staging and child reaping. Read-only requests, including inherited outer procfs superblock policy normalized before dispatch, apply recursive read-only attributes.

The implemented flag whitelist is `MS_RDONLY | MS_NOSUID | MS_NODEV | MS_NOEXEC | MS_RELATIME | MS_STRICTATIME | MS_SILENT | MS_LAZYTIME`. Unknown bits are rejected. New proc mounts always receive nosuid/nodev/noexec attributes. Whitelist membership does not imply that every combination succeeds: `MS_STRICTATIME` fails on the validated baseline. Proc root ownership is deliberately not rewritten with initial-user capabilities; a single-UID sandbox can see the overflow UID while process entries retain mapped ownership.

The daemon binds pinned requester objects to the original notification with an ID check before launch. The helper polls a thread pidfd on the actual TID before staging and immediately before transfer; it cannot observe live-thread notification invalidation, premature leader exit while its group survives, or leader replacement by another thread’s exec. The notification race starts at the pre-launch check, the observable nonleader/whole-process exit race at the final poll. Undetectable leader exit/replacement shares the notification race boundary. A raced commit retains every protection; upstream revalidation and the kernel notification send prevent success to an invalid ID. See [design checkpoints](design.md) for exact actors, failure outcomes and deterministic test criteria.

Parent death signals, helper alarm, daemon timeout, nondumpable workers, requester pidfd checks, private staging and synchronous reaping limit lifecycle and exposure. Unsupported APIs fail before final commit. These mechanisms are preserved from the validated implementation; packaging is not a comprehensive security audit. The portable tests check existing protection behavior, unauthorized direct launch, and the included namespace/liveness/flag rejection cases; they are not an exhaustive attack suite. See [compatibility](compatibility.md) for prior failure-condition results and unverified kernel requirements.

### Sysfs authority and limits

The trusted pre-exec mount-table snapshot is mandatory; a requester's mountinfo or a fixed SysMounts list cannot supply complete policy. Source replacement, missing sources, downgraded attributes, malformed flags/data, unsupported ownership and unavailable thread pidfds fail before transfer. Acquisition diagnostics preserve errno. Root floor and source clones are checked independently. The helper executable and daemon environment must remain protected from containers.

Backing mode is read-only and restricted to the existing virtual-net handler. It omits that emulation ancestor only to serve its network-specific passthrough, keeps OCI masks and nested mounts, and clears privileges before resource opening. Final symlinks can be inspected with O_PATH, but `RESOLVE_NO_SYMLINKS` rejects traversal even when the lexical path has no `..`; the backing helper cannot resolve arbitrary raw sysfs through an in-network link. Lookup/Getattr return host-root UID/GID with SkipIdRemap, preserving nobody ownership rather than caller-owned mapped Network IDs. Writable Open is rejected independently of caller capabilities. Read/write permissions and FUSE's default-permission checks remain; no write privilege is added. Per-request pinning and uncached entry/attribute/data handling prevent one namespace from priming another's network view. Trusted source pinning needs a metadata-only exception for this daemon’s own pinned threads/direct inode worker (host UID/GID 0) and its direct child sysfs helper during mapped construction before capability clearing (registered container-root UID/GID, CAP_SYS_ADMIN and an FD10 pidfd required). The locker and grandchildren are excluded. This exception returns synthetic traversal attributes only on registered source boundaries and their ancestors, without raw resource access or mount operations. Backing projects only verified readonly self-binds of this same network passthrough to the caller’s raw sysfs with equivalent security attributes to avoid recursive FUSE construction; the actual transferred tree retains their original identities. Unsupported network FUSE overlays fail closed. The actual caller/helper namespace graph is unchanged; positive entry/attribute TTLs remain zero for these metadata nodes too.

The synchronous alarm, parent-death signal, daemon timeout and reaper guard bound children and descriptors. Live-thread notification interruption and leader replacement are not detectable by a final pidfd poll alone. Notification and move_mount are not atomic. No full security audit, installer support or Talos compatibility is claimed before the consumer gate.

A registered network protection boundary or ancestor with an existing protocol identity must remain a valid positive FUSE entry even when this caller's backing Lookup fails. Linux invalidates an expired dentry on a LOOKUP error and detaches submounts on that shared dentry in every namespace, including locked protection clones. For these policy paths only, failed Lookup returns the same protocol identity/kind with fixed read-only traversal metadata (host-root IDs, zero size; no saved network attributes). Entry/attribute TTLs stay zero. This may expose the existence of a registered policy ancestor when the caller's Network lacks it; directory enumeration, Getattr, Open, Read and Readlink still obtain and authorize the actual caller view, and missing non-policy paths retain their errors. No contents or write access are granted. Unknown identities and pre-registration paths retain the original failure. See `tests/runtime/sysfs-dentry-protection.py` for rejected deeper-User, renamed-interface and injected-failure protection retention checks.

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
分岐前に継承した外側 procfs superblock の read-only policy を含め、read-only request では属性を再帰的に適用します。

実装の flag whitelist は `MS_RDONLY | MS_NOSUID | MS_NODEV | MS_NOEXEC | MS_RELATIME | MS_STRICTATIME | MS_SILENT | MS_LAZYTIME` です。
未知の bit は拒否し、新しい proc mount には常に nosuid/nodev/noexec 属性を付けます。
whitelist に含まれる全組み合わせの成功を保証するものではありません。
`MS_STRICTATIME` は検証済み環境で失敗します。
proc root の所有者を初期 User namespace の権限で書き換えません。
単一 UID の sandbox では overflow UID として見える場合がありますが、process entry は mapped ownership を保持します。

daemon は FD 固定後、起動前の通知 ID 確認で要求元と元の通知を結び付けます。
helper は実際の TID の thread pidfd を staging 前と転送直前に確認します。
生存した thread の通知失効や、group が生存する間の leader の先行終了や、別 thread の exec による leader の置き換えは検出できません。
通知の競合区間は起動前の確認から、poll で検出できる終了の競合区間は最後の poll から始まります。
検出できない leader の先行終了や置き換えは、通知の競合区間に含めます。
競合して成立する mount でも全保護を保持し、upstream の再確認と kernel への通知送信は失効 ID への成功を防ぎます。
実行主体、失敗時の結果、決定的な検査の合否基準は [設計](design.md) を参照してください。

parent death signal、helper alarm、daemon timeout、nondumpable worker、requester pidfd 検査、private staging、同期 reaping で lifecycle と露出を制御します。
未対応 API では最終 commit 前に失敗します。
これらは検証済み実装から維持した機構であり、今回の整理は完全な安全性監査ではありません。
移植可能な検査は既存保護の動作、不正な直接起動、収録した namespace・生存・flag の拒否条件を確認します。
網羅的な攻撃試験ではありません。
過去の失敗条件の結果と未検証の kernel 条件は [動作条件](compatibility.md) を参照してください。

### sysfs の権限と制約

登録時の信頼された mount table を必須とします。
requester の mountinfo や固定 SysMounts だけでは全 policy を表せません。
source の置き換え、欠落、保護属性の低下、不正 flags/data、対象外の所有関係、thread pidfd の取得失敗は転送前に拒否します。
取得失敗の診断は元の errno を保持します。
root の下限と各 source clone を別々に確認します。
helper executable と daemon 環境はコンテナから変更できないように管理します。

backing mode は既存 virtual-net handler の読み取りに限定します。
network passthrough 用に emulation の親だけを除き、OCI mask と入れ子 mount は保持します。
resource を開く前に capability を消します。
末尾 symlink の Readlink は保持し、`RESOLVE_NO_SYMLINKS` で途中の symlink を拒否するため、字面に `..` がなくても backing helper から任意の raw sysfs へ移動できません。
Lookup/Getattr は host root の UID/GID を返し、SkipIdRemap により mapped container の nobody 所有を保持します。
caller の capability にかかわらず書き込み用 Open を拒否します。
既存の読み書きの制約と FUSE default permissions を保持し、write 権限を追加しません。
操作ごとの FD 固定と cache 無効化で、別 namespace に先行 lookup の結果を流用しません。
信頼された source 固定用の metadata 専用例外は、daemon 自身の固定 thread と直下の inode worker（host UID/GID0）、および capability を消す前の構築段階にある daemon 直下の sysfs helper（登録済みコンテナの root UID/GID、CAP_SYS_ADMIN と FD10 の pidfd が必要）に限ります。locker と孫 task は含めません。登録済み source の mount 境界と祖先にだけ適用します。
合成した通過用属性だけを返し、raw resource の読み取りや mount は許可しません。
再帰を避けるため、確認済みの同じ network passthrough の readonly self-bind だけを、同等の保護属性で caller の raw backing に投影します。
転送 tree は元の identity を保持し、対象外の network FUSE overlay は拒否します。
実際の caller と helper の namespace 所有関係は変えず、この metadata node も entry/属性 TTL は zero とします。

alarm、parent-death signal、daemon timeout、reaper guard で child と FD の寿命を制限します。
生存 thread の通知中断や leader の置き換えは最終 pidfd poll だけでは検出できません。
通知確認と move_mount は原子的ではありません。
完全な安全性監査や installer 対応を主張せず、consumer gate 前に Talos の対応完了と扱いません。

登録済み network 保護の mount 境界と祖先に既存の protocol identity がある場合、要求元の backing Lookup が失敗しても、その FUSE entry は有効なまま維持します。Linux は期限切れ dentry の LOOKUP error で共有 dentry を失効させ、別 namespace の locked clone を含む配下の保護 mount を detach するためです。この policy path だけは同じ identity と種別の固定した読み取り専用 traversal metadata（host-root ID、size zero）を返し、保存した Network 属性は返しません。entry／属性 TTL は zero のままです。要求元の Network に存在しなくても登録済み policy 祖先の存在は見える場合がありますが、列挙、Getattr、Open、Read、Readlink は実際の caller view と認可を使い、policy 外の不在は元の error を維持します。内容や write 権限は与えず、未知の identity と登録前は元の失敗を返します。深い User、interface rename、失敗注入の後も外側と転送 tree の保護が残ることを `tests/runtime/sysfs-dentry-protection.py` で確認します。
