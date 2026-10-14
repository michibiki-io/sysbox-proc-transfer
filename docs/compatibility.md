# Compatibility / 動作条件

## Contents / 目次

- [English](#english): [Validated baseline](#validated-baseline), [Review correction validation](#review-correction-validation), [Verification boundaries](#verification-boundaries)
- [日本語](#日本語): [検証済みの基準](#検証済みの基準), [レビュー修正の検証](#レビュー修正の検証), [検証範囲](#検証範囲)

## English

### Validated baseline

The adopted implementation was previously validated on **arm64, Linux 7.1, Sysbox 0.7.1 and bubblewrap 0.9.0**. The unchanged non-root invocation below succeeded, along with sandbox PID identity, mapped outer User namespace isolation, registered masks/read-only protections and submount detach locks:

```sh
bwrap --die-with-parent --unshare-all --share-net \
  --ro-bind / / --dev-bind /dev /dev --proc /proc -- /bin/true
```

The prior baseline also passed recursive read-only proc checks, preserved `/sys` tree bind checks and 500 mounts with eight workers plus concurrent nsenter/FUSE reaping. `/sys` coverage concerns a bound existing tree only. It is not evidence for a nested sysfs mount implementation.

Before the review correction below, the common build and portable runtime tests were also completed for this repository packaging in an **arm64 environment** with the same kernel and runtime baseline. Both generated binary SHA-256 values matched the validated binary pair: `sysbox-fs` = `bee88e0d87c0b6978fc19542952064b574aae63ab1f372ed687da7355eba419b`, `proc-mount-helper` = `2c81e159530dd30c994e9dcb12be2939d318b22d44e5470a1b896edf9d90efa6`. This is an observed match for this build, not a guarantee of byte-identical future builds.

The unchanged non-root command, PID identity, seccomp, protection inode/read-only retention, masks, detach denial, recursive read-only procfs and preserved `/sys` tree checks passed. The concurrent 500-mount stress check passed. The existing helper rejection harness is included as `tests/runtime/helper-rejections.py`, with runtime-specific execution supplied by the operator. Wrong Mount namespace ownership, a dead requester, unsupported flags and a mapped-user launcher were rejected; live failed requests left the target unchanged. The harness was exercised against the same binary pair in the arm64 environment. Private host identities and raw operational logs are intentionally not part of the public validation record.

### Review correction validation

The final patch moves nested dispatch after the existing `createProcPayload` read-only policy normalization. A focused upstream-package regression test covers inherited read-only, read-write, explicit read-only and missing proc metadata cases through the real dispatcher without launching the helper. The corrected daemon builds and this regression test passes in an arm64 builder. The C helper and its prior runtime validation remain unchanged. Full container runtime tests were not rerun with the corrected daemon, and it was not installed into a running host; the initial runtime binary hash above is historical, not the final daemon hash.

### Verification boundaries

Runtime requires the paired patched daemon and trusted helper, registered container UID/GID maps, a direct child User namespace owning the target Mount/PID namespaces, container root `/`, empty proc data and accepted mount flags. It requires procfs `pidns` FD configuration plus `openat2`, pidfds and the new mount APIs (`fsopen`, `fsconfig`, `fsmount`, `open_tree`, `move_mount`, `mount_setattr`). Other kernels and architectures remain unverified. The unchanged implementation opens the notifying PID/TID with `pidfd_open(..., 0)`; non-thread-group-leader requesters are not supported by this path. The validated bubblewrap mount is issued by a leader process. Thread-pidfd support is not added by this packaging issue. `MS_STRICTATIME` is in the whitelist but fails on this baseline; no blanket flag compatibility is claimed.

The portable runtime runner requires independently supplied host PID/User namespace identifiers and runs as the caller inside a provisioned Sysbox container. A C compiler, Python 3 and bubblewrap must already be installed. It does not configure the host or provision containers. Local static/compilation checks and CI native builds verify packaging contracts, not the runtime baseline. Explicit `--platform` compilation depends on builder support and does not extend runtime support. This repository makes no byte-identical rebuild or full security audit claim.

## 日本語

### 検証済みの基準

採用する実装は、arm64、Linux 7.1、Sysbox 0.7.1、bubblewrap 0.9.0 で過去に検証済みです。
次の一般ユーザーによる変更なしの呼び出しと、sandbox PID identity、outer mapped User namespace の隔離、登録済み mask/read-only 保護、submount detach lock を確認しています。

```sh
bwrap --die-with-parent --unshare-all --share-net \
  --ro-bind / / --dev-bind /dev /dev --proc /proc -- /bin/true
```

基準環境では再帰的 read-only proc、保持した `/sys` tree の bind、8 worker による 500 mount と並行 nsenter/FUSE reaping も成功しています。
`/sys` は既存 tree の bind のみを検査しています。
nested sysfs mount 実装の検証結果ではありません。

後述のレビュー修正前のリポジトリ構成についても、同じ kernel/runtime 条件の **arm64 環境でビルドと実行時検証を完了しました**。
生成した二つの binary の SHA-256 は、検証済みの binary と一致しました。
`sysbox-fs` は `bee88e0d87c0b6978fc19542952064b574aae63ab1f372ed687da7355eba419b`、`proc-mount-helper` は `2c81e159530dd30c994e9dcb12be2939d318b22d44e5470a1b896edf9d90efa6` です。
今回観測した一致であり、将来の全ビルドの byte 一致を保証するものではありません。

元の一般ユーザーの command、PID identity、seccomp、保護 inode/read-only 属性、mask、detach 拒否、再帰的 read-only procfs、保持した `/sys` tree の検査が成功しました。
500 回の並行 mount 検査も成功しました。
既存の helper 拒否条件を確認する harness は `tests/runtime/helper-rejections.py` に収録し、実行環境固有の起動コマンドは運用者から渡します。
同じ binary を使った arm64 検証で、誤った Mount namespace owner、終了した requester、未対応 flag、mapped User namespace からの launcher が拒否されました。
生存する requester の拒否ケースでは target が変更されないことも確認しました。
公開の検証記録にホスト識別情報や実機の生ログは含めません。

### レビュー修正の検証

最終 patch は nested 分岐を、既存の `createProcPayload` の read-only policy 判定より後に移動します。
upstream package の対象を絞った regression test で、継承する read-only、read-write、明示的 read-only、proc metadata がない場合を、実際の dispatcher を通して確認します。
この検査では helper を起動しません。
arm64 builder で修正した daemon のビルドと regression test が成功しました。
C helper と、その実行時検証結果は変わりません。
修正した daemon を稼働中ホストへ導入して container runtime 検査を再実行することはしていません。
上記の初期 runtime binary hash は過去の記録であり、最終 daemon の hash ではありません。

### 検証範囲

実行時には patched daemon と信頼された helper の対、登録済み UID/GID map、target Mount/PID namespace を所有する直接の child User namespace、container root `/`、空の proc data、受理される mount flag が必要です。
procfs の `pidns` FD 設定に加え、`openat2`、pidfd、新しい mount API（`fsopen`、`fsconfig`、`fsmount`、`open_tree`、`move_mount`、`mount_setattr`）を使います。
他の kernel と architecture は未検証です。
変更していない実装は通知元 PID/TID に `pidfd_open(..., 0)` を使うため、thread group leader 以外からの request はこの経路では対応しません。
検証済みの bubblewrap mount は leader process から実行されます。
今回の整理では thread pidfd 対応を追加しません。
`MS_STRICTATIME` は whitelist に含まれますが、基準環境では失敗します。
全 flag の互換性を主張しません。

実行時 runner は別途取得したホスト PID/User namespace 識別子を要求し、構成済み Sysbox コンテナ内で呼び出し元ユーザーとして動作します。
C compiler、Python 3、bubblewrap は事前に導入します。
ホスト設定やコンテナ構築は行いません。
ローカル静的検査、コンパイル検査、CI native build は packaging の契約を確認し、基準環境の実行時検証を代替しません。
明示的な `--platform` は builder の対応に依存し、実行時対応を拡大しません。
byte 単位で一致する再ビルドや完全な安全性監査は保証しません。
