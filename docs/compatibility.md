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

The final patch moves nested dispatch after the existing `createProcPayload` read-only policy normalization. A focused upstream-package regression test covers inherited read-only, read-write, explicit read-only and missing proc metadata cases through the real dispatcher without launching the helper. The corrected daemon builds and this regression test passes in an arm64 builder. At that review-correction stage the C helper was unchanged and full runtime checks were not rerun. Issue #3 changes the final poll placement and exit diagnostics and supplies the updated-pair evidence below. The initial runtime hashes above remain historical.

Issue #3 was verified on arm64, Linux 7.1.0, Sysbox 0.7.1 and bubblewrap 0.9.0 using a temporary isolated daemon and a dedicated disposable container. The native BuildKit build used the pinned public Dockerfile inputs and passed all four focused upstream Go tests. The paired artifact SHA-256 values were `sysbox-fs` = `79b3edfdb69c1c36b9fb37f7a8ca7c2608fb52acccc824365abfc5bf83dcff37` and `proc-mount-helper` = `9125ecc309246e2bbdd1c83971a0737f0f7acc122d158eb5f5271a655b88c0fd`.

Passed: the unchanged non-root bwrap command; PID/User namespace separation and seccomp; registered protection identities, masks, read-only policy and detach locks; recursive read-only procfs; preserved `/sys` binds; actual nonleader read-write/read-only mounts in distinct Mount namespaces; all 32 direct-helper checkpoint cases with independent surviving observers; all four historical helper rejection modes; and 500 unchanged mounts with eight workers and concurrent nsenter/FUSE reaping. The checkpoint fixture creates its own notification listener from a trusted namespace-entry launcher, while the actual-path probe retains Sysbox's production seccomp filter. No running host daemon was replaced and no installation/configuration support is claimed. [Runtime instructions](../tests/runtime/README.md) specify reproduction and the distinction between these test paths.

### Verification boundaries

Runtime requires the paired patched daemon and trusted helper, registered container UID/GID maps, a direct child User namespace owning the target Mount/PID namespaces, container root `/`, empty proc data and accepted mount flags. It requires procfs `pidns` FD configuration plus `openat2`, pidfds and the new mount APIs (`fsopen`, `fsconfig`, `fsmount`, `open_tree`, `move_mount`, `mount_setattr`). Other kernels and architectures remain unverified. Issue #3 uses `pidfd_open(actual_tid, PIDFD_THREAD)` for both leader and nonleader requesters. Linux introduced this flag in 6.9; that alone does not establish the minimum kernel for procfs `pidns` or the complete transfer. The historical bubblewrap result covers leader requests only. **The updated pair passed the arm64 runtime checks recorded in Review correction validation on 2026-10-14.** `MS_STRICTATIME` is in the whitelist but fails on this baseline; no blanket flag compatibility is claimed.


The thread API requirement applies to leaders too. Thread pidfd acquisition has no fallback: `EINVAL` (unsupported flag), `ENOSYS` (missing syscall), `ESRCH` (exited TID) and permission/resource errors are returned as their original errno, with a daemon diagnostic containing `PIDFD_THREAD required`. No helper launches and no target changes on acquisition failure. The upstream Go tests inject these failures and assert a single acquisition on the actual TID. Unsupported flag tests are not older-kernel runtime support evidence. The helper reports `ESRCH` for observed exit and `EBADF` for an invalid FD; interrupted polls retry.

The local suite runs actual seccomp notification interruption, thread/process exit and leader/nonleader exec and delayed leader-exit lifecycle tests on the build client's kernel. The public Docker build runs the existing policy regression and the real notification pre-launch regression. These do not establish Sysbox runtime support. `verify.sh` now also invokes the real nonleader mount probe in distinct Mount namespaces, read-write and read-only. The trusted direct-helper checkpoint matrix and its pass criteria are documented in [design](design.md). Run them with the matched pair in the arm64 baseline; publish only architecture, kernel/runtime versions and outcomes. Keep private identifiers and raw logs local.

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
そのレビュー修正時点では C helper は不変でした。
その時点では完全な runtime 検査を再実行していませんでした。
Issue #3 は最後の poll の位置と終了診断を変更し、更新した対を下記のとおり検証しました。
上記の初期 runtime binary hash は過去の記録であり、最終 daemon の hash ではありません。

Issue #3 は arm64、Linux 7.1.0、Sysbox 0.7.1、bubblewrap 0.9.0 で、一時的に隔離した daemon と専用の一時コンテナを使って検証しました。
固定した公開 Dockerfile の入力を使うネイティブ BuildKit ビルドと、対象を絞った Go 検査 4 件が成功しました。
検証した対の SHA-256 は `sysbox-fs` が `79b3edfdb69c1c36b9fb37f7a8ca7c2608fb52acccc824365abfc5bf83dcff37`、`proc-mount-helper` が `9125ecc309246e2bbdd1c83971a0737f0f7acc122d158eb5f5271a655b88c0fd` です。

変更なしの一般ユーザーの bwrap command、PID/User namespace の分離、seccomp、登録済み保護の identity、mask、read-only 属性、detach lock、再帰的 read-only procfs、既存 `/sys` の bind 検査が成功しました。
異なる Mount namespace の非 leader による read-write/read-only mount、存続する別 process から保護を確認する直接 helper の全 32 ケース、既存の拒否検査 4 モード、8 worker と並行 nsenter/FUSE 回収を伴う 500 mount も成功しました。
確認地点の検査用 process は、信頼された namespace entry の起動元から独自の通知 listener を作ります。
実経路の検査は Sysbox の production seccomp filter を保持します。
稼働中ホストの daemon は置き換えておらず、導入や設定の対応を主張する結果ではありません。
再現手順と二つの検査経路の違いは [実行手順](../tests/runtime/README.md) に記載します。

### 検証範囲

実行時には patched daemon と信頼された helper の対、登録済み UID/GID map、target Mount/PID namespace を所有する直接の child User namespace、container root `/`、空の proc data、受理される mount flag が必要です。
procfs の `pidns` FD 設定に加え、`openat2`、pidfd、新しい mount API（`fsopen`、`fsconfig`、`fsmount`、`open_tree`、`move_mount`、`mount_setattr`）を使います。
他の kernel と architecture は未検証です。
Issue #3 は leader と非 leader の両方で `pidfd_open(actual_tid, PIDFD_THREAD)` を使います。
この flag は Linux 6.9 で導入されましたが、procfs の `pidns` や転送全体の最小 kernel を確定するものではありません。
過去の bubblewrap の結果は leader の要求だけを対象とします。
**更新した対は、2026-10-14 に「レビュー修正の検証」節に記載した arm64 実行時検証を通過しました。**
`MS_STRICTATIME` は whitelist に含まれますが、基準環境では失敗します。
全 flag の互換性を主張しません。


thread API は leader にも必要です。
thread pidfd の取得に fallback はありません。
未対応 flag の `EINVAL`、syscall がない場合の `ENOSYS`、終了した TID の `ESRCH`、権限や資源の error は元の errno で返し、daemon は `PIDFD_THREAD required` を含む診断を出します。
取得失敗時は helper を起動せず、target を変更しません。
Go の検査ではこれらの失敗を注入し、実際の TID に対する取得が一回だけであることを確認します。
この検査を古い kernel の実行時対応の証拠にはしません。
helper は検出した終了を `ESRCH`、不正な FD を `EBADF` として返し、中断した poll は再試行します。

ローカル検査はビルド端末の kernel で、実際の seccomp 通知の中断、thread と process の終了、leader と非 leader の exec、leader の先行終了の通知遅延を確認します。
公開 Docker build は既存 policy の回帰検査と、実際の通知を使った起動前の回帰検査を実行します。
これらは Sysbox の実行時対応を確定しません。
`verify.sh` は異なる Mount namespace を使う非 leader の実際の mount を、read-write と read-only の両方で確認します。
信頼された起動元から helper を直接検査する全確認地点の条件と合否基準は [設計](design.md) に記載します。
arm64 の基準環境で対となる binary を使い、architecture、kernel/runtime の版、結果だけを公開します。
非公開の識別子や生ログはローカルに保持します。

実行時 runner は別途取得したホスト PID/User namespace 識別子を要求し、構成済み Sysbox コンテナ内で呼び出し元ユーザーとして動作します。
C compiler、Python 3、bubblewrap は事前に導入します。
ホスト設定やコンテナ構築は行いません。
ローカル静的検査、コンパイル検査、CI native build は packaging の契約を確認し、基準環境の実行時検証を代替しません。
明示的な `--platform` は builder の対応に依存し、実行時対応を拡大しません。
byte 単位で一致する再ビルドや完全な安全性監査は保証しません。
