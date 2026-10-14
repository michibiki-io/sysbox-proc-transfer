# Sysbox proc transfer

## Contents / 目次

- [English](#english): [Build](#build), [Verify](#verify), [License](#license)
- [日本語](#日本語): [ビルド](#ビルド), [検証](#検証), [ライセンス](#ライセンス)
- [Design / 設計](docs/design.md)
- [Security model / 安全性の設計](docs/security-model.md)
- [Compatibility / 動作条件](docs/compatibility.md)

## English

This repository packages the validated Sysbox v0.7.1 patch and C helper that let an unchanged, unprivileged-user bubblewrap `--proc /proc` invocation create procfs for its sandbox PID namespace. A review correction applies the existing outer procfs read-only normalization before nested dispatch; other validated transfer behavior is retained. The implementation preserves registered procfs protections and User/PID/Mount isolation. Its validated baseline is arm64, Linux 7.1, Sysbox 0.7.1 and bubblewrap 0.9.0. Packaging does not broaden runtime support or constitute a full security audit.

### Build

Prerequisites on the build client are Python 3 and Docker CLI with a working buildx/BuildKit builder. No host compiler, Go toolchain or existing Sysbox checkout is needed. All compilation and package installation occur in the builder. Public upstream inputs are fetched over HTTPS.

```sh
python3 scripts/build.py
# Optional single target platform, if the builder supports it:
python3 scripts/build.py --platform linux/arm64 --output dist
```

The default is a native build. `dist/` receives `sysbox-fs`, `proc-mount-helper` and `manifest.json` using BuildKit local output from a scratch stage. The manifest records the output ELF architecture, component revisions, builder digest, generator version and input/output SHA-256 hashes without machine identities or local paths. Treat the two binaries as a matched pair. Set `SYSBOX_PROC_TRANSFER_HELPER` in the `sysbox-fs` process environment to the trusted helper executable's absolute path; an unset variable leaves the original proc mount path active. Protect both executables and that environment from container callers. Host deployment configuration is outside this repository.

[build/sources.lock.json](build/sources.lock.json) is the authoritative pin source. The wrapper supplies its values as Docker build arguments, checks source integrity hashes, and the builder checks root/component commits after recursive submodule initialization. IPC protobuf generation with `protoc-gen-go` v1.3.5 runs before building `sysbox-fs`. A focused upstream-package regression test verifies read-only policy normalization before nested dispatch without executing a helper or changing mounts. The patch retains upstream component paths and is applied at the Sysbox root. The namespace-entry C code is linked into `sysbox-fs`; standalone `sysbox-runc` and `sysbox-mgr` need no replacement for this patch.

Pinned inputs and recorded hashes do not establish byte-identical rebuilds. Builder apt repositories and upstream Go module availability remain external dependencies. A successful build on another architecture is compilation evidence only, not runtime validation. This issue publishes source, not binaries.

### Verify

Focused local checks require Python 3, Bash and a C compiler with Linux headers:

```sh
python3 -m unittest discover -s tests/static -v
```

Runtime verification runs **inside an already provisioned Sysbox container**, as its existing non-root caller. Preinstall `cc`, `/usr/bin/python3` and bubblewrap; scripts install nothing. Supply the actual host PID and User namespace identifiers, obtained independently by the operator, as positional inputs (the `pid:[number]` and `user:[number]` forms returned by `readlink`). Do not derive those inputs from inside the container.

```sh
bash tests/runtime/verify.sh "$HOST_PID_NAMESPACE" "$HOST_USER_NAMESPACE"
# Optional separate stress check in the same container:
python3 tests/runtime/stress-proc.py
```

The verification script uses a caller-owned `mktemp` directory with exit cleanup and paths relative to the script. It checks the original bwrap command, sandbox PID identity, seccomp, registered protection identities, masks, read-only flags, detach denial and recursive read-only procfs. Its `/sys` check covers the preserved tree bound by `--ro-bind /sys /sys`; it does not test a new nested sysfs mount fix. The optional stress case exercises 500 unchanged bwrap mounts with eight workers and concurrent nsenter/FUSE reaping. Runtime results and namespace identifiers are local diagnostics; do not publish raw operational logs.

The existing negative helper tests run from the trusted launcher environment and create only their own disposable sandbox via an operator-supplied container-exec prefix. Python 3.12+ and root access to namespace metadata are required for this harness. It never configures or restarts a daemon. Select one rejection case per invocation; use a dedicated test container.

```sh
python3 tests/runtime/helper-rejections.py \
  --outer-pid "$OUTER_INIT_PID" --helper "$TRUSTED_HELPER" \
  --uid "$CALLER_UID" --gid "$CALLER_GID" --mode wrong-owner \
  --exec docker exec --user "$CALLER_UID:$CALLER_GID" test-container
```

Other modes are `dead-requester`, `unsupported-flags`, and `mapped-launcher`. `OUTER_INIT_PID` must identify the registered outer container in the launcher's proc view. The script locates and kills only its uniquely tagged sandbox through a pinned pidfd; it does not use a supplied arbitrary target PID. Mount work inside the helper continues to use the mapped outer User namespace.

CI runs focused checks and a native container build from public inputs. It does not run the supported Sysbox runtime environment. See [compatibility](docs/compatibility.md) for the distinction between prior baseline results and checks performed on this packaging.

### License

Original helper, validation, build tooling and documentation use the root [MIT license](LICENSE). The Sysbox patch is an Apache-2.0 derivative; upstream attribution and license are retained in [LICENSES/Apache-2.0.txt](LICENSES/Apache-2.0.txt) and [THIRD_PARTY_NOTICES.md](THIRD_PARTY_NOTICES.md). Static binary redistribution requires separate third-party license review, including applicable LGPL obligations; root MIT does not cover every linked dependency.

## 日本語

このリポジトリは、検証済みの Sysbox v0.7.1 patch と C helper を独立利用できる構成にまとめます。
一般ユーザーの bubblewrap 呼び出しを変更せず、`--proc /proc` で sandbox 自身の PID namespace に対応する procfs を作成します。
登録済みの procfs 保護と User/PID/Mount namespace の隔離を維持します。
検証済みの基準環境は arm64、Linux 7.1、Sysbox 0.7.1、bubblewrap 0.9.0 です。
レビューで判明した read-only 継承の抜けを修正し、既存の判定を nested 転送前に適用します。
その他の検証済み処理は維持しています。
今回の整理は動作対応の拡大や完全な安全性監査を意味しません。

### ビルド

ビルドクライアントには Python 3 と、動作する buildx/BuildKit builder を使える Docker CLI が必要です。
ホストの C compiler、Go toolchain、既存 Sysbox checkout は不要です。
コンパイルとパッケージ導入は builder 内で行い、公開 upstream を HTTPS で取得します。

```sh
python3 scripts/build.py
# builder が対応する場合、単一の target platform を指定できます。
python3 scripts/build.py --platform linux/arm64 --output dist
```

既定は native build です。
scratch stage の BuildKit local output から、`dist/` に `sysbox-fs`、`proc-mount-helper`、`manifest.json` を出力します。
manifest は ELF architecture、component revision、builder digest、generator version、input/output SHA-256 を記録し、マシン識別情報やローカルパスを含めません。
二つの binary は同じビルドの対として扱います。
`sysbox-fs` の環境変数 `SYSBOX_PROC_TRANSFER_HELPER` に、信頼する helper executable の絶対パスを指定します。
未設定の場合は従来の proc mount 処理を使用します。
コンテナの呼び出し元が executable や環境変数を書き換えられないように管理します。
ホストの導入設定は本リポジトリの対象外です。

固定値の正本は [build/sources.lock.json](build/sources.lock.json) です。
wrapper は固定値を Docker build argument に渡し、source integrity hash を確認します。
builder は再帰的な submodule 初期化後に root と component の commit を確認します。
`protoc-gen-go` v1.3.5 による IPC protobuf 生成を `sysbox-fs` のビルドより先に実行します。
upstream package 内の対象を絞った regression test で、helper の実行や mount 変更なしに nested 分岐前の read-only 継承を確認します。
patch の upstream component path は保持し、Sysbox root で適用します。
namespace-entry の C コードは `sysbox-fs` にリンクされるため、この patch のために単体の `sysbox-runc` や `sysbox-mgr` を置き換える必要はありません。

固定 input と hash の記録だけでは、再ビルドの byte 単位の一致を保証できません。
builder の apt repository と upstream Go module の可用性は外部依存です。
別 architecture のビルド成功はコンパイルの確認であり、実行時の検証ではありません。
この Issue では source を公開し、binary は公開しません。

### 検証

ローカルの静的検査には Python 3、Bash、Linux header を使える C compiler が必要です。

```sh
python3 -m unittest discover -s tests/static -v
```

実行時検証は、構成済みの Sysbox コンテナ内で既存の一般ユーザーとして実行します。
`cc`、`/usr/bin/python3`、bubblewrap は事前に用意します。
script は依存パッケージを導入しません。
実際のホスト PID/User namespace の識別子を、運用者が別途取得して位置引数に渡します。
形式は `readlink` が返す `pid:[number]` と `user:[number]` です。
コンテナ内から取得した値をホスト識別子として使いません。

```sh
bash tests/runtime/verify.sh "$HOST_PID_NAMESPACE" "$HOST_USER_NAMESPACE"
# 同じコンテナ内で任意に実行する stress check:
python3 tests/runtime/stress-proc.py
```

検証 script は script 相対パスと呼び出し元所有の `mktemp` directory を使い、終了時に作業ファイルを削除します。
元の bwrap command、sandbox PID identity、seccomp、登録済み保護の inode、mask、read-only 属性、detach 拒否、再帰的 read-only procfs を確認します。
`/sys` の検査は `--ro-bind /sys /sys` で保持した tree の確認です。
新しい nested sysfs mount の修正を検証するものではありません。
任意の stress case は、8 worker による 500 回の変更なし bwrap mount と、並行する nsenter/FUSE reaping を確認します。
検査結果と namespace 識別子はローカル診断情報として扱い、実機の生ログを公開しません。

既存の helper 拒否検査は、信頼された launcher 環境で実行します。
運用者が渡すコンテナ内実行コマンドで、この検査専用の sandbox を作成します。
Python 3.12 以降と namespace metadata にアクセスできる root が必要です。
daemon の設定や再起動は行いません。
専用テストコンテナを使い、一回の呼び出しで一つの拒否条件を指定します。

```sh
python3 tests/runtime/helper-rejections.py \
  --outer-pid "$OUTER_INIT_PID" --helper "$TRUSTED_HELPER" \
  --uid "$CALLER_UID" --gid "$CALLER_GID" --mode wrong-owner \
  --exec docker exec --user "$CALLER_UID:$CALLER_GID" test-container
```

他の mode は `dead-requester`、`unsupported-flags`、`mapped-launcher` です。
`OUTER_INIT_PID` には launcher の proc view における登録済み outer container の init PID を渡します。
検査は固有の識別子を付けた自分の sandbox だけを探索し、固定した pidfd で終了させます。
任意の target PID を終了対象として受け取る設計にはしていません。
helper の mount は引き続き外側の mapped User namespace の権限で行います。

CI は静的検査と公開 input からの native container build を実行します。
対応する Sysbox 環境での実行時検証は行いません。
過去の基準結果と今回の packaging の検査の区別は [動作条件](docs/compatibility.md) を参照してください。

### ライセンス

独自の helper、検証コード、build tooling、文書には root の [MIT license](LICENSE) を適用します。
Sysbox patch は Apache-2.0 の派生物です。
upstream の帰属表示と license は [LICENSES/Apache-2.0.txt](LICENSES/Apache-2.0.txt) と [THIRD_PARTY_NOTICES.md](THIRD_PARTY_NOTICES.md) に保持しています。
static binary を再配布する packager は、適用される LGPL の義務を含めて third-party license を別途確認する必要があります。
root の MIT はリンクされる全依存物を対象にしません。
