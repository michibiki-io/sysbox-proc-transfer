# Sysbox proc transfer / Sysbox の procfs 転送

## Table of Contents / 目次

- [English](#english)
  - [Overview](#overview)
  - [Build](#build)
  - [Verify](#verify)
  - [Documentation](#documentation)
  - [License](#license)
- [日本語](#日本語)
  - [概要](#概要)
  - [ビルド](#ビルド)
  - [検証](#検証)
  - [関連文書](#関連文書)
  - [ライセンス](#ライセンス)

- [Sysfs opt-in](#sysfs-opt-in) / [sysfs の有効化](#sysfs-の有効化)

## English

### Overview

This repository packages the validated Sysbox v0.7.1 patch and C helper that let an unchanged, unprivileged-user bubblewrap `--proc /proc` invocation create procfs for its sandbox PID namespace. A review correction applies the existing outer procfs read-only normalization before nested dispatch; other validated transfer behavior is retained. The implementation preserves registered procfs protections and User/PID/Mount isolation. Its validated baseline is arm64, Linux 7.1, Sysbox 0.7.1 and bubblewrap 0.9.0. Issue #3 implements nonleader thread requests using actual-TID thread pidfds and post-pinning notification validation. The updated pair passed arm64 runtime validation, including nonleader mounts and deterministic commit races; see [compatibility](docs/compatibility.md) for evidence and limits. This is not a full security audit.

### Build

Prerequisites on the build client are Python 3 and Docker CLI with a working buildx/BuildKit builder. No host compiler, Go toolchain or existing Sysbox checkout is needed. All compilation and package installation occur in the builder. Public upstream inputs are fetched over HTTPS.

```sh
python3 scripts/build.py
# Optional single target platform, if the builder supports it:
python3 scripts/build.py --platform linux/arm64 --output dist
```

The default is a native build. `dist/` receives `sysbox-fs`, `proc-mount-helper`, `sysfs-mount-helper` and `manifest.json` using BuildKit local output from a scratch stage. The manifest records the output ELF architecture, component revisions, builder digest, generator version and input/output SHA-256 hashes without machine identities or local paths. Treat the three binaries as one build. Set `SYSBOX_PROC_TRANSFER_HELPER` in the `sysbox-fs` process environment to the trusted helper executable's absolute path; an unset variable leaves the original proc mount path active. Protect all three executables and that environment from container callers. Host deployment configuration is outside this repository.

[build/sources.lock.json](build/sources.lock.json) is the authoritative pin source. The wrapper supplies its values as Docker build arguments, checks source integrity hashes, and the builder checks root/component commits after recursive submodule initialization. IPC protobuf generation with `protoc-gen-go` v1.3.5 runs before building `sysbox-fs`. A focused upstream-package regression test verifies read-only policy normalization before nested dispatch without executing a helper or changing mounts. The patch retains upstream component paths and is applied at the Sysbox root. The namespace-entry C code is linked into `sysbox-fs`; standalone `sysbox-runc` and `sysbox-mgr` need no replacement for this patch.

Pinned inputs and recorded hashes do not establish byte-identical rebuilds. Builder apt repositories and upstream Go module availability remain external dependencies. A successful build on another architecture is compilation evidence only, not runtime validation. This repository publishes source, not binaries.

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

The runner also checks nonleader TID != TGID mounts in distinct Mount namespaces, with an independent observer and all visible registered proc submounts. For deterministic exit/invalidation/exec race cases, compile and run the trusted test-only checkpoint harness described in [design](docs/design.md) and [runtime commands](tests/runtime/README.md). Thread pidfds require `PIDFD_THREAD`; unsupported acquisition returns the original errno and never falls back to a TGID or an unprotected mount.

CI runs focused checks and a native container build from public inputs. It does not run the supported Sysbox runtime environment. See [compatibility](docs/compatibility.md) for the distinction between prior baseline results and checks performed on this packaging.

### Documentation

- [Design](docs/design.md): procfs transfer flow and the internal daemon/helper contract.
- [Security model](docs/security-model.md): authorization, namespace isolation and registered procfs protections.
- [Compatibility](docs/compatibility.md): validated conditions, review correction checks and remaining limitations.

### License

Original helper, validation, build tooling and documentation use the root [MIT license](LICENSE). The Sysbox portions of the patches are Apache-2.0 derivatives; the pinned FUSE-library change retains its [BSD notice](LICENSES/bazil-fuse.txt); upstream attribution and license are retained in [LICENSES/Apache-2.0.txt](LICENSES/Apache-2.0.txt) and [THIRD_PARTY_NOTICES.md](THIRD_PARTY_NOTICES.md). Static binary redistribution requires separate third-party license review, including applicable LGPL obligations; root MIT does not cover every linked dependency.

### Sysfs opt-in

Issue #5 adds a separate opt-in sysfs path. Set the trusted daemon environment `SYSBOX_SYSFS_TRANSFER_HELPER` to the absolute path of `sysfs-mount-helper`. Unset preserves upstream sysfs dispatch. The proc helper source and FD protocol remain unchanged. Builds export all three binaries plus their manifest; deploy them from the same build. The new sysfs path and FUSE repair are separate from existing proc import acceptance. **AC7 is deferred/unrun until talos-sysbox-installer integration on genuine amd64/6.18.18-talos, Sysbox 0.7.1 and bwrap 0.12.0.** Compilation and supplemental arm64 tests do not establish that support.

Use [runtime instructions](tests/runtime/README.md) for the new nonleader sysfs probe and direct lifecycle fixture. Preserve all outer masks/read-only mounts and the original bwrap proc and `/sys` bind checks. Production helpers never accept test checkpoint sockets. No installer, host daemon or cluster changes are supplied.

## 日本語

### 概要

このリポジトリは、検証済みの Sysbox v0.7.1 のパッチと C 製の補助プログラム（**helper**）を、独立して利用できる構成にまとめます。
一般ユーザーの bubblewrap 呼び出しを変更せず、`--proc /proc` で sandbox 自身の PID 名前空間に対応する procfs を作成します。
レビューで判明した読み取り専用属性の継承漏れを修正し、既存の判定を入れ子の名前空間への転送前に適用します。
その他の検証済み処理は維持しています。
登録済みの procfs 保護と User/PID/Mount 名前空間の隔離を維持します。
検証済みの基準環境は arm64、Linux 7.1、Sysbox 0.7.1、bubblewrap 0.9.0 です。
Issue #3 は実際の TID の thread pidfd と FD 固定後の通知確認により、非 leader の要求に対応する処理を実装します。
更新した対は arm64 の実行時検証で、非 leader の mount と決定的な commit の競合検査を通過しました。
証跡と検証範囲は [動作条件](docs/compatibility.md) に記載します。
完全な安全性監査を意味しません。

### ビルド

ビルドを実行するクライアントには Python 3 と Docker CLI が必要です。
Docker CLI から buildx/BuildKit のビルダーを利用できるように構成します。
ホストに C コンパイラーや Go ツールチェーン、既存の Sysbox チェックアウトを用意する必要はありません。
コンパイルとパッケージの導入はビルダー内で行い、公開されている upstream の入力を HTTPS で取得します。

```sh
python3 scripts/build.py
# ビルダーが対応する場合、単一の対象プラットフォームを指定できます。
python3 scripts/build.py --platform linux/arm64 --output dist
```

既定ではビルダーのネイティブアーキテクチャ向けにビルドします。
scratch ステージから BuildKit のローカル出力を使い、`dist/` に `sysbox-fs`、`proc-mount-helper`、`sysfs-mount-helper`、`manifest.json` を出力します。
manifest は ELF のアーキテクチャ、コンポーネントのリビジョン、ビルダーのダイジェスト、生成器のバージョン、入出力の SHA-256 を記録します。
マシン識別情報やローカルパスは含めません。
三つのバイナリは同じビルドの組み合わせとして扱います。
`sysbox-fs` の環境変数 `SYSBOX_PROC_TRANSFER_HELPER` に、信頼する helper の実行ファイルの絶対パスを指定します。
未設定の場合は従来の proc mount 処理を使用します。
コンテナの呼び出し元が実行ファイルや環境変数を書き換えられないように管理します。
ホストの導入設定は本リポジトリの対象外です。

固定値の正本は [build/sources.lock.json](build/sources.lock.json) です。
ビルドスクリプトは固定値を Docker のビルド引数に渡し、ソースの整合性をハッシュで確認します。
ビルダーはサブモジュールを再帰的に初期化した後、ルートと各コンポーネントのコミットを確認します。
`protoc-gen-go` v1.3.5 による IPC protobuf 生成を `sysbox-fs` のビルドより先に実行します。
upstream パッケージ内の回帰テストで、helper の実行や mount の変更なしに、入れ子の名前空間を扱う分岐より前の読み取り専用属性の継承を確認します。
パッチは upstream のコンポーネントパスを保持し、Sysbox のルートディレクトリで適用します。
名前空間に入る処理の C コードは `sysbox-fs` にリンクされるため、このパッチのために単体の `sysbox-runc` や `sysbox-mgr` を置き換える必要はありません。

入力の固定とハッシュの記録だけでは、再ビルド時にバイト単位で一致することを保証できません。
ビルダーの apt リポジトリと upstream の Go モジュールの可用性は外部依存です。
別のアーキテクチャでのビルド成功はコンパイルの確認であり、実行時の検証ではありません。
このリポジトリではソースを公開し、バイナリは公開しません。

### 検証

ローカルの静的検査には Python 3、Bash、Linux ヘッダーを使える C コンパイラーが必要です。

```sh
python3 -m unittest discover -s tests/static -v
```

実行時検証は、構成済みの Sysbox コンテナ内で既存の一般ユーザーとして実行します。
`cc`、`/usr/bin/python3`、bubblewrap は事前に用意します。
スクリプトは依存パッケージを導入しません。
実際のホスト PID/User 名前空間の識別子を、運用者が別途取得して位置引数に渡します。
形式は `readlink` が返す `pid:[number]` と `user:[number]` です。
コンテナ内から取得した値をホスト識別子として使いません。

```sh
bash tests/runtime/verify.sh "$HOST_PID_NAMESPACE" "$HOST_USER_NAMESPACE"
# 同じコンテナ内で任意に実行する負荷検査:
python3 tests/runtime/stress-proc.py
```

検証スクリプトは自身の配置先からの相対パスと、呼び出し元が所有する `mktemp` ディレクトリを使います。
作業ファイルは終了時に削除します。
元の bwrap コマンド、sandbox の PID 名前空間との一致、seccomp、登録済み保護の inode、マスク、読み取り専用属性、取り外しの拒否、再帰的に読み取り専用にした procfs を確認します。
`/sys` の検査対象は、`--ro-bind /sys /sys` で保持した既存のツリーです。
新しい入れ子の sysfs mount の修正を検証するものではありません。
任意の負荷検査では、8 ワーカーによる 500 回の変更なしの bwrap mount と、並行する nsenter/FUSE プロセスの回収を確認します。
検査結果と名前空間の識別子はローカルの診断情報として扱い、実機の生ログを公開しません。

既存の helper 拒否検査は、信頼された起動元の環境で実行します。
運用者が渡すコンテナ内実行コマンドで、この検査専用の sandbox を作成します。
Python 3.12 以降と、名前空間のメタデータにアクセスできる root 権限が必要です。
デーモンの設定や再起動は行いません。
専用テストコンテナを使い、一回の呼び出しで一つの拒否条件を指定します。

```sh
python3 tests/runtime/helper-rejections.py \
  --outer-pid "$OUTER_INIT_PID" --helper "$TRUSTED_HELPER" \
  --uid "$CALLER_UID" --gid "$CALLER_GID" --mode wrong-owner \
  --exec docker exec --user "$CALLER_UID:$CALLER_GID" test-container
```

他の検査モードは `dead-requester`、`unsupported-flags`、`mapped-launcher` です。
`OUTER_INIT_PID` には、起動元の procfs から見た、登録済み外側コンテナの init PID を渡します。
検査は固有の識別子を付けた自身の sandbox だけを探索し、固定した pidfd で終了させます。
終了対象として任意の PID を受け取ることはありません。
helper の mount は引き続き、UID/GID をマッピングした外側の User 名前空間の権限で行います。

runner は TID と TGID が異なる非 leader の mount を、異なる Mount namespace と独立した観測 process で確認し、見える登録済み proc submount をすべて検査します。
終了、通知失効、exec の競合を決定的に検査する手順は [設計](docs/design.md) と [実行コマンド](tests/runtime/README.md) に記載します。
thread pidfd には `PIDFD_THREAD` が必要で、未対応の場合は元の errno で拒否します。
TGID への置き換えや保護のない mount への fallback はありません。

CI は静的検査と、公開されている入力からのネイティブコンテナビルドを実行します。
対応する Sysbox 環境での実行時検証は行いません。
過去の基準環境での検証結果と、本リポジトリの構成で実施した検査の区別は、[動作条件](docs/compatibility.md) を参照してください。

### 関連文書

- [設計](docs/design.md)：procfs 転送の流れとデーモン/helper 間の内部契約。
- [安全性の設計](docs/security-model.md)：認証、名前空間の隔離、登録済みの procfs 保護。
- [動作条件](docs/compatibility.md)：検証済みの条件、レビュー修正の検査、残る制約。

### ライセンス

独自の helper、検証コード、ビルドツール、文書には、ルートディレクトリの [MIT ライセンス](LICENSE) を適用します。
パッチの Sysbox 部分は Apache-2.0 の派生物です。
固定した FUSE library の変更部分は [BSD の表示](LICENSES/bazil-fuse.txt) を保持します。
upstream の帰属表示とライセンスは [LICENSES/Apache-2.0.txt](LICENSES/Apache-2.0.txt) と [THIRD_PARTY_NOTICES.md](THIRD_PARTY_NOTICES.md) に保持しています。
静的リンクしたバイナリを再配布する場合は、適用される LGPL の義務を含め、第三者のライセンスを別途確認する必要があります。
ルートディレクトリの MIT ライセンスは、リンクされるすべての依存物を対象にするものではありません。

### sysfs の有効化

Issue #5 は sysfs 用の独立した opt-in 経路を追加します。
信頼された daemon の環境変数 `SYSBOX_SYSFS_TRANSFER_HELPER` に `sysfs-mount-helper` の絶対パスを指定します。
未設定時の sysfs dispatch と既存 proc helper のソース、FD 契約を維持します。
ビルドは三つの binary と manifest を出力し、同じビルドの組み合わせとして管理します。
新しい sysfs と FUSE 修正の受け入れ条件は既存 proc の取り込み条件から独立しています。
**AC7 の amd64、6.18.18-talos、Sysbox 0.7.1、bwrap 0.12.0 実環境検証は、talos-sysbox-installer 取り込み時まで deferred/unrun とします。**
コンパイルや arm64 の補助検査では代替しません。

新しい非 leader の sysfs probe と直接起動の lifecycle fixture は [実行手順](tests/runtime/README.md) を参照してください。
外側の mask と read-only mount、元の bwrap proc と `/sys` bind 検査を維持します。
production helper は checkpoint socket を受け付けません。
installer、ホスト daemon、cluster の設定変更は提供しません。
