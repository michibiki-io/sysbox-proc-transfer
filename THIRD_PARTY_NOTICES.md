# Third-party notices / 第三者の帰属表示

## Contents / 目次

- [English](#english)
- [日本語](#日本語)

## English

`patches/proc-transfer.patch` and `patches/sysfs-transfer.patch` modify Sysbox v0.7.1 `sysbox-fs` and the `sysbox-runc` namespace-entry source linked into it. The Sysbox changes are Apache-2.0 derivatives. The sysfs patch also modifies the pinned nestybox/fuse `bazil/fs/serve.go`; that portion retains its BSD terms and Tommi Virtanen / Go Authors copyright notices in [LICENSES/bazil-fuse.txt](LICENSES/bazil-fuse.txt). The patch is a prominent record of modifications; applying it retains existing upstream file copyright/license headers. The upstream Sysbox license, including **Copyright 2020 Nestybox, Inc.**, is reproduced unchanged in `LICENSES/Apache-2.0.txt`. Public source repositories and immutable component revisions are recorded in `build/sources.lock.json`.

The independently authored C helper, portable validation programs, packaging scripts and documentation use the root MIT license, Copyright (c) 2026 michibiki.io. This does not relicense upstream Sysbox, its dependencies or generated protobuf code.

No prebuilt binaries are distributed in this issue. A packager redistributing the statically linked outputs must identify the dependencies actually linked, retain applicable licenses/copyright/NOTICE material, provide corresponding source or relinking materials where required (including applicable LGPL obligations), and satisfy each dependency's redistribution conditions. Root MIT is not a binary license inventory or a substitute for those obligations. The builder's package inputs and Go dependencies must be reviewed for the actual build; this source package does not fabricate a complete binary dependency inventory.

## 日本語

`patches/proc-transfer.patch` と `patches/sysfs-transfer.patch` は Sysbox v0.7.1 の `sysbox-fs` と、そこにリンクする `sysbox-runc` namespace-entry source を変更する Apache-2.0 の派生物です。
sysfs patch は固定した nestybox/fuse の `bazil/fs/serve.go` も変更します。
この部分の BSD 条項と Tommi Virtanen / Go Authors の著作権表示は [LICENSES/bazil-fuse.txt](LICENSES/bazil-fuse.txt) に保持します。
patch が変更箇所を明示し、適用時には upstream file の copyright/license header を保持します。
**Copyright 2020 Nestybox, Inc.** を含む upstream Sysbox license は、`LICENSES/Apache-2.0.txt` に変更せず収録しています。
公開 source repository と固定 component revision は `build/sources.lock.json` に記録しています。

独自の C helper、移植可能な検証プログラム、packaging script、文書には root の MIT license（Copyright (c) 2026 michibiki.io）を適用します。
upstream Sysbox、その依存物、生成 protobuf code の license を変更しません。

この Issue では事前ビルド済み binary を配布しません。
static linked output を再配布する packager は、実際にリンクした依存物を特定し、適用される license、copyright、NOTICE を保持する必要があります。
適用される LGPL の義務を含め、必要な対応 source や relink 用資料を用意し、各依存物の再配布条件を満たしてください。
root の MIT は binary license inventory でも、これらの義務の代替でもありません。
実際のビルドで builder package と Go dependency を確認する必要があります。
この source package は完全な binary dependency inventory を作成したとは主張しません。
