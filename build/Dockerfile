ARG BUILDER_IMAGE
FROM ${BUILDER_IMAGE} AS build
ARG ROOT_REV
ARG FS_REV
ARG RUNC_REV
ARG IPC_REV
ARG LIBS_REV
ARG FUSE_REV
ARG PROTOC_GEN_GO
RUN apt-get update \
    && apt-get install -y --no-install-recommends git patch make protobuf-compiler libprotobuf-dev gcc libc6-dev libseccomp-dev pkg-config ca-certificates \
    && test -s /usr/include/google/protobuf/timestamp.proto \
    && mkdir -p /usr/local/include \
    && ln -s /usr/include/google /usr/local/include/google \
    && rm -rf /var/lib/apt/lists/*
# Upstream IPC Makefiles use the legacy --go_out=plugins=grpc interface.
RUN go install "${PROTOC_GEN_GO}"
WORKDIR /src
RUN git clone --depth 1 --branch v0.7.1 https://github.com/nestybox/sysbox.git \
    && cd sysbox \
    && test "$(git rev-parse HEAD)" = "$ROOT_REV" \
    && git submodule update --init --recursive sysbox-fs sysbox-ipc sysbox-libs sysbox-runc \
    && test "$(git -C sysbox-fs rev-parse HEAD)" = "$FS_REV" \
    && test "$(git -C sysbox-runc rev-parse HEAD)" = "$RUNC_REV" \
    && test "$(git -C sysbox-ipc rev-parse HEAD)" = "$IPC_REV" \
    && test "$(git -C sysbox-libs rev-parse HEAD)" = "$LIBS_REV" \
    && test "$(git -C sysbox-fs/bazil rev-parse HEAD)" = "$FUSE_REV"
COPY patches/proc-transfer.patch /src/proc-transfer.patch
COPY patches/sysfs-transfer.patch /src/sysfs-transfer.patch
RUN cd /src/sysbox && patch -p1 < /src/proc-transfer.patch && patch -p1 < /src/sysfs-transfer.patch
RUN PATH="/go/bin:$PATH" make -C /src/sysbox/sysbox-ipc sysbox-ipc \
    && test -s /src/sysbox/sysbox-ipc/sysboxFsGrpc/sysboxFsProtobuf/sysboxFsProtobuf.pb.go \
    && test -s /src/sysbox/sysbox-ipc/sysboxMgrGrpc/sysboxMgrProtobuf/sysboxMgrProtobuf.pb.go
WORKDIR /src/sysbox/sysbox-fs
COPY tests/upstream/proc_policy_test.go /src/sysbox/sysbox-fs/seccomp/proc_policy_test.go
COPY tests/unit/lifecycle.c /src/sysbox/sysbox-fs/seccomp/testdata/proc_lifecycle.c
COPY tests/upstream/sysfs_policy_test.go /src/sysbox/sysbox-fs/sysfstransfer/policy_test.go
COPY tests/upstream/sysfs_snapshot_test.go /src/sysbox/sysbox-fs/mount/sysfs_snapshot_test.go
COPY tests/upstream/sysfs_metadata_test.go /src/sysbox/sysbox-fs/handler/implementations/sysfs_metadata_test.go
# Pinned upstream external-package tests have obsolete mocks; compile the full
# production handler package with only this focused regression.
RUN CGO_ENABLED=1 go test $(find handler/implementations -maxdepth 1 -name '*.go' ! -name '*_test.go' -print) handler/implementations/sysfs_metadata_test.go -run '^TestNetwork(SourceMetadata|MetadataGrandchild)$' -count=1
COPY tests/upstream/sysfs_dentry_test.go /src/sysbox/sysbox-fs/fuse/sysfs_dentry_test.go
RUN CGO_ENABLED=1 go test $(find fuse -maxdepth 1 -name '*.go' ! -name '*_test.go' -print) fuse/sysfs_dentry_test.go -run '^TestProtectedNetworkLookupFailure$' -count=1
COPY tests/upstream/fuse_container_test.go /src/sysbox/sysbox-fs/fuse/fuse_container_test.go
RUN CGO_ENABLED=1 go test $(find fuse -maxdepth 1 -name '*.go' ! -name '*_test.go' -print) fuse/fuse_container_test.go -run '^TestNetworkOwningContainer$' -count=1
COPY tests/upstream/fuse_identity_test.go /src/sysbox/sysbox-fs/bazil/fs/lookup_identity_test.go
RUN cd bazil && CGO_ENABLED=1 go test $(find fs -maxdepth 1 -name '*.go' ! -name '*_test.go' -print) fs/lookup_identity_test.go -run '^Test(LookupIdentityFreshAttributes|GetattrDispatchInode)$' -count=1
RUN CGO_ENABLED=1 go test ./mount -run '^TestSysfsRegistration(Snapshot|RootMetadata)$' -count=1
RUN CGO_ENABLED=1 go test ./sysfstransfer
RUN CGO_ENABLED=1 go test -tags 'netgo osusergo' ./seccomp -run '^TestProc(PolicyBeforeNestedTransfer|RequesterThreadPidfd|TransferInvalidNotificationDoesNotLaunch|TransferRealNotification)$' -count=1
RUN CGO_ENABLED=1 go build -buildvcs=false -trimpath -tags 'netgo osusergo' \
    -ldflags "-linkmode external -extldflags -static -X main.edition=Community -X main.version=0.7.1-proc-sysfs-transfer -X main.commitId=${FS_REV}+proc-sysfs-transfer" \
    -o /out/sysbox-fs ./cmd/sysbox-fs
COPY helper/sysfs-mount-helper.c /src/sysfs-mount-helper.c
RUN cc -O2 -Wall -Wextra -Werror -static /src/sysfs-mount-helper.c -o /out/sysfs-mount-helper
COPY helper/proc-mount-helper.c /src/proc-mount-helper.c
RUN cc -O2 -Wall -Wextra -Werror -static /src/proc-mount-helper.c -o /out/proc-mount-helper
FROM scratch AS export
COPY --from=build /out/sysbox-fs /sysbox-fs
COPY --from=build /out/proc-mount-helper /proc-mount-helper
COPY --from=build /out/sysfs-mount-helper /sysfs-mount-helper
