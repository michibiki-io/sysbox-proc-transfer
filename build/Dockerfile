ARG BUILDER_IMAGE
FROM ${BUILDER_IMAGE} AS build
ARG ROOT_REV
ARG FS_REV
ARG RUNC_REV
ARG IPC_REV
ARG LIBS_REV
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
    && test "$(git -C sysbox-libs rev-parse HEAD)" = "$LIBS_REV"
COPY patches/proc-transfer.patch /src/proc-transfer.patch
RUN cd /src/sysbox && patch -p1 < /src/proc-transfer.patch
RUN PATH="/go/bin:$PATH" make -C /src/sysbox/sysbox-ipc sysbox-ipc \
    && test -s /src/sysbox/sysbox-ipc/sysboxFsGrpc/sysboxFsProtobuf/sysboxFsProtobuf.pb.go \
    && test -s /src/sysbox/sysbox-ipc/sysboxMgrGrpc/sysboxMgrProtobuf/sysboxMgrProtobuf.pb.go
WORKDIR /src/sysbox/sysbox-fs
RUN CGO_ENABLED=1 go build -buildvcs=false -trimpath -tags 'netgo osusergo' \
    -ldflags "-linkmode external -extldflags -static -X main.edition=Community -X main.version=0.7.1-proc-transfer -X main.commitId=${FS_REV}+proc-transfer" \
    -o /out/sysbox-fs ./cmd/sysbox-fs
COPY helper/proc-mount-helper.c /src/proc-mount-helper.c
RUN cc -O2 -Wall -Wextra -Werror -static /src/proc-mount-helper.c -o /out/proc-mount-helper
FROM scratch AS export
COPY --from=build /out/sysbox-fs /sysbox-fs
COPY --from=build /out/proc-mount-helper /proc-mount-helper
