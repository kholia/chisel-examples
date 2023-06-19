ARG UBUNTU_RELEASE=22.04
ARG USER=app
ARG UID=101
ARG GROUP=app
ARG GID=101

FROM golang:1.18 AS chisel
ARG UBUNTU_RELEASE
RUN git clone -b jre8-jammy-slices https://github.com/kholia/chisel-releases /opt/chisel-releases \
    && git clone --depth 1 -b main https://github.com/canonical/chisel /opt/chisel
WORKDIR /opt/chisel
RUN go generate internal/deb/version.go \
    && go build ./cmd/chisel

FROM public.ecr.aws/ubuntu/ubuntu:$UBUNTU_RELEASE@sha256:2c1168b31e636c7ab22598bfaefa6de63d1806a908d0c39bd402277881356fab AS builder
SHELL ["/bin/bash", "-oeux", "pipefail", "-c"]
RUN apt-get update \
    && DEBIAN_FRONTEND=noninteractive apt-get install -y ca-certificates \
        ca-certificates-java \
    && apt-get clean -y \
    && rm -rf /var/lib/apt/lists/*
COPY --from=chisel /opt/chisel/chisel /usr/bin/

### BOILERPLATE END ###

FROM builder AS sliced-deps
ARG USER
ARG UID
ARG GROUP
ARG GID
SHELL ["/bin/bash", "-oeux", "pipefail", "-c"]
COPY --from=chisel /opt/chisel-releases /opt/chisel-releases
RUN mkdir -p /rootfs \
      && chisel cut --release /opt/chisel-releases --root /rootfs \
        openjdk-8-jre-headless_core \
        openjdk-8-jre-headless_locale \
        openjdk-8-jre-headless_security \
        openjdk-8-jre-headless_management \
        openjdk-8-jre-headless_jfr \
        openjdk-8-jre-headless_tools \
        openjdk-8-jre-headless_jplis \
        openjdk-8-jre-headless_jndidns \
        openjdk-8-jre-headless_zipfs \
        openjdk-8-jre-headless_sctp \
        media-types_data \
        base-files_bin \
    && ln -s "$(find /rootfs/usr/lib/jvm/java-8-openjdk-*/jre/bin -name java | sed 's/\/rootfs//')" /rootfs/usr/bin/
RUN install -d -m 0755 -o $UID -g $GID /rootfs/home/$USER \
    && echo -e "root:x:0:\n$GROUP:x:$GID:" >/rootfs/etc/group \
    && echo -e "root:x:0:0:root:/root:/noshell\n$USER:x:$UID:$GID::/home/$USER:/noshell" >/rootfs/etc/passwd
COPY --from=builder /etc/ssl/certs/java/cacerts /rootfs/etc/ssl/certs/java/cacerts

FROM scratch
ARG USER
ARG UID
ARG GID
USER $UID:$GID
COPY --from=sliced-deps /rootfs /
# Workaround for https://github.com/moby/moby/issues/38710
COPY --from=sliced-deps --chown=$UID:$GID /rootfs/home/$USER /home/$USER
ENTRYPOINT ["/usr/bin/java"]
