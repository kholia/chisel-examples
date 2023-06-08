ARG UBUNTU_RELEASE=22.04
ARG USER=app
ARG UID=101
ARG GROUP=app
ARG GID=101

FROM golang:1.20 AS chisel
ARG UBUNTU_RELEASE
RUN git clone -b stunnel-slices https://github.com/kholia/chisel-releases /opt/chisel-releases \
    && git clone --depth 1 -b main https://github.com/kholia/chisel /opt/chisel
WORKDIR /opt/chisel
RUN go generate internal/deb/version.go \
    && go build ./cmd/chisel

FROM public.ecr.aws/ubuntu/ubuntu:$UBUNTU_RELEASE AS builder
# FROM public.ecr.aws/ubuntu/ubuntu:$UBUNTU_RELEASE@sha256:2c1168b31e636c7ab22598bfaefa6de63d1806a908d0c39bd402277881356fab AS builder
SHELL ["/bin/bash", "-oeux", "pipefail", "-c"]
RUN apt-get update \
    && DEBIAN_FRONTEND=noninteractive apt-get install -y ca-certificates busybox-static \
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
        base-files_base \
        base-files_release-info \
        ca-certificates_data \
        libc6_libs \
        stunnel4_bins \
        stunnel4_libs

RUN find /rootfs

# Generate SBOM using the information in urls.txt file

RUN install -d -m 0755 -o $UID -g $GID /rootfs/home/$USER \
    && echo -e "root:x:0:\n$GROUP:x:$GID:" >/rootfs/etc/group \
    && echo -e "root:x:0:0:root:/root:/noshell\n$USER:x:$UID:$GID::/home/$USER:/noshell" >/rootfs/etc/passwd

FROM scratch
ARG USER
ARG UID
ARG GID
USER $UID:$GID
COPY --from=sliced-deps /rootfs /
COPY --from=sliced-deps /bin/busybox /bin
COPY --from=sliced-deps /tmp/urls.txt /root/packages.txt
# Workaround for https://github.com/moby/moby/issues/38710
COPY --from=sliced-deps --chown=$UID:$GID /rootfs/home/$USER /home/$USER
# ENTRYPOINT ["/bin/busybox"]
ENTRYPOINT ["/usr/bin/stunnel4"]
