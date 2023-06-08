ARG UBUNTU_RELEASE=22.04
ARG USER=app
ARG UID=101
ARG GROUP=app
ARG GID=101

FROM golang:1.20 AS chisel
ARG UBUNTU_RELEASE
RUN git clone -b stunnel-slices-v2 https://github.com/kholia/chisel-releases /opt/chisel-releases \
    && git clone --depth 1 -b main https://github.com/kholia/chisel /opt/chisel
WORKDIR /opt/chisel
RUN go generate internal/deb/version.go \
    && go build ./cmd/chisel

FROM public.ecr.aws/ubuntu/ubuntu:$UBUNTU_RELEASE AS builder
SHELL ["/bin/bash", "-oeux", "pipefail", "-c"]
RUN apt-get update \
    && DEBIAN_FRONTEND=noninteractive apt-get install -y ca-certificates busybox-static wget file \
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
RUN wget https://raw.githubusercontent.com/canonical/rocks-toolbox/main/chisel-wrapper && chmod +x chisel-wrapper && mkdir -p /rootfs/var/lib/dpkg/
RUN mkdir -p /rootfs \
      && ./chisel-wrapper --generate-dpkg-status /rootfs/var/lib/dpkg/status -- --release /opt/chisel-releases --root /rootfs \
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
COPY --from=sliced-deps /tmp/urls.txt /packages.txt
# Workaround for https://github.com/moby/moby/issues/38710
COPY --from=sliced-deps --chown=$UID:$GID /rootfs/home/$USER /home/$USER
ENTRYPOINT ["/usr/bin/stunnel4"]
