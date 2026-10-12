FROM debian:trixie

ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update && apt-get install -y --no-install-recommends \
    live-build \
    debootstrap \
    debian-archive-keyring \
    xorriso \
    isolinux \
    syslinux-efi \
    syslinux-common \
    grub-pc-bin \
    grub-efi-amd64-bin \
    mtools \
    curl \
    ca-certificates \
    dosfstools \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /workspace

ENTRYPOINT ["/repo/packaging/iso/build-iso.sh"]
