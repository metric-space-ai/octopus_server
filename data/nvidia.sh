#!/bin/sh

apt-get install -y \
    libnvidia-cfg1-550 \
    libnvidia-common-550 \
    libnvidia-compute-550 \
    libnvidia-decode-550 \
    libnvidia-encode-550 \
    libnvidia-extra-550 \
    libnvidia-fbc1-550 \
    libnvidia-gl-550 \
    nvidia-compute-utils-550 \
    nvidia-dkms-550 \
    nvidia-driver-550 \
    nvidia-firmware-550-550.120 \
    nvidia-kernel-common-550 \
    nvidia-kernel-source-550 \
    nvidia-utils-550 \
    xserver-xorg-video-nvidia-550

apt-mark hold \
    libnvidia-cfg1-550 \
    libnvidia-common-550 \
    libnvidia-compute-550 \
    libnvidia-decode-550 \
    libnvidia-encode-550 \
    libnvidia-extra-550 \
    libnvidia-fbc1-550 \
    libnvidia-gl-550 \
    nvidia-compute-utils-550 \
    nvidia-dkms-550 \
    nvidia-driver-550 \
    nvidia-firmware-550-550.120 \
    nvidia-kernel-common-550 \
    nvidia-kernel-source-550 \
    nvidia-utils-550 \
    xserver-xorg-video-nvidia-550
