#!/bin/bash

DATABASE_PASSWORD=""
DOMAIN=""
PROCEED="true"

save_env() {
    echo "$1=\"$2\"" | tee -a .env.install
}

install_base_utils() {
    echo "Installing base utils..."

    apt-get update && apt-get install -y \
        curl \
        git \
        wget
}

install_dialog() {
    echo "Installing dialog..."

    apt-get update && apt-get install -y dialog
}

install_go() {
    echo "Installing Go..."

    if [ -d /target ]
    then
        echo "Deleting old /target"
        rm -rf /target
    fi

    PATH="/usr/local/go/bin:$PATH"
    GOLANG_VERSION="1.23.6"
    set -eux; \
        now="$(date '+%s')"; \
        arch="$(dpkg --print-architecture)"; arch="${arch##*-}"; \
        url=; \
        case "$arch" in \
            'amd64') \
                url='https://dl.google.com/go/go1.23.6.linux-amd64.tar.gz'; \
                sha256='9379441ea310de000f33a4dc767bd966e72ab2826270e038e78b2c53c2e7802d'; \
                ;; \
            'armhf') \
                url='https://dl.google.com/go/go1.23.6.linux-armv6l.tar.gz'; \
                sha256='27a4611010c16b8c4f37ade3aada55bd5781998f02f348b164302fd5eea4eb74'; \
                ;; \
            'arm64') \
                url='https://dl.google.com/go/go1.23.6.linux-arm64.tar.gz'; \
                sha256='561c780e8f4a8955d32bf72e46af0b5ee5e0debe1e4633df9a03781878219202'; \
                ;; \
            'i386') \
                url='https://dl.google.com/go/go1.23.6.linux-386.tar.gz'; \
                sha256='e61f87693169c0bbcc43363128f1e929b9dff0b7f448573f1bdd4e4a0b9687ba'; \
                ;; \
            'mips64el') \
                url='https://dl.google.com/go/go1.23.6.linux-mips64le.tar.gz'; \
                sha256='74ca7bc475bcc084c6718b74df024d7de9612932cea8a6dc75e29d3a5315a23a'; \
                ;; \
            'ppc64el') \
                url='https://dl.google.com/go/go1.23.6.linux-ppc64le.tar.gz'; \
                sha256='0f817201e83d78ddbfa27f5f78d9b72450b92cc21d5e045145efacd0d3244a99'; \
                ;; \
            'riscv64') \
                url='https://dl.google.com/go/go1.23.6.linux-riscv64.tar.gz'; \
                sha256='f95f7f817ab22ecab4503d0704d6449ea1aa26a595f57bf9b9f94ddf2aa7c1f3'; \
                ;; \
            's390x') \
                url='https://dl.google.com/go/go1.23.6.linux-s390x.tar.gz'; \
                sha256='321e7ed0d5416f731479c52fa7610b52b8079a8061967bd48cec6d66f671a60e'; \
                ;; \
            *) echo >&2 "error: unsupported architecture '$arch' (likely packaging update needed)"; exit 1 ;; \
        esac; \
        \
        wget -O go.tgz.asc "$url.asc"; \
        wget -O go.tgz "$url" --progress=dot:giga; \
        echo "$sha256 *go.tgz" | sha256sum -c -; \
        \
        GNUPGHOME="$(mktemp -d)"; export GNUPGHOME; \
        gpg --batch --keyserver keyserver.ubuntu.com --recv-keys 'EB4C 1BFD 4F04 2F6D DDCC  EC91 7721 F63B D38B 4796'; \
        gpg --batch --keyserver keyserver.ubuntu.com --recv-keys '2F52 8D36 D67B 69ED F998  D857 78BD 6547 3CB3 BD13'; \
        gpg --batch --verify go.tgz.asc go.tgz; \
        gpgconf --kill all; \
        rm -rf "$GNUPGHOME" go.tgz.asc; \
        \
        tar -C /usr/local -xzf go.tgz; \
        rm go.tgz; \
        \
        SOURCE_DATE_EPOCH="$(stat -c '%Y' /usr/local/go)"; \
        export SOURCE_DATE_EPOCH; \
        touchy="$(date -d "@$SOURCE_DATE_EPOCH" '+%Y%m%d%H%M.%S')"; \
        date --date "@$SOURCE_DATE_EPOCH" --rfc-2822; \
        [ "$SOURCE_DATE_EPOCH" -lt "$now" ]; \
        \
        if [ "$arch" = 'armhf' ]; then \
            [ -s /usr/local/go/go.env ]; \
            before="$(go env GOARM)"; [ "$before" != '7' ]; \
            { \
                echo; \
                echo '# https://github.com/docker-library/golang/issues/494'; \
                echo 'GOARM=7'; \
            } >> /usr/local/go/go.env; \
            after="$(go env GOARM)"; [ "$after" = '7' ]; \
            touch -t "$touchy" /usr/local/go/go.env /usr/local/go; \
        fi; \
        \
        mkdir /target /target/usr /target/usr/local; \
        mv -vT /usr/local/go /target/usr/local/go; \
        ln -svfT /target/usr/local/go /usr/local/go; \
        touch -t "$touchy" /target/usr/local /target/usr /target; \
        \
        go version; \
        epoch="$(stat -c '%Y' /target/usr/local/go)"; \
        [ "$SOURCE_DATE_EPOCH" = "$epoch" ]; \
        find /target -newer /target/usr/local/go -exec sh -c 'ls -ld "$@" && exit "$#"' -- '{}' +

    set -eux; \
        apt-get update; \
        apt-get install -y --no-install-recommends \
            g++ \
            gcc \
            libc6-dev \
            make \
            pkg-config \
        ; \
        rm -rf /var/lib/apt/lists/*

    GOTOOLCHAIN="local"
    GOPATH="/go"
    PATH="$GOPATH/bin:/usr/local/go/bin:$PATH"
    mkdir -p "$GOPATH/src" "$GOPATH/bin" && chmod -R 1777 "$GOPATH"
}

install_miniconda() {
    echo "Installing Miniconda..."

    if [ -f /etc/profile.d/conda.sh ]
    then
        echo "Deleting old /etc/profile.d/conda.sh"
        rm -rf /etc/profile.d/conda.sh
    fi

    if [ -d /opt/conda ]
    then
        echo "Deleting old /opt/conda"
        rm -rf /opt/conda
    fi

    LANG="C.UTF-8"
    LC_ALL="C.UTF-8"

    apt-get update -q && \
        apt-get install -q -y --no-install-recommends \
            bzip2 \
            ca-certificates \
            git \
            libglib2.0-0 \
            libsm6 \
            libxext6 \
            libxrender1 \
            mercurial \
            openssh-client \
            procps \
            subversion \
            wget \
        && apt-get clean \
        && rm -rf /var/lib/apt/lists/*

    PATH="/opt/conda/bin:$PATH"

    INSTALLER_URL_LINUX64="https://repo.anaconda.com/miniconda/Miniconda3-py312_25.1.1-2-Linux-x86_64.sh"
    SHA256SUM_LINUX64="4766d85b5f7d235ce250e998ebb5a8a8210cbd4f2b0fea4d2177b3ed9ea87884"
    INSTALLER_URL_S390X="https://repo.anaconda.com/miniconda/Miniconda3-py312_25.1.1-2-Linux-s390x.sh"
    SHA256SUM_S390X="55c681937c27e13a8ed818d1fec182e623e0308fffc1b10605896dac15f90077"
    INSTALLER_URL_AARCH64="https://repo.anaconda.com/miniconda/Miniconda3-py312_25.1.1-2-Linux-aarch64.sh"
    SHA256SUM_AARCH64="6d05b9f9b7f327b90797a4cf56d68c81578bab2f63257a3e7a8b72cb0f0e4b5d"

    set -x && \
        UNAME_M="$(uname -m)" && \
        if [ "${UNAME_M}" = "x86_64" ]; then \
            INSTALLER_URL="${INSTALLER_URL_LINUX64}"; \
            SHA256SUM="${SHA256SUM_LINUX64}"; \
        elif [ "${UNAME_M}" = "s390x" ]; then \
            INSTALLER_URL="${INSTALLER_URL_S390X}"; \
            SHA256SUM="${SHA256SUM_S390X}"; \
        elif [ "${UNAME_M}" = "aarch64" ]; then \
            INSTALLER_URL="${INSTALLER_URL_AARCH64}"; \
            SHA256SUM="${SHA256SUM_AARCH64}"; \
        fi && \
        wget "${INSTALLER_URL}" -O miniconda.sh -q && \
        echo "${SHA256SUM} miniconda.sh" > shasum && \
        sha256sum --check --status shasum && \
        mkdir -p /opt && \
        bash miniconda.sh -b -p /opt/conda && \
        rm miniconda.sh shasum && \
        ln -s /opt/conda/etc/profile.d/conda.sh /etc/profile.d/conda.sh && \
        echo ". /opt/conda/etc/profile.d/conda.sh" >> ~/.bashrc && \
        echo "conda activate base" >> ~/.bashrc && \
        find /opt/conda/ -follow -type f -name '*.a' -delete && \
        find /opt/conda/ -follow -type f -name '*.js.map' -delete && \
        /opt/conda/bin/conda clean -afy
}

install_node() {
    echo "Installing Node..."

    if [ -f /usr/local/bin/yarn ]
    then
        echo "Deleting old /usr/local/bin/yarn"
        rm -rf /usr/local/bin/yarn
    fi

    if [ -f /usr/local/bin/yarnpkg ]
    then
        echo "Deleting old /usr/local/bin/yarnpkg"
        rm -rf /usr/local/bin/yarnpkg
    fi

    groupadd --gid 1000 node \
        && useradd --uid 1000 --gid node --shell /bin/bash --create-home node

    NODE_VERSION="18.20.6"

    ARCH= && dpkgArch="$(dpkg --print-architecture)" \
        && case "${dpkgArch##*-}" in \
            amd64) ARCH='x64';; \
            ppc64el) ARCH='ppc64le';; \
            s390x) ARCH='s390x';; \
            arm64) ARCH='arm64';; \
            armhf) ARCH='armv7l';; \
            i386) ARCH='x86';; \
            *) echo "unsupported architecture"; exit 1 ;; \
        esac \
        && export GNUPGHOME="$(mktemp -d)" \
        && set -ex \
        && for key in \
            C0D6248439F1D5604AAFFB4021D900FFDB233756 \
            DD792F5973C6DE52C432CBDAC77ABFA00DDBF2B7 \
            CC68F5A3106FF448322E48ED27F5E38D5B0A215F \
            8FCCA13FEF1D0C2E91008E09770F7A9A5AE15600 \
            890C08DB8579162FEE0DF9DB8BEAB4DFCF555EF4 \
            C82FA3AE1CBEDC6BE46B9360C43CEC45C17AB93C \
            108F52B48DB57BB0CC439B2997B01419BD92F80A \
            A363A499291CBBC940DD62E41F10027AF002F8B0 \
        ; do \
            gpg --batch --keyserver hkps://keys.openpgp.org --recv-keys "$key" || \
            gpg --batch --keyserver keyserver.ubuntu.com --recv-keys "$key" ; \
        done \
        && curl -fsSLO --compressed "https://nodejs.org/dist/v$NODE_VERSION/node-v$NODE_VERSION-linux-$ARCH.tar.xz" \
        && curl -fsSLO --compressed "https://nodejs.org/dist/v$NODE_VERSION/SHASUMS256.txt.asc" \
        && gpg --batch --decrypt --output SHASUMS256.txt SHASUMS256.txt.asc \
        && gpgconf --kill all \
        && rm -rf "$GNUPGHOME" \
        && grep " node-v$NODE_VERSION-linux-$ARCH.tar.xz\$" SHASUMS256.txt | sha256sum -c - \
        && tar -xJf "node-v$NODE_VERSION-linux-$ARCH.tar.xz" -C /usr/local --strip-components=1 --no-same-owner \
        && rm "node-v$NODE_VERSION-linux-$ARCH.tar.xz" SHASUMS256.txt.asc SHASUMS256.txt \
        && ln -s /usr/local/bin/node /usr/local/bin/nodejs \
        && node --version \
        && npm --version

    YARN_VERSION="1.22.22"

    set -ex \
        && export GNUPGHOME="$(mktemp -d)" \
        && for key in \
            6A010C5166006599AA17F08146C2130DFD2497F5 \
        ; do \
            gpg --batch --keyserver hkps://keys.openpgp.org --recv-keys "$key" || \
            gpg --batch --keyserver keyserver.ubuntu.com --recv-keys "$key" ; \
        done \
        && curl -fsSLO --compressed "https://yarnpkg.com/downloads/$YARN_VERSION/yarn-v$YARN_VERSION.tar.gz" \
        && curl -fsSLO --compressed "https://yarnpkg.com/downloads/$YARN_VERSION/yarn-v$YARN_VERSION.tar.gz.asc" \
        && gpg --batch --verify yarn-v$YARN_VERSION.tar.gz.asc yarn-v$YARN_VERSION.tar.gz \
        && gpgconf --kill all \
        && rm -rf "$GNUPGHOME" \
        && mkdir -p /opt \
        && tar -xzf yarn-v$YARN_VERSION.tar.gz -C /opt/ \
        && ln -s /opt/yarn-v$YARN_VERSION/bin/yarn /usr/local/bin/yarn \
        && ln -s /opt/yarn-v$YARN_VERSION/bin/yarnpkg /usr/local/bin/yarnpkg \
        && rm yarn-v$YARN_VERSION.tar.gz.asc yarn-v$YARN_VERSION.tar.gz \
        && yarn --version \
        && rm -rf /tmp/*
}

install_nvidia_base() {
    echo "Installing base Nvidia libraries..."

    NVARCH="x86_64"

    save_env "NVARCH" $NVARCH

    NVIDIA_REQUIRE_CUDA="cuda>=12.8 brand=unknown,driver>=470,driver<471 brand=grid,driver>=470,driver<471 brand=tesla,driver>=470,driver<471 brand=nvidia,driver>=470,driver<471 brand=quadro,driver>=470,driver<471 brand=quadrortx,driver>=470,driver<471 brand=nvidiartx,driver>=470,driver<471 brand=vapps,driver>=470,driver<471 brand=vpc,driver>=470,driver<471 brand=vcs,driver>=470,driver<471 brand=vws,driver>=470,driver<471 brand=cloudgaming,driver>=470,driver<471 brand=unknown,driver>=535,driver<536 brand=grid,driver>=535,driver<536 brand=tesla,driver>=535,driver<536 brand=nvidia,driver>=535,driver<536 brand=quadro,driver>=535,driver<536 brand=quadrortx,driver>=535,driver<536 brand=nvidiartx,driver>=535,driver<536 brand=vapps,driver>=535,driver<536 brand=vpc,driver>=535,driver<536 brand=vcs,driver>=535,driver<536 brand=vws,driver>=535,driver<536 brand=cloudgaming,driver>=535,driver<536 brand=unknown,driver>=550,driver<551 brand=grid,driver>=550,driver<551 brand=tesla,driver>=550,driver<551 brand=nvidia,driver>=550,driver<551 brand=quadro,driver>=550,driver<551 brand=quadrortx,driver>=550,driver<551 brand=nvidiartx,driver>=550,driver<551 brand=vapps,driver>=550,driver<551 brand=vpc,driver>=550,driver<551 brand=vcs,driver>=550,driver<551 brand=vws,driver>=550,driver<551 brand=cloudgaming,driver>=550,driver<551 brand=unknown,driver>=560,driver<561 brand=grid,driver>=560,driver<561 brand=tesla,driver>=560,driver<561 brand=nvidia,driver>=560,driver<561 brand=quadro,driver>=560,driver<561 brand=quadrortx,driver>=560,driver<561 brand=nvidiartx,driver>=560,driver<561 brand=vapps,driver>=560,driver<561 brand=vpc,driver>=560,driver<561 brand=vcs,driver>=560,driver<561 brand=vws,driver>=560,driver<561 brand=cloudgaming,driver>=560,driver<561 brand=unknown,driver>=565,driver<566 brand=grid,driver>=565,driver<566 brand=tesla,driver>=565,driver<566 brand=nvidia,driver>=565,driver<566 brand=quadro,driver>=565,driver<566 brand=quadrortx,driver>=565,driver<566 brand=nvidiartx,driver>=565,driver<566 brand=vapps,driver>=565,driver<566 brand=vpc,driver>=565,driver<566 brand=vcs,driver>=565,driver<566 brand=vws,driver>=565,driver<566 brand=cloudgaming,driver>=565,driver<566"
    NV_CUDA_CUDART_VERSION="12.8.57-1"

    apt-get update && apt-get install -y --no-install-recommends \
        gnupg2 curl ca-certificates && \
        curl -fsSL https://developer.download.nvidia.com/compute/cuda/repos/ubuntu2404/${NVARCH}/3bf863cc.pub | apt-key add - && \
        echo "deb https://developer.download.nvidia.com/compute/cuda/repos/ubuntu2404/${NVARCH} /" > /etc/apt/sources.list.d/cuda.list && \
        rm -rf /var/lib/apt/lists/*

    CUDA_VERSION="12.8.0"

    apt-get update && apt-get install -y --no-install-recommends \
        cuda-cudart-12-8=${NV_CUDA_CUDART_VERSION} \
        cuda-compat-12-8 \
        && rm -rf /var/lib/apt/lists/*

    echo "/usr/local/nvidia/lib" >> /etc/ld.so.conf.d/nvidia.conf \
        && echo "/usr/local/nvidia/lib64" >> /etc/ld.so.conf.d/nvidia.conf

    PATH="/usr/local/nvidia/bin:/usr/local/cuda/bin:${PATH}"
    LD_LIBRARY_PATH="/usr/local/nvidia/lib:/usr/local/nvidia/lib64"

    NVIDIA_VISIBLE_DEVICES="all"
    NVIDIA_DRIVER_CAPABILITIES="compute,utility"

    NV_CUDA_LIB_VERSION="12.8.0-1"

    NV_NVTX_VERSION="12.8.55-1"
    NV_LIBNPP_VERSION="12.3.3.65-1"
    NV_LIBNPP_PACKAGE="libnpp-12-8=${NV_LIBNPP_VERSION}"
    NV_LIBCUSPARSE_VERSION="12.5.7.53-1"

    NV_LIBCUBLAS_PACKAGE_NAME="libcublas-12-8"
    NV_LIBCUBLAS_VERSION="12.8.3.14-1"
    NV_LIBCUBLAS_PACKAGE="${NV_LIBCUBLAS_PACKAGE_NAME}=${NV_LIBCUBLAS_VERSION}"

    NV_LIBNCCL_PACKAGE_NAME="libnccl2"
    NV_LIBNCCL_PACKAGE_VERSION="2.25.1-1"
    NCCL_VERSION="2.25.1-1"
    NV_LIBNCCL_PACKAGE="${NV_LIBNCCL_PACKAGE_NAME}=${NV_LIBNCCL_PACKAGE_VERSION}+cuda12.8"

    apt-get update && apt-get install -y --no-install-recommends \
        cuda-libraries-12-8=${NV_CUDA_LIB_VERSION} \
        ${NV_LIBNPP_PACKAGE} \
        cuda-nvtx-12-8=${NV_NVTX_VERSION} \
        libcusparse-12-8=${NV_LIBCUSPARSE_VERSION} \
        ${NV_LIBCUBLAS_PACKAGE} \
        ${NV_LIBNCCL_PACKAGE} \
        && rm -rf /var/lib/apt/lists/*

    apt-mark hold ${NV_LIBCUBLAS_PACKAGE_NAME} ${NV_LIBNCCL_PACKAGE_NAME}

    NV_CUDA_CUDART_DEV_VERSION="12.8.57-1"
    NV_NVML_DEV_VERSION="12.8.55-1"
    NV_LIBCUSPARSE_DEV_VERSION="12.5.7.53-1"
    NV_LIBNPP_DEV_VERSION="12.3.3.65-1"
    NV_LIBNPP_DEV_PACKAGE="libnpp-dev-12-8=${NV_LIBNPP_DEV_VERSION}"

    NV_LIBCUBLAS_DEV_VERSION="12.8.3.14-1"
    NV_LIBCUBLAS_DEV_PACKAGE_NAME="libcublas-dev-12-8"
    NV_LIBCUBLAS_DEV_PACKAGE="${NV_LIBCUBLAS_DEV_PACKAGE_NAME}=${NV_LIBCUBLAS_DEV_VERSION}"

    NV_CUDA_NSIGHT_COMPUTE_VERSION="12.8.0-1"
    NV_CUDA_NSIGHT_COMPUTE_DEV_PACKAGE="cuda-nsight-compute-12-8=${NV_CUDA_NSIGHT_COMPUTE_VERSION}"

    NV_NVPROF_VERSION="12.8.57-1"
    NV_NVPROF_DEV_PACKAGE="cuda-nvprof-12-8=${NV_NVPROF_VERSION}"

    NV_LIBNCCL_DEV_PACKAGE_NAME="libnccl-dev"
    NV_LIBNCCL_DEV_PACKAGE_VERSION="2.25.1-1"
    NCCL_VERSION="2.25.1-1"
    NV_LIBNCCL_DEV_PACKAGE="${NV_LIBNCCL_DEV_PACKAGE_NAME}=${NV_LIBNCCL_DEV_PACKAGE_VERSION}+cuda12.8"

    apt-get update && apt-get install -y --no-install-recommends \
        cuda-cudart-dev-12-8=${NV_CUDA_CUDART_DEV_VERSION} \
        cuda-command-line-tools-12-8=${NV_CUDA_LIB_VERSION} \
        cuda-minimal-build-12-8=${NV_CUDA_LIB_VERSION} \
        cuda-libraries-dev-12-8=${NV_CUDA_LIB_VERSION} \
        cuda-nvml-dev-12-8=${NV_NVML_DEV_VERSION} \
        ${NV_NVPROF_DEV_PACKAGE} \
        ${NV_LIBNPP_DEV_PACKAGE} \
        libcusparse-dev-12-8=${NV_LIBCUSPARSE_DEV_VERSION} \
        ${NV_LIBCUBLAS_DEV_PACKAGE} \
        ${NV_LIBNCCL_DEV_PACKAGE} \
        ${NV_CUDA_NSIGHT_COMPUTE_DEV_PACKAGE} \
        && rm -rf /var/lib/apt/lists/*

    apt-mark hold ${NV_LIBCUBLAS_DEV_PACKAGE_NAME} ${NV_LIBNCCL_DEV_PACKAGE_NAME}

    LIBRARY_PATH=/usr/local/cuda/lib64/stubs

    NV_CUDNN_VERSION="9.7.0.66-1"
    NV_CUDNN_PACKAGE_NAME="libcudnn9-cuda-12"
    NV_CUDNN_PACKAGE="libcudnn9-cuda-12=${NV_CUDNN_VERSION}"
    NV_CUDNN_PACKAGE_DEV="libcudnn9-dev-cuda-12=${NV_CUDNN_VERSION}"

    apt-get update && apt-get install -y --no-install-recommends \
        ${NV_CUDNN_PACKAGE} \
        ${NV_CUDNN_PACKAGE_DEV} \
        && apt-mark hold ${NV_CUDNN_PACKAGE_NAME} \
        && rm -rf /var/lib/apt/lists/*
}

install_nvidia_driver() {
    echo "Installing Nvidia driver..."

    apt-get update && apt-get install -y \
        alsa-utils \
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
        nvidia-kernel-common-550 \
        nvidia-kernel-source-550 \
        nvidia-utils-550 \
        ubuntu-drivers-common \
        xserver-xorg-video-nvidia-550

    ubuntu-drivers install nvidia-driver-550
}

install_postgresql() {
    echo "Installing PostgreSQL..."

    apt-get update

    curl -fsSL https://www.postgresql.org/media/keys/ACCC4CF8.asc | gpg --dearmor -o /etc/apt/trusted.gpg.d/postgresql.gpg

    sh -c 'echo "deb http://apt.postgresql.org/pub/repos/apt $(lsb_release -cs)-pgdg main" > /etc/apt/sources.list.d/pgdg.list'

    apt-get update

    apt-get install postgresql-17

    systemctl start postgresql
    systemctl enable postgresql

    sed -i "s/#listen_addresses = 'localhost'/listen_addresses = '*'/g" /etc/postgresql/17/main/postgresql.conf

    echo "host    all             all             0.0.0.0/0            scram-sha-256" >> /etc/postgresql/17/main/pg_hba.conf

    systemctl restart postgresql

    ufw allow 5432/tcp
}

install_rust() {
    echo "Installing Rust..."

    RUSTUP_HOME="/usr/local/rustup"
    save_env "RUSTUP_HOME" $RUSTUP_HOME
    CARGO_HOME="/usr/local/cargo"
    save_env "CARGO_HOME" $CARGO_HOME
    PATH="/usr/local/cargo/bin:$PATH"
    save_env "PATH" $PATH
    RUST_VERSION="1.84.1"

    set -eux; \
        dpkgArch="$(dpkg --print-architecture)"; \
        case "${dpkgArch##*-}" in \
            amd64) rustArch='x86_64-unknown-linux-gnu'; rustupSha256='6aeece6993e902708983b209d04c0d1dbb14ebb405ddb87def578d41f920f56d' ;; \
            armhf) rustArch='armv7-unknown-linux-gnueabihf'; rustupSha256='3c4114923305f1cd3b96ce3454e9e549ad4aa7c07c03aec73d1a785e98388bed' ;; \
            arm64) rustArch='aarch64-unknown-linux-gnu'; rustupSha256='1cffbf51e63e634c746f741de50649bbbcbd9dbe1de363c9ecef64e278dba2b2' ;; \
            i386) rustArch='i686-unknown-linux-gnu'; rustupSha256='0a6bed6e9f21192a51f83977716466895706059afb880500ff1d0e751ada5237' ;; \
            ppc64el) rustArch='powerpc64le-unknown-linux-gnu'; rustupSha256='079430f58ad4da1d1f4f5f2f0bd321422373213246a93b3ddb53dad627f5aa38' ;; \
            s390x) rustArch='s390x-unknown-linux-gnu'; rustupSha256='e7f89da453c8ce5771c28279d1a01d5e83541d420695c74ec81a7ec5d287c51c' ;; \
            *) echo >&2 "unsupported architecture: ${dpkgArch}"; exit 1 ;; \
        esac; \
        url="https://static.rust-lang.org/rustup/archive/1.27.1/${rustArch}/rustup-init"; \
        wget "$url"; \
        echo "${rustupSha256} *rustup-init" | sha256sum -c -; \
        chmod +x rustup-init; \
        ./rustup-init -y --no-modify-path --profile minimal --default-toolchain $RUST_VERSION --default-host ${rustArch}; \
        rm rustup-init; \
        . "$HOME/.cargo/env"
        #chmod -R a+w $RUSTUP_HOME $CARGO_HOME; \
        rustup --version; \
        cargo --version; \
        rustc --version;
}

install_selenium() {
    echo "Installing Selenium..."

    VERSION="4.28.0"
    RELEASE="selenium-${VERSION}"
    MVN_SELENIUM_VERSION
    OPENTELEMETRY_VERSION="1.46.0"
    GRPC_VERSION="1.69.0"
    NETTY_VERSION="4.1.117.Final"
    CS_VERSION="2.1.18"
    POSTGRESQL_VERSION="42.7.5"

    SEL_USER="seluser"
    SEL_GROUP="${SEL_USER}"
    HOME="/home/${SEL_USER}"
    UID="1200"
    GID="1201"
    TZ="UTC"
    JRE_VERSION="21"
    TARGETARCH
    TARGETVARIANT

    DEBIAN_FRONTEND=noninteractive
    DEBCONF_NONINTERACTIVE_SEEN=true
    SEL_USER=${SEL_USER}
    SEL_UID=${UID}
    SEL_GID=${GID}
    HOME=${HOME}
    TZ=${TZ}
    SEL_DOWNLOAD_DIR=${HOME}/Downloads
    VIDEO_FOLDER="/videos"
    CONFIG_FILE="/opt/selenium/config.toml"

    apt-get -qqy update \
    && apt-get upgrade -yq \
    && apt-get -qqy --no-install-recommends install \
        acl \
        bzip2 \
        xz-utils \
        tzdata \
        sudo \
        unzip \
        wget \
        jq \
        curl \
        supervisor \
        gnupg2 \
        libnss3-tools \
        openjdk-${JRE_VERSION}-jdk-headless \
        ca-certificates \
    && rm -rf /var/lib/apt/lists/* /var/cache/apt/*

    --mount=type=secret,id=SEL_PASSWD \
        if [ "${TARGETARCH}" = "arm" ] && [ "${TARGETVARIANT}" = "v7" ]; then \
        export ARCH=armhf ; \
        else \
        export ARCH=$(dpkg --print-architecture) ; \
        fi \
    && sed -i 's/securerandom\.source=file:\/dev\/random/securerandom\.source=file:\/dev\/urandom/' /usr/lib/jvm/java-${JRE_VERSION}-openjdk-${ARCH}/conf/security/java.security \
    && ln -fs /usr/share/zoneinfo/${TZ} /etc/localtime && \
        dpkg-reconfigure -f noninteractive tzdata && \
        cat /etc/timezone \
    && groupadd ${SEL_GROUP} \
            --gid ${SEL_GID} \
    && useradd ${SEL_USER} \
            --create-home \
            --gid ${SEL_GID} \
            --shell /bin/bash \
            --uid ${SEL_UID} \
    && usermod -a -G sudo ${SEL_USER} \
    && echo 'ALL ALL = (ALL) NOPASSWD: ALL' >> /etc/sudoers \
    && echo "${SEL_USER}:$(cat /run/secrets/SEL_PASSWD)" | chpasswd \
    && mkdir -p /opt/selenium /opt/selenium/assets /opt/selenium/secrets /opt/selenium/logs /var/run/supervisor /var/log/supervisor ${SEL_DOWNLOAD_DIR} \
        ${HOME}/.mozilla ${HOME}/.vnc ${HOME}/.pki/nssdb ${VIDEO_FOLDER} \
    && certutil -d sql:${HOME}/.pki/nssdb -N --empty-password \
    && touch ${CONFIG_FILE} \
    && chown -R ${SEL_USER}:${SEL_GROUP} /opt/selenium /var/run/supervisor /var/log/supervisor /etc/passwd ${HOME} ${VIDEO_FOLDER} \
    && chmod -R 775 /opt/selenium /var/run/supervisor /var/log/supervisor /etc/passwd ${HOME} ${VIDEO_FOLDER} \
    && wget --no-verbose https://github.com/${AUTHORS}/selenium/releases/download/${RELEASE}/selenium-server-${VERSION}.jar \
        -O /opt/selenium/selenium-server.jar \
    && chgrp -R 0 /opt/selenium ${HOME} ${VIDEO_FOLDER} /opt/selenium/assets /var/run/supervisor /var/log/supervisor \
    && chmod -R g=u /opt/selenium ${HOME} ${VIDEO_FOLDER} /opt/selenium/assets /var/run/supervisor /var/log/supervisor \
    && setfacl -Rm u:${SEL_USER}:rwx /opt /opt/selenium ${HOME} ${VIDEO_FOLDER} /opt/selenium/assets /var/run/supervisor /var/log/supervisor \
    && setfacl -Rm g:${SEL_GROUP}:rwx /opt /opt/selenium ${HOME} ${VIDEO_FOLDER} /opt/selenium/assets /var/run/supervisor /var/log/supervisor \
    && if [ `arch` = "aarch64" ] || [ `arch` = "x86_64" ]; then \
            curl -fL https://github.com/coursier/coursier/releases/download/v${CS_VERSION}/coursier.jar > /tmp/cs \
            && chmod +x /tmp/cs \
            && mkdir -p /external_jars \
            && chmod -R 775 /external_jars ; \
        fi \
    && if [ -f "/tmp/cs" ]; then \
            java -jar /tmp/cs fetch --classpath --cache /external_jars \
            io.opentelemetry:opentelemetry-exporter-otlp:${OPENTELEMETRY_VERSION} \
            io.grpc:grpc-netty:${GRPC_VERSION} \
            io.netty:netty-codec-http:${NETTY_VERSION} \
            > /external_jars/.classpath.txt \
            && chmod 664 /external_jars/.classpath.txt \
            && java -jar /tmp/cs fetch --classpath --cache /external_jars \
            org.seleniumhq.selenium:selenium-session-map-jdbc:${MVN_SELENIUM_VERSION} \
            org.postgresql:postgresql:${POSTGRESQL_VERSION} \
            org.seleniumhq.selenium:selenium-session-map-redis:${MVN_SELENIUM_VERSION} \
            # Patch specific version for CVEs in the dependencies
            > /external_jars/.classpath_session_map.txt \
            && chmod 664 /external_jars/.classpath_session_map.txt ; \
        fi \
    && rm -fr /root/.cache/* \
    && echo 'if [[ $(ulimit -n) -gt 200000 ]]; then echo "WARNING: Very high value reported by \"ulimit -n\". Consider passing \"--ulimit nofile=32768\" to \"docker run\"."; fi' >> ${HOME}/.bashrc

    COPY --chown="${SEL_UID}:${SEL_GID}" check-grid.sh entry_point.sh configs/node/nodeGridUrl.sh configs/node/nodePreStop.sh handle_heap_dump.sh /opt/bin/
    COPY --chown="${SEL_UID}:${SEL_GID}" mask /usr/local/bin/
    chmod +x /opt/bin/*.sh /usr/local/bin/mask

    COPY supervisord.conf /etc

    CERT_TRUST_ATTR="TCu,Cu,Tu"
    COPY --chown="${SEL_UID}:${SEL_GID}" certs/add-cert-helper.sh certs/add-jks-helper.sh /opt/bin/
    COPY --chown="${SEL_UID}:${SEL_GID}" certs/tls.crt certs/tls.key certs/server.jks certs/server.pass /opt/selenium/secrets/

    USER ${SEL_UID}:${SEL_GID}

    RUN /opt/bin/add-jks-helper.sh -d /opt/selenium/secrets \
        && /opt/bin/add-cert-helper.sh -d /opt/selenium/secrets ${CERT_TRUST_ATTR}

    SE_BIND_HOST="false"
    SE_SERVER_PROTOCOL="http"
    SE_REJECT_UNSUPPORTED_CAPS="false"
    SE_OTEL_JAVA_GLOBAL_AUTOCONFIGURE_ENABLED="true"
    SE_OTEL_TRACES_EXPORTER="otlp"
    SE_SUPERVISORD_LOG_LEVEL="info"
    SE_SUPERVISORD_CHILD_LOG_DIR="/tmp"
    SE_SUPERVISORD_LOG_FILE="/tmp/supervisord.log"
    SE_SUPERVISORD_PID_FILE="/tmp/supervisord.pid"
    SE_SUPERVISORD_AUTO_RESTART="true"
    SE_SUPERVISORD_START_RETRIES="5"
    SE_LOG_TIMESTAMP_FORMAT="%Y-%m-%d %H:%M:%S,%3N"
    SE_LOG_LEVEL="INFO"
    SE_HTTP_LOGS="false"
    SE_STRUCTURED_LOGS="false"
    SE_ENABLE_TRACING="true"
    SE_ENABLE_TLS="false"
    SE_JAVA_OPTS_DEFAULT="-XX:+HeapDumpOnOutOfMemoryError -XX:HeapDumpPath=/opt/selenium/logs"
    SE_JAVA_HEAP_DUMP="false"
    SE_JAVA_HTTPCLIENT_VERSION="HTTP_1_1"
    SE_JAVA_SSL_TRUST_STORE="/opt/selenium/secrets/server.jks"
    SE_JAVA_SSL_TRUST_STORE_PASSWORD="/opt/selenium/secrets/server.pass"
    SE_JAVA_DISABLE_HOSTNAME_VERIFICATION="true"
    SE_HTTPS_CERTIFICATE="/opt/selenium/secrets/tls.crt"
    SE_HTTPS_PRIVATE_KEY="/opt/selenium/secrets/tls.key"
}

installer_configuration_option_database_password() {
    USER_INPUT="file.tmp"
    >$USER_INPUT;
    dialog --backtitle "Octopus Software installer" --clear --title "Configure parameters" --inputbox "Database password:" 8 60 2> $USER_INPUT
    USER_CHOICE=$?;
    if [ "$USER_CHOICE" == 0 ];
    then
        echo "Continue with the selected option.";
    else
        echo "Have a good day! Bye!";

        exit 1;
    fi
    USER_INPUT=$(<$USER_INPUT)
    DATABASE_PASSWORD=$USER_INPUT

    installer_configuration_screen
}

installer_configuration_option_proceed() {
    if [ "$DATABASE_PASSWORD" == "" ] || [ "$DOMAIN" == "" ];
    then
        MSG="Configuration not complete missing parameters:"
        if [ "$DATABASE_PASSWORD" == "" ];
        then
            MSG="$MSG\nDatabase password"
        fi
        if [ "$DOMAIN" == "" ];
        then
            MSG="$MSG\nDomain name"
        fi
        dialog --backtitle "Octopus Software installer" --clear --title "Configure parameters" --msgbox "$MSG" 10 60

        installer_configuration_screen
    fi

    installer_proceed
}

installer_configuration_option_domain() {
    USER_INPUT="file.tmp"
    >$USER_INPUT;
    dialog --backtitle "Octopus Software installer" --clear --title "Configure parameters" --inputbox "Domain name:" 8 60 2> $USER_INPUT
    USER_CHOICE=$?;
    if [ "$USER_CHOICE" == 0 ];
    then
        echo "Continue with the selected option.";
    else
        echo "Have a good day! Bye!";

        exit 1;
    fi
    USER_INPUT=$(<$USER_INPUT)
    DOMAIN=$USER_INPUT

    installer_configuration_screen
}

installer_configuration_screen() {
    USER_CHOICE_MENU="file.tmp"
    >$USER_CHOICE_MENU;
    dialog --backtitle "Octopus Software installer" --clear --title "Configure parameters" --menu "Choice:" 14 60 3 1 "Database password" 2 "Domain name" 10 "Proceed" 2> $USER_CHOICE_MENU
    USER_CHOICE=$?;
    if [ "$USER_CHOICE" == 0 ];
    then
        echo "Continue with the selected option.";
    else
        echo "Have a good day! Bye!";

        exit 1;
    fi
    USER_CHOICE_MENU=$(<$USER_CHOICE_MENU)

    if [ "$USER_CHOICE_MENU" == "1" ];
    then
        installer_configuration_option_database_password
    elif [ "$USER_CHOICE_MENU" == "2" ];
    then
        installer_configuration_option_domain
    elif [ "$USER_CHOICE_MENU" == "10" ];
    then
        installer_configuration_option_proceed
    fi
}

installer_proceed() {
    if [ "$PROCEED" == "true" ];
    then
        PROCEED="false"
        echo "DATABASE_PASSWORD=$DATABASE_PASSWORD"
        echo "DOMAIN=$DOMAIN"

        install_base_utils
        install_nvidia_base
        install_nvidia_driver
        install_rust
        install_go
        install_node
        install_miniconda
        install_selenium
    fi
}

installer_welcome_screen() {
    dialog --backtitle "Octopus Software installer" --clear --title "Welcome" --yesno "Thank you for choosing Octopus Software. Do you want to proceed with installing the Octopus Server with all dependencies?" 8 60
    USER_CHOICE=$?;
    if [ "$USER_CHOICE" == 0 ];
    then
        installer_configuration_screen
    else
        echo "Have a good day! Bye!";
    fi
}

if [ "$EUID" -ne 0 ]; then
    echo "Please run this script as root (e.g. via sudo)." >&2
    exit 1
fi

if [ -e .env.install ]
then
    echo "Deleting old .env.install"
    rm .env.install
fi

apt-get update --fix-missing
apt-get upgrade -y

if ! which dialog >/dev/null 2>&1; then
    install_dialog
fi

installer_welcome_screen
