FROM nvidia/cuda:12.2.2-cudnn8-devel-ubuntu22.04 AS chef
RUN apt-get update --fix-missing && \
    apt-get install -y --no-install-recommends \
        librust-openssl-dev \
        wget && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*
# https://github.com/rust-lang/docker-rust/blob/master/1.73.0/bookworm/Dockerfile
ENV RUSTUP_HOME=/usr/local/rustup \
    CARGO_HOME=/usr/local/cargo \
    PATH=/usr/local/cargo/bin:$PATH \
    RUST_VERSION=1.73.0
RUN set -eux; \
    dpkgArch="$(dpkg --print-architecture)"; \
    case "${dpkgArch##*-}" in \
        amd64) rustArch='x86_64-unknown-linux-gnu'; rustupSha256='0b2f6c8f85a3d02fde2efc0ced4657869d73fccfce59defb4e8d29233116e6db' ;; \
        armhf) rustArch='armv7-unknown-linux-gnueabihf'; rustupSha256='f21c44b01678c645d8fbba1e55e4180a01ac5af2d38bcbd14aa665e0d96ed69a' ;; \
        arm64) rustArch='aarch64-unknown-linux-gnu'; rustupSha256='673e336c81c65e6b16dcdede33f4cc9ed0f08bde1dbe7a935f113605292dc800' ;; \
        i386) rustArch='i686-unknown-linux-gnu'; rustupSha256='e7b0f47557c1afcd86939b118cbcf7fb95a5d1d917bdd355157b63ca00fc4333' ;; \
        *) echo >&2 "unsupported architecture: ${dpkgArch}"; exit 1 ;; \
    esac; \
    url="https://static.rust-lang.org/rustup/archive/1.26.0/${rustArch}/rustup-init"; \
    wget "$url"; \
    echo "${rustupSha256} *rustup-init" | sha256sum -c -; \
    chmod +x rustup-init; \
    ./rustup-init -y --no-modify-path --profile minimal --default-toolchain $RUST_VERSION --default-host ${rustArch}; \
    rm rustup-init; \
    chmod -R a+w $RUSTUP_HOME $CARGO_HOME; \
    rustup --version; \
    cargo --version; \
    rustc --version;
RUN cargo install cargo-chef
WORKDIR /octopus_server

FROM chef AS planner
COPY octopus_server /octopus_server/
RUN cargo chef prepare --recipe-path recipe.json

FROM chef AS builder
ARG AZURE_OPENAI_API_KEY
ARG AZURE_OPENAI_DEPLOYMENT_ID
ARG AZURE_OPENAI_ENABLED
ARG DATABASE_URL
ARG OCTOPUS_PEPPER
ARG OCTOPUS_PEPPER_ID
ARG OCTOPUS_SERVER_PORT
ARG OPENAI_API_KEY
ARG SENDGRID_API_KEY
RUN cargo install sqlx-cli
COPY --from=planner /octopus_server/recipe.json recipe.json
RUN cargo chef cook --release --recipe-path recipe.json
COPY octopus_server /octopus_server/
WORKDIR /octopus_server
RUN cargo build --release

FROM nvidia/cuda:12.2.2-cudnn8-devel-ubuntu22.04 AS prod
ENV LANG=C.UTF-8 LC_ALL=C.UTF-8
RUN apt-get update --fix-missing && \
    apt-get install -y --no-install-recommends \
        g++ \
        git \
        librust-openssl-dev \
        nvidia-utils-535 \
        procps \
        wget && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*
# https://github.com/rust-lang/docker-rust/blob/master/1.73.0/bookworm/Dockerfile
ENV RUSTUP_HOME=/usr/local/rustup \
    CARGO_HOME=/usr/local/cargo \
    PATH=/usr/local/cargo/bin:$PATH \
    RUST_VERSION=1.73.0
RUN set -eux; \
    dpkgArch="$(dpkg --print-architecture)"; \
    case "${dpkgArch##*-}" in \
        amd64) rustArch='x86_64-unknown-linux-gnu'; rustupSha256='0b2f6c8f85a3d02fde2efc0ced4657869d73fccfce59defb4e8d29233116e6db' ;; \
        armhf) rustArch='armv7-unknown-linux-gnueabihf'; rustupSha256='f21c44b01678c645d8fbba1e55e4180a01ac5af2d38bcbd14aa665e0d96ed69a' ;; \
        arm64) rustArch='aarch64-unknown-linux-gnu'; rustupSha256='673e336c81c65e6b16dcdede33f4cc9ed0f08bde1dbe7a935f113605292dc800' ;; \
        i386) rustArch='i686-unknown-linux-gnu'; rustupSha256='e7b0f47557c1afcd86939b118cbcf7fb95a5d1d917bdd355157b63ca00fc4333' ;; \
        *) echo >&2 "unsupported architecture: ${dpkgArch}"; exit 1 ;; \
    esac; \
    url="https://static.rust-lang.org/rustup/archive/1.26.0/${rustArch}/rustup-init"; \
    wget "$url"; \
    echo "${rustupSha256} *rustup-init" | sha256sum -c -; \
    chmod +x rustup-init; \
    ./rustup-init -y --no-modify-path --profile minimal --default-toolchain $RUST_VERSION --default-host ${rustArch}; \
    rm rustup-init; \
    chmod -R a+w $RUSTUP_HOME $CARGO_HOME; \
    rustup --version; \
    cargo --version; \
    rustc --version;
# https://github.com/ContinuumIO/docker-images/blob/main/miniconda3/debian/Dockerfile
ENV LANG=C.UTF-8 LC_ALL=C.UTF-8
RUN apt-get update -q && \
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
ENV PATH /opt/conda/bin:$PATH
CMD [ "/bin/bash" ]
ARG CONDA_VERSION=py311_23.9.0-0
RUN set -x && \
    UNAME_M="$(uname -m)" && \
    if [ "${UNAME_M}" = "x86_64" ]; then \
        MINICONDA_URL="https://repo.anaconda.com/miniconda/Miniconda3-${CONDA_VERSION}-Linux-x86_64.sh"; \
        SHA256SUM="43651393236cb8bb4219dcd429b3803a60f318e5507d8d84ca00dafa0c69f1bb"; \
    elif [ "${UNAME_M}" = "s390x" ]; then \
        MINICONDA_URL="https://repo.anaconda.com/miniconda/Miniconda3-${CONDA_VERSION}-Linux-s390x.sh"; \
        SHA256SUM="707c68e25c643c84036a16acdf836a3835ea75ffd2341c05ec2da6db1f3e9963"; \
    elif [ "${UNAME_M}" = "aarch64" ]; then \
        MINICONDA_URL="https://repo.anaconda.com/miniconda/Miniconda3-${CONDA_VERSION}-Linux-aarch64.sh"; \
        SHA256SUM="1242847b34b23353d429fcbcfb6586f0c373e63070ad7d6371c23ddbb577778a"; \
    elif [ "${UNAME_M}" = "ppc64le" ]; then \
        MINICONDA_URL="https://repo.anaconda.com/miniconda/Miniconda3-${CONDA_VERSION}-Linux-ppc64le.sh"; \
        SHA256SUM="07b53e411c2e4423bd34c3526d6644b916c4b2143daa8fbcb36b8ead412239b9"; \
    fi && \
    wget "${MINICONDA_URL}" -O miniconda.sh -q && \
    echo "${SHA256SUM} miniconda.sh" > shasum && \
    if [ "${CONDA_VERSION}" != "latest" ]; then sha256sum --check --status shasum; fi && \
    mkdir -p /opt && \
    bash miniconda.sh -b -p /opt/conda && \
    rm miniconda.sh shasum && \
    ln -s /opt/conda/etc/profile.d/conda.sh /etc/profile.d/conda.sh && \
    echo ". /opt/conda/etc/profile.d/conda.sh" >> ~/.bashrc && \
    echo "conda activate base" >> ~/.bashrc && \
    find /opt/conda/ -follow -type f -name '*.a' -delete && \
    find /opt/conda/ -follow -type f -name '*.js.map' -delete && \
    /opt/conda/bin/conda clean -afy
ARG AZURE_OPENAI_API_KEY
ARG AZURE_OPENAI_DEPLOYMENT_ID
ARG AZURE_OPENAI_ENABLED
ARG DATABASE_URL
ARG OCTOPUS_PEPPER
ARG OCTOPUS_PEPPER_ID
ARG OCTOPUS_SERVER_PORT
ARG OPENAI_API_KEY
ARG SENDGRID_API_KEY
RUN conda init
WORKDIR /octopus_server
COPY --from=builder /usr/local/cargo/bin/cargo-sqlx ./
COPY --from=builder /usr/local/cargo/bin/sqlx ./
COPY --from=builder /octopus_server/target/release/octopus_server ./
COPY --from=builder /octopus_server/migrations ./migrations
COPY --from=builder /octopus_server/docker-entrypoint.sh ./
RUN chmod +x docker-entrypoint.sh && \
    mkdir ./public/ && \
    mkdir ./services/
ENV NVIDIA_VISIBLE_DEVICES all
ENV NVIDIA_DRIVER_CAPABILITIES all
ENTRYPOINT ["./docker-entrypoint.sh"]
