FROM nvidia/cuda:12.2.2-cudnn8-devel-ubuntu22.04 AS chef
RUN apt-get update --fix-missing && \
    apt-get install -y --no-install-recommends \
        build-essential \
        curl \
        git \
        libffi-dev \
        libffi8ubuntu1 \
        libgmp-dev \
        libgmp10 \
        libncurses-dev \
        libncurses5 \
        librust-openssl-dev \
        libtinfo5 \
        wget \
        zlib1g-dev && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*
# https://github.com/rust-lang/docker-rust/blob/master/1.76.0/bookworm/Dockerfile
ENV RUSTUP_HOME=/usr/local/rustup \
    CARGO_HOME=/usr/local/cargo \
    PATH=/usr/local/cargo/bin:$PATH \
    RUST_VERSION=1.76.0
RUN set -eux; \
    dpkgArch="$(dpkg --print-architecture)"; \
    case "${dpkgArch##*-}" in \
        amd64) rustArch='x86_64-unknown-linux-gnu'; rustupSha256='0b2f6c8f85a3d02fde2efc0ced4657869d73fccfce59defb4e8d29233116e6db' ;; \
        armhf) rustArch='armv7-unknown-linux-gnueabihf'; rustupSha256='f21c44b01678c645d8fbba1e55e4180a01ac5af2d38bcbd14aa665e0d96ed69a' ;; \
        arm64) rustArch='aarch64-unknown-linux-gnu'; rustupSha256='673e336c81c65e6b16dcdede33f4cc9ed0f08bde1dbe7a935f113605292dc800' ;; \
        i386) rustArch='i686-unknown-linux-gnu'; rustupSha256='e7b0f47557c1afcd86939b118cbcf7fb95a5d1d917bdd355157b63ca00fc4333' ;; \
        ppc64el) rustArch='powerpc64le-unknown-linux-gnu'; rustupSha256='1032934fb154ad2d365e02dcf770c6ecfaec6ab2987204c618c21ba841c97b44' ;; \
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

FROM chef AS backend_builder
ARG DATABASE_URL
RUN cargo install sqlx-cli
COPY --from=planner /octopus_server/recipe.json recipe.json
COPY octopus_server/crates /octopus_server/crates
RUN cargo chef cook --release --recipe-path recipe.json
COPY octopus_server /octopus_server/
WORKDIR /octopus_server
RUN cargo build --release

FROM nvidia/cuda:12.2.2-cudnn8-devel-ubuntu22.04 AS frontend_builder
RUN apt-get update --fix-missing && \
    apt-get install -y --no-install-recommends \
        curl \
        git && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*
# https://github.com/nodejs/docker-node/blob/main/18/bookworm/Dockerfile
RUN groupadd --gid 1000 node \
    && useradd --uid 1000 --gid node --shell /bin/bash --create-home node
ENV NODE_VERSION 18.19.1
RUN ARCH= && dpkgArch="$(dpkg --print-architecture)" \
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
        4ED778F539E3634C779C87C6D7062848A1AB005C \
        141F07595B7B3FFE74309A937405533BE57C7D57 \
        74F12602B6F1C4E913FAA37AD3A89613643B6201 \
        DD792F5973C6DE52C432CBDAC77ABFA00DDBF2B7 \
        61FC681DFB92A079F1685E77973F295594EC4689 \
        8FCCA13FEF1D0C2E91008E09770F7A9A5AE15600 \
        C4F0DFFF4E8C1A8236409D08E73BC641CC11F4C8 \
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
ENV YARN_VERSION 1.22.19
RUN set -ex \
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
    && yarn --version
ARG NEXT_PUBLIC_BASE_URL
WORKDIR /octopus_client
COPY /octopus_client/.env.example .env
COPY /octopus_client/package.json /octopus_client/yarn.lock ./
RUN npm install --frozen-lockfile
COPY /octopus_client/LICENSE /octopus_client/README.md /octopus_client/next-env.d.ts /octopus_client/next.config.js /octopus_client/package.json /octopus_client/package-lock.json /octopus_client/postcss.config.js /octopus_client/tailwind.config.js /octopus_client/tsconfig.json /octopus_client/yarn.lock ./
COPY /octopus_client/public public/
COPY /octopus_client/src src/
ENV NEXT_TELEMETRY_DISABLED 1
RUN npm run lint
RUN npm run build

FROM nvidia/cuda:12.2.2-cudnn8-devel-ubuntu22.04 AS prod
ENV LANG=C.UTF-8 LC_ALL=C.UTF-8
RUN apt-get update --fix-missing && \
    apt-get install -y --no-install-recommends \
        build-essential \
        cgroup-tools \
        curl \
        g++ \
        git \
        libffi-dev \
        libffi8ubuntu1 \
        libgmp-dev \
        libgmp10 \
        libncurses-dev \
        libncurses5 \
        librust-openssl-dev \
        libtinfo5 \
        nvidia-utils-535 \
        procps \
        wget \
        zlib1g-dev && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*
# https://github.com/rust-lang/docker-rust/blob/master/1.76.0/bookworm/Dockerfile
ENV RUSTUP_HOME=/usr/local/rustup \
    CARGO_HOME=/usr/local/cargo \
    PATH=/usr/local/cargo/bin:$PATH \
    RUST_VERSION=1.76.0
RUN set -eux; \
    dpkgArch="$(dpkg --print-architecture)"; \
    case "${dpkgArch##*-}" in \
        amd64) rustArch='x86_64-unknown-linux-gnu'; rustupSha256='0b2f6c8f85a3d02fde2efc0ced4657869d73fccfce59defb4e8d29233116e6db' ;; \
        armhf) rustArch='armv7-unknown-linux-gnueabihf'; rustupSha256='f21c44b01678c645d8fbba1e55e4180a01ac5af2d38bcbd14aa665e0d96ed69a' ;; \
        arm64) rustArch='aarch64-unknown-linux-gnu'; rustupSha256='673e336c81c65e6b16dcdede33f4cc9ed0f08bde1dbe7a935f113605292dc800' ;; \
        i386) rustArch='i686-unknown-linux-gnu'; rustupSha256='e7b0f47557c1afcd86939b118cbcf7fb95a5d1d917bdd355157b63ca00fc4333' ;; \
        ppc64el) rustArch='powerpc64le-unknown-linux-gnu'; rustupSha256='1032934fb154ad2d365e02dcf770c6ecfaec6ab2987204c618c21ba841c97b44' ;; \
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
        xdg-utils \
    && apt-get clean \
    && rm -rf /var/lib/apt/lists/*
ENV PATH /opt/conda/bin:$PATH
CMD [ "/bin/bash" ]
ARG CONDA_VERSION=py311_23.11.0-1
RUN set -x && \
    UNAME_M="$(uname -m)" && \
    if [ "${UNAME_M}" = "x86_64" ]; then \
        MINICONDA_URL="https://repo.anaconda.com/miniconda/Miniconda3-${CONDA_VERSION}-Linux-x86_64.sh"; \
        SHA256SUM="5b3cefe534e23541f5f703f40d4818e361c3615dbf14651a0f29554c3fc3d0fd"; \
    elif [ "${UNAME_M}" = "s390x" ]; then \
        MINICONDA_URL="https://repo.anaconda.com/miniconda/Miniconda3-${CONDA_VERSION}-Linux-s390x.sh"; \
        SHA256SUM="04586c734987a39114b81384014c2cfa89360c518371b6fa249d3062efca27fe"; \
    elif [ "${UNAME_M}" = "aarch64" ]; then \
        MINICONDA_URL="https://repo.anaconda.com/miniconda/Miniconda3-${CONDA_VERSION}-Linux-aarch64.sh"; \
        SHA256SUM="63c06a1974695e50bbe767a030903d169e637e42d5b7b6d30876b19a01fbbad8"; \
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
# https://github.com/nodejs/docker-node/blob/main/18/bookworm/Dockerfile
RUN groupadd --gid 1000 node \
    && useradd --uid 1000 --gid node --shell /bin/bash --create-home node
ENV NODE_VERSION 18.19.1
RUN ARCH= && dpkgArch="$(dpkg --print-architecture)" \
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
        4ED778F539E3634C779C87C6D7062848A1AB005C \
        141F07595B7B3FFE74309A937405533BE57C7D57 \
        74F12602B6F1C4E913FAA37AD3A89613643B6201 \
        DD792F5973C6DE52C432CBDAC77ABFA00DDBF2B7 \
        61FC681DFB92A079F1685E77973F295594EC4689 \
        8FCCA13FEF1D0C2E91008E09770F7A9A5AE15600 \
        C4F0DFFF4E8C1A8236409D08E73BC641CC11F4C8 \
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
ENV YARN_VERSION 1.22.19
RUN set -ex \
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
    && yarn --version
# https://github.com/SeleniumHQ/docker-selenium/blob/trunk/Base/Dockerfile
LABEL authors="Selenium <selenium-developers@googlegroups.com>"
ARG VERSION=4.18.0
ARG RELEASE=selenium-${VERSION}
ARG OPENTELEMETRY_VERSION=1.34.1
ARG GRPC_VERSION=1.61.0
ARG SEL_USER=seluser
ARG SEL_GROUP=${SEL_USER}
ARG SEL_PASSWD=secret
ARG UID=1200
ARG GID=1201
USER root
RUN  echo "deb http://archive.ubuntu.com/ubuntu jammy main universe\n" > /etc/apt/sources.list \
    && echo "deb http://archive.ubuntu.com/ubuntu jammy-updates main universe\n" >> /etc/apt/sources.list \
    && echo "deb http://security.ubuntu.com/ubuntu jammy-security main universe\n" >> /etc/apt/sources.list
ENV DEBIAN_FRONTEND=noninteractive \
    DEBCONF_NONINTERACTIVE_SEEN=true
RUN apt-get -qqy update \
    && apt-get upgrade -yq \
    && apt-get -qqy --no-install-recommends install \
        acl \
        bzip2 \
        ca-certificates \
        openjdk-11-jre-headless \
        tzdata \
        sudo \
        unzip \
        wget \
        jq \
        curl \
        supervisor \
        gnupg2 \
        libnss3-tools \
    && rm -rf /var/lib/apt/lists/* /var/cache/apt/* \
    && sed -i 's/securerandom\.source=file:\/dev\/random/securerandom\.source=file:\/dev\/urandom/' ./usr/lib/jvm/java-11-openjdk-amd64/conf/security/java.security
ENV TZ "UTC"
RUN ln -fs /usr/share/zoneinfo/${TZ} /etc/localtime && \
    dpkg-reconfigure -f noninteractive tzdata && \
    cat /etc/timezone
ENV SEL_USER=${SEL_USER}
ENV SEL_UID=${UID}
ENV SEL_GID=${GID}
ENV HOME=/home/${SEL_USER}
ENV SEL_DOWNLOAD_DIR=${HOME}/Downloads
RUN groupadd ${SEL_GROUP} \
            --gid ${SEL_GID} \
    && useradd ${SEL_USER} \
            --create-home \
            --gid ${SEL_GID} \
            --shell /bin/bash \
            --uid ${SEL_UID} \
    && usermod -a -G sudo ${SEL_USER} \
    && echo 'ALL ALL = (ALL) NOPASSWD: ALL' >> /etc/sudoers \
    && echo "${SEL_USER}:${SEL_PASSWD}" | chpasswd
COPY --chown="${SEL_UID}:${SEL_GID}" octopus_server/selenium/check-grid.sh octopus_server/selenium/entry_point.sh /opt/bin/
COPY octopus_server/selenium/supervisord.conf /etc
RUN mkdir -p /opt/selenium /opt/selenium/assets /var/run/supervisor /var/log/supervisor ${SEL_DOWNLOAD_DIR} \
        ${HOME}/.mozilla ${HOME}/.vnc $HOME/.pki/nssdb \
    && touch /opt/selenium/config.toml \
    && chown -R ${SEL_USER}:${SEL_GROUP} /opt/selenium /var/run/supervisor /var/log/supervisor /etc/passwd ${HOME} \
    && chmod -R 775 /opt/selenium /var/run/supervisor /var/log/supervisor /etc/passwd ${HOME} \
    && wget --no-verbose https://github.com/SeleniumHQ/selenium/releases/download/${RELEASE}/selenium-server-${VERSION}.jar \
        -O /opt/selenium/selenium-server.jar \
    && echo "${SEL_PASSWD}" > /opt/selenium/initialPasswd \
    && chgrp -R 0 /opt/selenium ${HOME} /opt/selenium/assets /var/run/supervisor /var/log/supervisor \
    && chmod -R g=u /opt/selenium ${HOME} /opt/selenium/assets /var/run/supervisor /var/log/supervisor \
    && setfacl -Rm u:${SEL_USER}:rwx /opt /opt/selenium ${HOME} /opt/selenium/assets /var/run/supervisor /var/log/supervisor \
    && setfacl -Rm g:${SEL_GROUP}:rwx /opt /opt/selenium ${HOME} /opt/selenium/assets /var/run/supervisor /var/log/supervisor
RUN curl -fLo /tmp/cs https://github.com/coursier/launchers/raw/master/coursier \
    && chmod +x /tmp/cs \
    && mkdir -p /external_jars \
    && chmod -R 775 /external_jars
RUN /tmp/cs fetch --classpath --cache /external_jars \
    io.opentelemetry:opentelemetry-exporter-otlp:${OPENTELEMETRY_VERSION} \
    io.grpc:grpc-netty:${GRPC_VERSION} > /external_jars/.classpath.txt
RUN chmod 664 /external_jars/.classpath.txt
RUN rm -fr /root/.cache/*
USER ${SEL_UID}:${SEL_GID}
RUN certutil -d sql:$HOME/.pki/nssdb -N --empty-password
ENV SE_BIND_HOST false
ENV SE_REJECT_UNSUPPORTED_CAPS false
ENV SE_OTEL_JAVA_GLOBAL_AUTOCONFIGURE_ENABLED true
ENV SE_OTEL_TRACES_EXPORTER "otlp"
RUN echo 'if [[ $(ulimit -n) -gt 200000 ]]; then echo "WARNING: Very high value reported by \"ulimit -n\". Consider passing \"--ulimit nofile=32768\" to \"docker run\"."; fi' >> ${HOME}/.bashrc

# https://github.com/SeleniumHQ/docker-selenium/blob/trunk/NodeDocker/Dockerfile
USER root
RUN apt-get update -qqy \
    && apt-get -qqy --no-install-recommends install socat \
    && rm -rf /var/lib/apt/lists/* /var/cache/apt/*
USER ${SEL_UID}
EXPOSE 4444
COPY --chown="${SEL_UID}:${SEL_GID}" octopus_server/selenium/start-selenium-grid-docker.sh \
    octopus_server/selenium/config.toml \
    octopus_server/selenium/start-socat.sh \
    /opt/bin/
COPY octopus_server/selenium/selenium-grid-docker.conf /etc/supervisor/conf.d/
ENV SE_OTEL_SERVICE_NAME "selenium-node-docker"

# https://github.com/SeleniumHQ/docker-selenium/blob/trunk/NodeBase/Dockerfile
ARG NOVNC_VERSION="1.4.0"
ARG WEBSOCKIFY_VERSION="0.11.0"
USER root
RUN apt-get update -qqy \
    && apt-get -qqy --no-install-recommends install \
        xvfb \
        xauth \
        pulseaudio \
    && rm -rf /var/lib/apt/lists/* /var/cache/apt/*
ENV LANG_WHICH en
ENV LANG_WHERE US
ENV ENCODING UTF-8
ENV LANGUAGE ${LANG_WHICH}_${LANG_WHERE}.${ENCODING}
ENV LANG ${LANGUAGE}
RUN apt-get -qqy update \
    && apt-get -qqy --no-install-recommends install \
        language-pack-en \
        tzdata \
        locales \
    && locale-gen ${LANGUAGE} \
    && dpkg-reconfigure --frontend noninteractive locales \
    && apt-get -qyy autoremove \
    && rm -rf /var/lib/apt/lists/* \
    && apt-get -qyy clean
RUN apt-get update -qqy \
    && apt-get -qqy --no-install-recommends install \
    x11vnc x11-utils \
    && rm -rf /var/lib/apt/lists/* /var/cache/apt/*
RUN apt-get update -qqy \
    && apt-get -qqy --no-install-recommends install \
        fluxbox eterm hsetroot feh \
    && rm -rf /var/lib/apt/lists/* /var/cache/apt/*
RUN apt-get -qqy update \
    && apt-get -qqy --no-install-recommends install \
        libfontconfig \
        libfreetype6 \
        xfonts-cyrillic \
        xfonts-scalable \
        fonts-liberation \
        fonts-ipafont-gothic \
        fonts-wqy-zenhei \
        fonts-tlwg-loma-otf \
        fonts-ubuntu \
        fonts-noto-color-emoji \
    && rm -rf /var/lib/apt/lists/* \
    && apt-get -qyy clean
RUN wget -nv -O noVNC.zip \
        "https://github.com/novnc/noVNC/archive/refs/tags/v${NOVNC_VERSION}.zip" \
    && unzip -x noVNC.zip \
    && mv noVNC-${NOVNC_VERSION} /opt/bin/noVNC \
    && cp /opt/bin/noVNC/vnc.html /opt/bin/noVNC/index.html \
    && rm noVNC.zip \
    && wget -nv -O websockify.zip \
        "https://github.com/novnc/websockify/archive/refs/tags/v${WEBSOCKIFY_VERSION}.zip" \
    && unzip -x websockify.zip \
    && rm websockify.zip \
    && mv websockify-${WEBSOCKIFY_VERSION} /opt/bin/noVNC/utils/websockify \
    && rm -rf /opt/bin/noVNC/utils/websockify/docker /opt/bin/noVNC/utils/websockify/tests
RUN chmod +x /dev/shm
RUN mkdir -p /tmp/.X11-unix
RUN mkdir -p ${HOME}/.vnc \
    && x11vnc -storepasswd $(cat /opt/selenium/initialPasswd) ${HOME}/.vnc/passwd \
    && chown -R "${SEL_USER}:${SEL_GROUP}" ${HOME}/.vnc
RUN chmod -R 775 ${HOME} /tmp/.X11-unix \
    && chgrp -R 0 ${HOME} /tmp/.X11-unix \
    && chmod -R g=u ${HOME} /tmp/.X11-unix
USER ${SEL_UID}
COPY --chown="${SEL_UID}:${SEL_GID}" octopus_server/selenium/start-selenium-node.sh \
    octopus_server/selenium/start-xvfb.sh \
    /opt/bin/
COPY octopus_server/selenium/selenium.conf /etc/supervisor/conf.d/
COPY --chown="${SEL_UID}:${SEL_GID}" octopus_server/selenium/start-vnc.sh \
    octopus_server/selenium/start-novnc.sh \
    /opt/bin/
ENV SE_SCREEN_WIDTH 1360
ENV SE_SCREEN_HEIGHT 1020
ENV SE_SCREEN_DEPTH 24
ENV SE_SCREEN_DPI 96
ENV SE_START_XVFB true
ENV SE_START_VNC true
ENV SE_START_NO_VNC true
ENV SE_NO_VNC_PORT 7900
ENV SE_VNC_PORT 5900
ENV DISPLAY :99.0
ENV DISPLAY_NUM 99
ENV CONFIG_FILE=/opt/selenium/config.toml
ENV GENERATE_CONFIG true
ENV SE_DRAIN_AFTER_SESSION_COUNT 0
ENV SE_OFFLINE true
ENV SE_NODE_MAX_SESSIONS 1
ENV SE_NODE_SESSION_TIMEOUT 300
ENV SE_NODE_OVERRIDE_MAX_SESSIONS false
ENV SE_NODE_HEARTBEAT_PERIOD 30
ENV DBUS_SESSION_BUS_ADDRESS=/dev/null
ENV SE_OTEL_SERVICE_NAME "selenium-node"
COPY --chown="${SEL_UID}:${SEL_GID}" octopus_server/selenium/generate_config /opt/bin/generate_config
# https://github.com/SeleniumHQ/docker-selenium/blob/trunk/NodeChrome/Dockerfile
USER root
ARG CHROME_VERSION="google-chrome-stable"
RUN wget -q -O - https://dl-ssl.google.com/linux/linux_signing_key.pub | gpg --dearmor | tee /etc/apt/trusted.gpg.d/google.gpg >/dev/null \
    && echo "deb http://dl.google.com/linux/chrome/deb/ stable main" >> /etc/apt/sources.list.d/google-chrome.list \
    && apt-get update -qqy \
    && apt-get -qqy --no-install-recommends install \
        ${CHROME_VERSION:-google-chrome-stable} \
    && rm /etc/apt/sources.list.d/google-chrome.list \
    && rm -rf /var/lib/apt/lists/* /var/cache/apt/*
COPY octopus_server/selenium/wrap_chrome_binary /opt/bin/wrap_chrome_binary
RUN /opt/bin/wrap_chrome_binary
ARG CHROME_DRIVER_VERSION
RUN if [ ! -z "$CHROME_DRIVER_VERSION" ]; \
    then CHROME_DRIVER_URL=https://storage.googleapis.com/chrome-for-testing-public/$CHROME_DRIVER_VERSION/linux64/chromedriver-linux64.zip ; \
    else CHROME_MAJOR_VERSION=$(google-chrome --version | sed -E "s/.* ([0-9]+)(\.[0-9]+){3}.*/\1/") \
        && echo "Geting ChromeDriver latest version from https://googlechromelabs.github.io/chrome-for-testing/LATEST_RELEASE_${CHROME_MAJOR_VERSION}" \
        && CHROME_DRIVER_VERSION=$(wget -qO- https://googlechromelabs.github.io/chrome-for-testing/LATEST_RELEASE_${CHROME_MAJOR_VERSION} | sed 's/\r$//') \
        && CHROME_DRIVER_URL=https://storage.googleapis.com/chrome-for-testing-public/$CHROME_DRIVER_VERSION/linux64/chromedriver-linux64.zip ; \
    fi \
    && echo "Using ChromeDriver from: "$CHROME_DRIVER_URL \
    && echo "Using ChromeDriver version: "$CHROME_DRIVER_VERSION \
    && wget --no-verbose -O /tmp/chromedriver_linux64.zip $CHROME_DRIVER_URL \
    && rm -rf /opt/selenium/chromedriver \
    && unzip /tmp/chromedriver_linux64.zip -d /opt/selenium \
    && rm /tmp/chromedriver_linux64.zip \
    && mv /opt/selenium/chromedriver-linux64/chromedriver /opt/selenium/chromedriver-$CHROME_DRIVER_VERSION \
    && chmod 755 /opt/selenium/chromedriver-$CHROME_DRIVER_VERSION \
    && ln -fs /opt/selenium/chromedriver-$CHROME_DRIVER_VERSION /usr/bin/chromedriver
USER ${SEL_UID}
RUN echo "chrome" > /opt/selenium/browser_name
RUN google-chrome --version | awk '{print $3}' > /opt/selenium/browser_version
RUN echo "\"goog:chromeOptions\": {\"binary\": \"/usr/bin/google-chrome\"}" > /opt/selenium/browser_binary_location
ENV SE_OTEL_SERVICE_NAME "selenium-node-chrome"

ENV HOME=/root
USER root
ARG AZURE_OPENAI_API_KEY
ARG AZURE_OPENAI_DEPLOYMENT_ID
ARG AZURE_OPENAI_ENABLED
ARG DATABASE_URL
ARG OCTOPUS_PEPPER
ARG OCTOPUS_PEPPER_ID
ARG OCTOPUS_SERVER_PORT
ARG OPENAI_API_KEY
ARG SENDGRID_API_KEY
ARG NEXT_PUBLIC_BASE_URL
ARG WASP_MAGE_DATABASE_URL
ENV NVIDIA_VISIBLE_DEVICES all
ENV NVIDIA_DRIVER_CAPABILITIES all
ENV NEXT_TELEMETRY_DISABLED 1
ENV PORT 3000
ENV WASP_MAGE_BACKEND_PORT 3031
ENV WASP_MAGE_PORT 3030
RUN conda init
RUN conda config --add channels conda-forge
RUN conda install -y -n base mamba
ENV PATH "$PATH:/root/.local/bin"
RUN chmod u+s /usr/bin/cgcreate
RUN chmod u+s /usr/bin/cgdelete
RUN chmod u+s /usr/bin/cgexec
RUN curl --proto '=https' --tlsv1.2 -sSf https://get-ghcup.haskell.org | sh
ENV PATH "$PATH:/root/.ghcup/bin"
RUN ghcup install ghc 8.10.7
WORKDIR /
RUN git clone https://github.com/wasp-lang/wasp.git
WORKDIR /wasp
RUN git checkout wasp-ai
WORKDIR /wasp/waspc
RUN ./run build
RUN ./run install
ENV PATH "$PATH:/root/.cabal/bin"
RUN ln -s /root/.cabal/bin/wasp-cli /root/.cabal/bin/wasp
WORKDIR /wasp_mage
COPY octopus_server/wasp_mage /wasp_mage
WORKDIR /octopus_client
COPY /octopus_client/.env.example .env
COPY /octopus_client/package.json /octopus_client/yarn.lock ./
COPY /octopus_client/LICENSE /octopus_client/README.md /octopus_client/next-env.d.ts /octopus_client/next.config.js /octopus_client/package.json /octopus_client/package-lock.json /octopus_client/postcss.config.js /octopus_client/tailwind.config.js /octopus_client/tsconfig.json /octopus_client/yarn.lock ./
COPY /octopus_client/public public/
COPY /octopus_client/src src/
WORKDIR /octopus_server
COPY --from=backend_builder /usr/local/cargo/bin/cargo-sqlx ./
COPY --from=backend_builder /usr/local/cargo/bin/sqlx ./
COPY --from=backend_builder /octopus_server/target/release/octopus_server ./
COPY --from=backend_builder /octopus_server/migrations ./migrations
COPY --from=backend_builder /octopus_server/docker-entrypoint.sh ./
COPY --from=backend_builder /octopus_server/frontend-start.sh ./
COPY --from=backend_builder /octopus_server/wasp-mage-start.sh ./
RUN chmod +x docker-entrypoint.sh && \
    chmod +x frontend-start.sh && \
    chmod +x wasp-mage-start.sh && \
    mkdir ./public/ && \
    mkdir ./services/ && \
    mkdir ./wasp_apps/
VOLUME /octopus_server/public
VOLUME /octopus_server/services
VOLUME /octopus_server/wasp_apps
EXPOSE 3000
ENTRYPOINT ["./docker-entrypoint.sh"]
