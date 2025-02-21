FROM nvidia/cuda:12.2.2-cudnn8-devel-ubuntu22.04 AS octopus_server_base
RUN sed -i "s/Pin-Priority: -1/Pin-Priority: 1001/g" /etc/apt/preferences.d/cuda-repository-pin-600
RUN sed -i "s/Pin-Priority: 600/Pin-Priority: -1/g" /etc/apt/preferences.d/cuda-repository-pin-600
RUN apt-get update --fix-missing && \
    apt-get upgrade -y && \
    apt-get install -y --no-install-recommends \
        build-essential \
        ca-certificates \
        cmake \
        curl \
        g++ \
        gcc \
        git \
        libc6-dev \
        libffi-dev \
        libffi8ubuntu1 \
        libgmp-dev \
        libgmp10 \
        libncurses-dev \
        libncurses5 \
        librust-openssl-dev \
        libtinfo5 \
        make \
        pkg-config \
        wget \
        zlib1g-dev && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*
# https://github.com/rust-lang/docker-rust/blob/master/stable/bookworm/Dockerfile
ENV RUSTUP_HOME=/usr/local/rustup \
    CARGO_HOME=/usr/local/cargo \
    PATH=/usr/local/cargo/bin:$PATH \
    RUST_VERSION=1.85.0
RUN set -eux; \
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
    chmod -R a+w $RUSTUP_HOME $CARGO_HOME; \
    rustup --version; \
    cargo --version; \
    rustc --version;
# https://github.com/docker-library/golang/blob/master/1.23/bookworm/Dockerfile
ENV PATH /usr/local/go/bin:$PATH
ENV GOLANG_VERSION 1.23.6
RUN set -eux; \
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
ENV GOTOOLCHAIN=local
ENV GOPATH /go
ENV PATH $GOPATH/bin:/usr/local/go/bin:$PATH
RUN mkdir -p "$GOPATH/src" "$GOPATH/bin" && chmod -R 1777 "$GOPATH"
# https://github.com/nodejs/docker-node/blob/main/18/bookworm/Dockerfile
RUN groupadd --gid 1000 node \
    && useradd --uid 1000 --gid node --shell /bin/bash --create-home node
ENV NODE_VERSION 18.20.6
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
ENV YARN_VERSION 1.22.22
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
    && yarn --version \
    && rm -rf /tmp/*
RUN cargo install cargo-chef
WORKDIR /octopus_server

FROM octopus_server_base AS octopus_server_planner
COPY octopus_server /octopus_server/
RUN cargo chef prepare --recipe-path recipe.json

FROM octopus_server_base AS octopus_server_builder
ARG DATABASE_URL
RUN cargo install sqlx-cli
COPY --from=octopus_server_planner /octopus_server/recipe.json recipe.json
COPY octopus_server/crates /octopus_server/crates
RUN cargo chef cook --release --recipe-path recipe.json
COPY octopus_server /octopus_server/
WORKDIR /octopus_server
RUN cargo build --release
ARG NEXT_PUBLIC_BASE_URL
ARG NEXT_PUBLIC_THEME_NAME
ARG NEXT_PUBLIC_DOMAIN
WORKDIR /octopus_client
COPY /octopus_client/.env.example .env
COPY /octopus_client/package.json ./
COPY /octopus_client/LICENSE /octopus_client/README.md /octopus_client/next-env.d.ts /octopus_client/next.config.js /octopus_client/package.json /octopus_client/package-lock.json /octopus_client/postcss.config.js /octopus_client/tailwind.config.js /octopus_client/tsconfig.json ./
COPY /octopus_client/public public/
COPY /octopus_client/src src/
RUN npm install --frozen-lockfile
ENV NEXT_TELEMETRY_DISABLED 1
RUN npm run build
ENV GOARCH=amd64

FROM octopus_server_base AS octopus_server_runtime
ARG OLLAMA_VERSION
ENV LANG=C.UTF-8 LC_ALL=C.UTF-8
ENV DEBIAN_FRONTEND=noninteractive \
    DEBCONF_NONINTERACTIVE_SEEN=true
ENV LANG_WHICH en
ENV LANG_WHERE US
ENV ENCODING UTF-8
ENV LANGUAGE ${LANG_WHICH}_${LANG_WHERE}.${ENCODING}
ENV LANG ${LANGUAGE}
RUN apt-get update --fix-missing && \
    apt-get install -y --no-install-recommends \
        acl \
        alsa-utils \
        bzip2 \
        cgroup-tools \
        davfs2 \
        eterm \
        feh \
        fluxbox \
        fonts-ipafont-gothic \
        fonts-liberation \
        fonts-noto-color-emoji \
        fonts-tlwg-loma-otf \
        fonts-ubuntu \
        fonts-wqy-zenhei \
        gnupg2 \
        hsetroot \
        jq \
        language-pack-en \
        libfontconfig \
        libfreetype6 \
        libglib2.0-0 \
        libnss3-tools \
        libnvidia-compute-550 \
        libsm6 \
        libxext6 \
        libxrender1 \
        locales \
        mercurial \
        nvidia-firmware-550-550.120 \
        nvidia-utils-550 \
        openjdk-11-jre-headless \
        openssh-client \
        procps \
        pulseaudio \
        socat \
        subversion \
        sudo \
        supervisor \
        tzdata \
        ubuntu-drivers-common \
        unzip \
        x11vnc \
        x11-utils \
        xauth \
        xvfb \
        xfonts-cyrillic \
        xfonts-scalable \
    && locale-gen ${LANGUAGE} \
    && dpkg-reconfigure --frontend noninteractive locales \
    && apt-get -qyy autoremove \
    && apt-get clean && \
    rm -rf /var/lib/apt/lists/*
RUN apt-mark hold libnvidia-compute-550 nvidia-firmware-550-550.120 nvidia-utils-550
RUN ubuntu-drivers install nvidia-driver-550
# https://github.com/ContinuumIO/docker-images/blob/main/miniconda3/debian/Dockerfile
ENV LANG=C.UTF-8 LC_ALL=C.UTF-8
ENV PATH=/opt/conda/bin:$PATH
CMD [ "/bin/bash" ]
ARG INSTALLER_URL_LINUX64="https://repo.anaconda.com/miniconda/Miniconda3-py312_24.11.1-0-Linux-x86_64.sh"
ARG SHA256SUM_LINUX64="636b209b00b6673471f846581829d4b96b9c3378679925a59a584257c3fef5a3"
ARG INSTALLER_URL_S390X="https://repo.anaconda.com/miniconda/Miniconda3-py312_24.11.1-0-Linux-s390x.sh"
ARG SHA256SUM_S390X="105bce6b0137f574147b8fdfd5e3a7d6c92f3ea9fbf3e0de61331ea43586e9af"
ARG INSTALLER_URL_AARCH64="https://repo.anaconda.com/miniconda/Miniconda3-py312_24.11.1-0-Linux-aarch64.sh"
ARG SHA256SUM_AARCH64="9180a2f1fab799fd76e9ef914643269dcf5bad9d455623b905b87f5d39ae140f"
RUN set -x && \
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

ENV SE_EVENT_BUS_HOST=localhost
ENV SE_EVENT_BUS_PUBLISH_PORT=4442
ENV SE_EVENT_BUS_SUBSCRIBE_PORT=4443

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
RUN sed -i 's/securerandom\.source=file:\/dev\/random/securerandom\.source=file:\/dev\/urandom/' /usr/lib/jvm/java-11-openjdk-amd64/conf/security/java.security
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

ARG DATABASE_URL
ARG OCTOPUS_PEPPER
ARG OCTOPUS_PEPPER_ID
ARG OCTOPUS_SERVER_PORT
ARG OPENAI_API_KEY
ARG SENDGRID_API_KEY
ARG NEXT_PUBLIC_BASE_URL
ARG NEXT_PUBLIC_DOMAIN
ARG NEXT_PUBLIC_THEME_NAME
ARG NEXTCLOUD_PASSWORD
ARG NEXTCLOUD_SUBDIR
ARG NEXTCLOUD_URL
ARG NEXTCLOUD_USERNAME
ENV NEXTCLOUD_MOUNT_POINT "/octopus_server/nextcloud_files/"
ENV NVIDIA_VISIBLE_DEVICES all
ENV NVIDIA_DRIVER_CAPABILITIES all
ENV NEXT_TELEMETRY_DISABLED 1
ENV PORT 3000
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
ENV OLLAMA_HOST http://localhost:5050
ENV OLLAMA_KEEP_ALIVE 2m
ENV LD_LIBRARY_PATH=$LD_LIBRARY_PATH:/usr/local/nvidia/lib:/usr/local/nvidia/lib64
RUN curl -fsSL https://ollama.com/install.sh | sh
WORKDIR /octopus_client
ARG NEXT_PUBLIC_SLACK_BOT_TOKEN
ARG NEXT_PUBLIC_SLACK_CHANNEL_ID
ARG NEXT_PUBLIC_SLACK_WEBHOOK_URL
COPY /octopus_client/.env.example .env
COPY /octopus_client/package.json ./
COPY /octopus_client/LICENSE /octopus_client/README.md /octopus_client/next-env.d.ts /octopus_client/next.config.js /octopus_client/package.json /octopus_client/package-lock.json /octopus_client/postcss.config.js /octopus_client/tailwind.config.js /octopus_client/tsconfig.json ./
COPY /octopus_client/public public/
COPY /octopus_client/src src/
WORKDIR /octopus_server
RUN mkdir -p /root/.cache/huggingface
RUN mkdir -p /root/.ollama
RUN mkdir -p data/generate/services
COPY --from=octopus_server_builder /usr/local/cargo/bin/cargo-sqlx ./
COPY --from=octopus_server_builder /usr/local/cargo/bin/sqlx ./
COPY --from=octopus_server_builder /octopus_server/target/release/octopus_server ./
COPY --from=octopus_server_builder /octopus_server/data/generate/services ./data/generate/services
COPY --from=octopus_server_builder /octopus_server/migrations ./migrations
COPY --from=octopus_server_builder /octopus_server/docker-entrypoint.sh ./
COPY --from=octopus_server_builder /octopus_server/frontend-start.sh ./
COPY --from=octopus_server_builder /octopus_server/mount-nextcloud.sh ./
RUN chmod +x docker-entrypoint.sh && \
    chmod +x frontend-start.sh && \
    chmod +x mount-nextcloud.sh && \
    mkdir ./nextcloud_files/ && \
    mkdir ./public/ && \
    mkdir ./services/ && \
    mkdir ./wasp_apps/ && \
    mkdir ./wasp_generator/
VOLUME /root/.cache/huggingface
VOLUME /root/.ollama
VOLUME /octopus_server/public
VOLUME /octopus_server/services
VOLUME /octopus_server/wasp_apps
VOLUME /octopus_server/wasp_generator
EXPOSE 3000
ENTRYPOINT ["./docker-entrypoint.sh"]
