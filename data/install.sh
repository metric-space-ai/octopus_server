#!/bin/bash

DATABASE_PASSWORD=""
DOMAIN=""
OCTOPUS_CLIENT_VERSION="v0.7.8"
OCTOPUS_SERVER_VERSION="v0.10.23"
PROCEED="true"

save_env() {
    echo "$1=\"$2\"" | tee -a /etc/environment
}

install_base_utils() {
    echo "Installing base utils..."

    apt-get update && apt-get install -y \
        cgroup-tools \
        curl \
        gcc \
        git \
        librust-openssl-dev \
        unzip \
        wget
}

install_dialog() {
    echo "Installing dialog..."

    apt-get update && apt-get install -y dialog
}

install_go() {
    echo "Installing Go..."

    if [ -f go1.23.6.linux-amd64.tar.gz ]
    then
        echo "Deleting old go1.23.6.linux-amd64.tar.gz"
        rm -rf go1.23.6.linux-amd64.tar.gz
    fi

    wget https://go.dev/dl/go1.23.6.linux-amd64.tar.gz

    rm -rf /usr/local/go && tar -C /usr/local -xzf go1.23.6.linux-amd64.tar.gz

    PATH=$PATH:/usr/local/go/bin

    go version

    if [ -f go1.23.6.linux-amd64.tar.gz ]
    then
        echo "Deleting go1.23.6.linux-amd64.tar.gz"
        rm -rf go1.23.6.linux-amd64.tar.gz
    fi
}

install_miniconda() {
    echo "Installing Miniconda..."

    if [ -f /etc/profile.d/conda.sh ]
    then
        echo "Deleting old /etc/profile.d/conda.sh"
        rm -rf /etc/profile.d/conda.sh
    fi

    if [ -f Miniconda3-py312_25.1.1-2-Linux-x86_64.sh ]
    then
        echo "Deleting old Miniconda3-py312_25.1.1-2-Linux-x86_64.sh"
        rm -rf Miniconda3-py312_25.1.1-2-Linux-x86_64.sh
    fi

    wget https://repo.anaconda.com/miniconda/Miniconda3-py312_25.1.1-2-Linux-x86_64.sh

    bash Miniconda3-py312_25.1.1-2-Linux-x86_64.sh -b -u -p /opt/conda

    ln -s /opt/conda/etc/profile.d/conda.sh /etc/profile.d/conda.sh
    echo ". /opt/conda/etc/profile.d/conda.sh" >> ~/.bashrc
    echo "conda activate base" >> ~/.bashrc

    if [ -f Miniconda3-py312_25.1.1-2-Linux-x86_64.sh ]
    then
        echo "Deleting Miniconda3-py312_25.1.1-2-Linux-x86_64.sh"
        rm -rf Miniconda3-py312_25.1.1-2-Linux-x86_64.sh
    fi
}

install_nginx() {
    echo "Installing Nginx..."

    if [ -f /etc/nginx/sites-enabled/octopus ]
    then
        echo "Deleting old /etc/nginx/sites-enabled/octopus"
        rm -rf /etc/nginx/sites-enabled/octopus
    fi

    apt-get update
    apt-get install -y \
        certbot \
        nginx \
        python3-certbot-nginx

    echo "127.0.0.1 $DOMAIN" >> /etc/hosts

    cat > /etc/nginx/sites-available/octopus << EOF
server {
    listen 80;
    listen [::]:80;

    server_name $DOMAIN;

    location / {
        proxy_pass http://127.0.0.1:3000;
        proxy_set_header Host \$host;
        proxy_set_header X-Real-IP \$remote_addr;
        proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto \$scheme;
    }
}

server {
    listen 80;
    listen [::]:80;

    server_name api.$DOMAIN;

    location / {
        proxy_pass http://127.0.0.1:8080;
        proxy_set_header Host \$host;
        proxy_set_header X-Real-IP \$remote_addr;
        proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto \$scheme;
    }

    location /ws/ {
        proxy_pass http://127.0.0.1:8081;
        proxy_set_header Host \$host;
        proxy_set_header X-Real-IP \$remote_addr;
        proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto \$scheme;
    }
}
EOF
    ln -s /etc/nginx/sites-available/octopus /etc/nginx/sites-enabled/octopus

    certbot --nginx -d $DOMAIN -d api.$DOMAIN --agree-tos --register-unsafely-without-email

    systemctl restart nginx
    systemctl enable nginx
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

install_nvidia_cuda() {
    echo "Installing base Nvidia CUDA libraries..."

    if [ -f cuda-repo-ubuntu2404-12-8-local_12.8.0-570.86.10-1_amd64.deb ]
    then
        echo "Deleting old cuda-repo-ubuntu2404-12-8-local_12.8.0-570.86.10-1_amd64.deb"
        rm -rf cuda-repo-ubuntu2404-12-8-local_12.8.0-570.86.10-1_amd64.deb
    fi

    wget https://developer.download.nvidia.com/compute/cuda/repos/ubuntu2404/x86_64/cuda-ubuntu2404.pin
    mv cuda-ubuntu2404.pin /etc/apt/preferences.d/cuda-repository-pin-600
    wget https://developer.download.nvidia.com/compute/cuda/12.8.0/local_installers/cuda-repo-ubuntu2404-12-8-local_12.8.0-570.86.10-1_amd64.deb
    dpkg -i cuda-repo-ubuntu2404-12-8-local_12.8.0-570.86.10-1_amd64.deb
    cp /var/cuda-repo-ubuntu2404-12-8-local/cuda-*-keyring.gpg /usr/share/keyrings/
    apt-get update
    apt-get -y install cuda-toolkit-12-8

    if [ -f cuda-repo-ubuntu2404-12-8-local_12.8.0-570.86.10-1_amd64.deb ]
    then
        echo "Deleting cuda-repo-ubuntu2404-12-8-local_12.8.0-570.86.10-1_amd64.deb"
        rm -rf cuda-repo-ubuntu2404-12-8-local_12.8.0-570.86.10-1_amd64.deb
    fi
}

install_nvidia_driver() {
    echo "Installing Nvidia driver..."

    if [ -f nvidia-driver-local-repo-ubuntu2404-570.86.15_1.0-1_amd64.deb ]
    then
        echo "Deleting old nvidia-driver-local-repo-ubuntu2404-570.86.15_1.0-1_amd64.deb"
        rm -rf nvidia-driver-local-repo-ubuntu2404-570.86.15_1.0-1_amd64.deb
    fi

    wget https://us.download.nvidia.com/tesla/570.86.15/nvidia-driver-local-repo-ubuntu2404-570.86.15_1.0-1_amd64.deb
    dpkg -i nvidia-driver-local-repo-ubuntu2404-570.86.15_1.0-1_amd64.deb
    cp /var/nvidia-driver-local-repo-ubuntu2404-570.86.15/nvidia-driver-*-keyring.gpg /usr/share/keyrings/
    apt-get update
    apt-get install -y cuda-drivers-570

    if [ -f nvidia-driver-local-repo-ubuntu2404-570.86.15_1.0-1_amd64.deb ]
    then
        echo "Deleting nvidia-driver-local-repo-ubuntu2404-570.86.15_1.0-1_amd64.deb"
        rm -rf nvidia-driver-local-repo-ubuntu2404-570.86.15_1.0-1_amd64.deb
    fi
}

install_octopus_client() {
    echo "Installing Octopus Client..."

    if [ -f /etc/systemd/system/octopus_client.service ]
    then
        systemctl stop octopus_client
    fi

    if [ -d /opt/octopus_tmp ]
    then
        echo "Deleting old /opt/octopus_tmp"
        rm -rf /opt/octopus_tmp
    fi

    if [ -L /opt/octopus_client ]
    then
        echo "Deleting old /opt/octopus_client"
        rm -rf /opt/octopus_client
    fi

    if [ -d /opt/octopus_client_$OCTOPUS_CLIENT_VERSION ]
    then
        echo "Deleting old /opt/octopus_client_$OCTOPUS_CLIENT_VERSION"
        rm -rf /opt/octopus_client_$OCTOPUS_CLIENT_VERSION
    fi

    NEXT_PUBLIC_BASE_URL="https://api.$DOMAIN/"
    NEXT_PUBLIC_THEME_NAME="default-dark"
    NEXT_PUBLIC_DOMAIN="$DOMAIN/"
    NEXT_TELEMETRY_DISABLED=1

    sh -c "mkdir /opt/octopus_tmp \
        && cd /opt/octopus_tmp \
        && git clone https://github.com/metric-space-ai/octopus_client.git \
        && cd /opt/octopus_tmp/octopus_client \
        && git checkout $OCTOPUS_CLIENT_VERSION \
        && mkdir /opt/octopus_client_$OCTOPUS_CLIENT_VERSION"

    cp /opt/octopus_tmp/octopus_client/.env.example /opt/octopus_client_$OCTOPUS_CLIENT_VERSION/.env
    cp /opt/octopus_tmp/octopus_client/package.json /opt/octopus_client_$OCTOPUS_CLIENT_VERSION/
    cp /opt/octopus_tmp/octopus_client/LICENSE /opt/octopus_client_$OCTOPUS_CLIENT_VERSION/
    cp /opt/octopus_tmp/octopus_client/README.md /opt/octopus_client_$OCTOPUS_CLIENT_VERSION/
    cp /opt/octopus_tmp/octopus_client/next.config.js /opt/octopus_client_$OCTOPUS_CLIENT_VERSION/
    cp /opt/octopus_tmp/octopus_client/package.json /opt/octopus_client_$OCTOPUS_CLIENT_VERSION/
    cp /opt/octopus_tmp/octopus_client/package-lock.json /opt/octopus_client_$OCTOPUS_CLIENT_VERSION/
    cp /opt/octopus_tmp/octopus_client/postcss.config.js /opt/octopus_client_$OCTOPUS_CLIENT_VERSION/
    cp /opt/octopus_tmp/octopus_client/tailwind.config.js /opt/octopus_client_$OCTOPUS_CLIENT_VERSION/
    cp /opt/octopus_tmp/octopus_client/tsconfig.json /opt/octopus_client_$OCTOPUS_CLIENT_VERSION/
    cp -R /opt/octopus_tmp/octopus_client/public /opt/octopus_client_$OCTOPUS_CLIENT_VERSION/
    cp -R /opt/octopus_tmp/octopus_client/src /opt/octopus_client_$OCTOPUS_CLIENT_VERSION/

    sh -c "cd /opt/octopus_client_$OCTOPUS_CLIENT_VERSION \
        && npm install --frozen-lockfile \
        && NEXT_PUBLIC_BASE_URL=\"https://api.$DOMAIN/\" NEXT_PUBLIC_THEME_NAME=\"default-dark\" NEXT_PUBLIC_DOMAIN=\"$DOMAIN/\" npm run build"

    echo "NEXT_PUBLIC_BASE_URL=$NEXT_PUBLIC_BASE_URL" > /opt/octopus_client_$OCTOPUS_CLIENT_VERSION/.env.installer
    echo "NEXT_PUBLIC_THEME_NAME=$NEXT_PUBLIC_THEME_NAME" >> /opt/octopus_client_$OCTOPUS_CLIENT_VERSION/.env.installer
    echo "NEXT_PUBLIC_DOMAIN=$NEXT_PUBLIC_DOMAIN" >> /opt/octopus_client_$OCTOPUS_CLIENT_VERSION/.env.installer

    echo "#!/usr/bin/env bash" > /opt/octopus_client_$OCTOPUS_CLIENT_VERSION/client-start.sh
    echo "cd /opt/octopus_client_$OCTOPUS_CLIENT_VERSION/" >> /opt/octopus_client_$OCTOPUS_CLIENT_VERSION/client-start.sh
    echo "npm install --frozen-lockfile" >> /opt/octopus_client_$OCTOPUS_CLIENT_VERSION/client-start.sh
    echo "NEXT_PUBLIC_BASE_URL=$NEXT_PUBLIC_BASE_URL NEXT_PUBLIC_DOMAIN=$NEXT_PUBLIC_DOMAIN NEXT_PUBLIC_THEME_NAME=$NEXT_PUBLIC_THEME_NAME npm run custom-start" >> /opt/octopus_client_$OCTOPUS_CLIENT_VERSION/client-start.sh

    ln -s /opt/octopus_client_$OCTOPUS_CLIENT_VERSION /opt/octopus_client

    echo "[Unit]" > /etc/systemd/system/octopus_client.service
    echo "Description=Octopus Client systemd service unit file." >> /etc/systemd/system/octopus_client.service
    echo "[Service]" >> /etc/systemd/system/octopus_client.service
    echo "ExecStart=/bin/bash /opt/octopus_client/client-start.sh" >> /etc/systemd/system/octopus_client.service
    echo "[Install]" >> /etc/systemd/system/octopus_client.service
    echo "WantedBy=multi-user.target" >> /etc/systemd/system/octopus_client.service

    systemctl daemon-reload

    systemctl start octopus_client
    systemctl enable octopus_client

    if [ -d /opt/octopus_tmp ]
    then
        echo "Deleting old /opt/octopus_tmp"
        rm -rf /opt/octopus_tmp
    fi
}

install_octopus_server() {
    echo "Installing Octopus Server..."

    if [ -f /etc/systemd/system/octopus_server.service ]
    then
        systemctl stop octopus_server
    fi

    if [ -d /opt/octopus_tmp ]
    then
        echo "Deleting old /opt/octopus_tmp"
        rm -rf /opt/octopus_tmp
    fi

    if [ -L /opt/octopus_server ]
    then
        echo "Deleting old /opt/octopus_server"
        rm -rf /opt/octopus_server
    fi

    if [ -d /opt/octopus_server_$OCTOPUS_SERVER_VERSION ]
    then
        echo "Deleting old /opt/octopus_server_$OCTOPUS_SERVER_VERSION"
        rm -rf /opt/octopus_server_$OCTOPUS_SERVER_VERSION
    fi

    sh -c "mkdir /opt/octopus_tmp \
        && cd /opt/octopus_tmp \
        && git clone https://github.com/metric-space-ai/octopus_server.git \
        && cd /opt/octopus_tmp/octopus_server \
        && git checkout $OCTOPUS_SERVER_VERSION \
        && mkdir /opt/octopus_server_$OCTOPUS_SERVER_VERSION"

    DATABASE_URL="postgres://postgres:$DATABASE_PASSWORD@127.0.0.1/octopus_server"
    NEXTCLOUD_SUBDIR="octopus_retrieval/preview/"
    OCTOPUS_PEPPER=`date | sha1sum | cut -d " " -f 1`
    OCTOPUS_PEPPER_ID="0"
    OCTOPUS_SERVER_PORT="8080"
    OCTOPUS_WS_SERVER_PORT="8081"
    OLLAMA_HOST="http://localhost:11434"
    WASP_DATABASE_URL="postgres://postgres:$DATABASE_PASSWORD@127.0.0.1"
    WEB_DRIVER_URL="http://localhost:4444"

    if [ ! -d /mnt/octopus_server_public ]
    then
        echo "Creating /mnt/octopus_server_public"
        mkdir /mnt/octopus_server_public
    fi

    if [ ! -d /mnt/octopus_server_services ]
    then
        echo "Creating /mnt/octopus_server_services"
        mkdir /mnt/octopus_server_services
    fi

    if [ ! -d /mnt/octopus_server_wasp_apps ]
    then
        echo "Creating /mnt/octopus_server_wasp_apps"
        mkdir /mnt/octopus_server_wasp_apps
    fi

    if [ ! -d /mnt/octopus_server_wasp_generator ]
    then
        echo "Creating /mnt/octopus_server_wasp_generator"
        mkdir /mnt/octopus_server_wasp_generator
    fi

    DATABASE_URL=$DATABASE_URL sh -c "cd /opt/octopus_tmp/octopus_server && sqlx database create && sqlx migrate run && cargo build --release"

    cp /opt/octopus_tmp/octopus_server/target/release/octopus_server /opt/octopus_server_$OCTOPUS_SERVER_VERSION/
    mkdir -p /opt/octopus_server_$OCTOPUS_SERVER_VERSION/data/generate
    cp -R /opt/octopus_tmp/octopus_server/data/generate/services /opt/octopus_server_$OCTOPUS_SERVER_VERSION/data/generate
    cp -R /opt/octopus_tmp/octopus_server/migrations /opt/octopus_server_$OCTOPUS_SERVER_VERSION/

    echo "DATABASE_URL=$DATABASE_URL" > /opt/octopus_server_$OCTOPUS_SERVER_VERSION/.env.installer
    echo "NEXTCLOUD_SUBDIR=$NEXTCLOUD_SUBDIR" >> /opt/octopus_server_$OCTOPUS_SERVER_VERSION/.env.installer
    echo "OCTOPUS_PEPPER=$OCTOPUS_PEPPER" >> /opt/octopus_server_$OCTOPUS_SERVER_VERSION/.env.installer
    echo "OCTOPUS_PEPPER_ID=$OCTOPUS_PEPPER_ID" >> /opt/octopus_server_$OCTOPUS_SERVER_VERSION/.env.installer
    echo "OCTOPUS_SERVER_PORT=$OCTOPUS_SERVER_PORT" >> /opt/octopus_server_$OCTOPUS_SERVER_VERSION/.env.installer
    echo "OCTOPUS_WS_SERVER_PORT=$OCTOPUS_WS_SERVER_PORT" >> /opt/octopus_server_$OCTOPUS_SERVER_VERSION/.env.installer
    echo "OLLAMA_HOST=$OLLAMA_HOST" >> /opt/octopus_server_$OCTOPUS_SERVER_VERSION/.env.installer
    echo "WASP_DATABASE_URL=$WASP_DATABASE_URL" >> /opt/octopus_server_$OCTOPUS_SERVER_VERSION/.env.installer
    echo "WEB_DRIVER_URL=$WEB_DRIVER_URL" >> /opt/octopus_server_$OCTOPUS_SERVER_VERSION/.env.installer

    echo "#!/usr/bin/env bash" > /opt/octopus_server_$OCTOPUS_SERVER_VERSION/server-start.sh
    echo "cd /opt/octopus_server_$OCTOPUS_SERVER_VERSION/" >> /opt/octopus_server_$OCTOPUS_SERVER_VERSION/server-start.sh
    echo "DATABASE_URL=$DATABASE_URL sqlx database create" >> /opt/octopus_server_$OCTOPUS_SERVER_VERSION/server-start.sh
    echo "DATABASE_URL=$DATABASE_URL sqlx migrate run" >> /opt/octopus_server_$OCTOPUS_SERVER_VERSION/server-start.sh
    echo "DATABASE_URL=$DATABASE_URL NEXTCLOUD_SUBDIR=$NEXTCLOUD_SUBDIR OCTOPUS_PEPPER=$OCTOPUS_PEPPER OCTOPUS_PEPPER_ID=$OCTOPUS_PEPPER_ID OCTOPUS_SERVER_PORT=$OCTOPUS_SERVER_PORT OCTOPUS_WS_SERVER_PORT=$OCTOPUS_WS_SERVER_PORT OLLAMA_HOST=$OLLAMA_HOST WASP_DATABASE_URL=$WASP_DATABASE_URL WEB_DRIVER_URL=$WEB_DRIVER_URL ./octopus_server" >> /opt/octopus_server_$OCTOPUS_SERVER_VERSION/server-start.sh

    ln -s /opt/octopus_server_$OCTOPUS_SERVER_VERSION /opt/octopus_server

    ln -s /mnt/octopus_server_public /opt/octopus_server_$OCTOPUS_SERVER_VERSION/public
    ln -s /mnt/octopus_server_services /opt/octopus_server_$OCTOPUS_SERVER_VERSION/services
    ln -s /mnt/octopus_server_wasp_apps /opt/octopus_server_$OCTOPUS_SERVER_VERSION/wasp_apps
    ln -s /mnt/octopus_server_wasp_generator /opt/octopus_server_$OCTOPUS_SERVER_VERSION/wasp_generator

    echo "[Unit]" > /etc/systemd/system/octopus_server.service
    echo "Description=Octopus Server systemd service unit file." >> /etc/systemd/system/octopus_server.service
    echo "[Service]" >> /etc/systemd/system/octopus_server.service
    echo "ExecStart=/bin/bash /opt/octopus_server/server-start.sh" >> /etc/systemd/system/octopus_server.service
    echo "[Install]" >> /etc/systemd/system/octopus_server.service
    echo "WantedBy=multi-user.target" >> /etc/systemd/system/octopus_server.service

    systemctl daemon-reload

    systemctl start octopus_server
    systemctl enable octopus_server

    if [ -d /opt/octopus_tmp ]
    then
        echo "Deleting old /opt/octopus_tmp"
        rm -rf /opt/octopus_tmp
    fi
}

install_ollama() {
    echo "Installing Ollama..."

    curl -fsSL https://ollama.com/install.sh | sh
}

install_postgresql() {
    echo "Installing PostgreSQL..."

    apt-get update
    apt-get install -y postgresql

    systemctl start postgresql
    systemctl enable postgresql

    sed -i "s/#listen_addresses = 'localhost'/listen_addresses = '*'/g" /etc/postgresql/16/main/postgresql.conf

    echo "host    all             all             0.0.0.0/0            scram-sha-256" >> /etc/postgresql/16/main/pg_hba.conf

    systemctl restart postgresql

    ufw allow 5432/tcp

    if [ -f file.tmp ]
    then
        echo "Deleting old file.tmp"
        rm -rf file.tmp
    fi

    echo "ALTER USER postgres PASSWORD '$DATABASE_PASSWORD';" > file.tmp
    sudo -u postgres psql -f file.tmp

    if [ -f file.tmp ]
    then
        echo "Deleting file.tmp"
        rm -rf file.tmp
    fi
}

install_rust() {
    echo "Installing Rust..."

    curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh

    . "$HOME/.cargo/env"

    cargo install --force --locked sqlx-cli
}

install_selenium() {
    echo "Installing Selenium..."

    if [ -f google-chrome-stable_current_amd64.deb ]
    then
        echo "Deleting old google-chrome-stable_current_amd64.deb"
        rm -rf google-chrome-stable_current_amd64.deb
    fi

    wget https://dl.google.com/linux/direct/google-chrome-stable_current_amd64.deb
    apt-get install -y ./google-chrome-stable_current_amd64.deb

    if [ -f google-chrome-stable_current_amd64.deb ]
    then
        echo "Deleting google-chrome-stable_current_amd64.deb"
        rm -rf google-chrome-stable_current_amd64.deb
    fi
}

install_wasp() {
    echo "Installing WASP..."

    curl -sSL https://get.wasp.sh/installer.sh | sh
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
        install_nvidia_cuda
        install_nvidia_driver
        install_rust
        install_go
        install_node
        install_miniconda
        install_selenium
        install_ollama
        install_wasp
        install_postgresql
        install_octopus_client
        install_octopus_server
        install_nginx
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

save_env "PATH" $PATH

if [ -f file.tmp ]
then
    echo "Deleting file.tmp"
    rm -rf file.tmp
fi
