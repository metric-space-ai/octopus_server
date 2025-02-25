OCTOPUS_CLIENT_VERSION="v0.7.7"
OCTOPUS_SERVER_VERSION="v0.10.19"

update_octopus_client() {
    echo "Updating Octopus Client..."

    if [ -d /opt/octopus_client_$OCTOPUS_CLIENT_VERSION ]
    then
        echo "This version is already installed in /opt/octopus_client_$OCTOPUS_CLIENT_VERSION"

        return
    fi

    if [ -f /etc/systemd/system/octopus_client.service ]
    then
        systemctl stop octopus_client
    fi

    if [ -d /opt/octopus_tmp ]
    then
        echo "Deleting old /opt/octopus_tmp"
        rm -rf /opt/octopus_tmp
    fi

    . /opt/octopus_client/.env.installer

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

    if [ -L /opt/octopus_client ]
    then
        echo "Deleting old /opt/octopus_client"
        rm -rf /opt/octopus_client
    fi

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

update_octopus_server() {
    echo "Updating Octopus Server..."

    if [ -d /opt/octopus_server_$OCTOPUS_SERVER_VERSION ]
    then
        echo "This version is already installed in /opt/octopus_server_$OCTOPUS_SERVER_VERSION"

        return
    fi

    if [ -f /etc/systemd/system/octopus_server.service ]
    then
        systemctl stop octopus_server
    fi

    if [ -d /opt/octopus_tmp ]
    then
        echo "Deleting old /opt/octopus_tmp"
        rm -rf /opt/octopus_tmp
    fi

    sh -c "mkdir /opt/octopus_tmp \
        && cd /opt/octopus_tmp \
        && git clone https://github.com/metric-space-ai/octopus_server.git \
        && cd /opt/octopus_tmp/octopus_server \
        && git checkout $OCTOPUS_SERVER_VERSION \
        && mkdir /opt/octopus_server_$OCTOPUS_SERVER_VERSION"

    . /opt/octopus_server/.env.installer

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

    if [ -L /opt/octopus_server ]
    then
        echo "Deleting old /opt/octopus_server"
        rm -rf /opt/octopus_server
    fi

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

update_octopus_client
update_octopus_server
