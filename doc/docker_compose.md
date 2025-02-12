# Short Docker Compose installation guide

This configuration doesn't allow you to run either Octopus AI Services or Octopus WASP Applications. It's caused by the fact that for isolation purposes Octopus Server is starting Python and WASP apps using Linux kernel control groups. At least on Ubuntu 22.04 it's not possible to properly run cgexec under docker-compose. That is why you need to use Kubernetes to use all features of the system. Please read [Running on Kubernetes](doc/kubernetes.md) guide.

This configuration assumes that you have installed PostgreSQL on the base system. It was described in [Short PostgreSQL installation guide](postgresql.md).

You need to make sure that information about packages in the system is updated.

```sh
sudo apt-get update
```

You can install docker-compose now.

```sh
sudo apt-get install docker-compose
```

Save and edit the following config in the .env file.

```text
DATABASE_URL=postgres://postgres:somepassword@78.ip.address/octopus_server
NEXT_PUBLIC_BASE_URL=http://78.ip.address:8080/
NEXT_PUBLIC_DOMAIN=78.ip.address/
NEXT_PUBLIC_THEME_NAME=default-dark
NEXTCLOUD_PASSWORD=password
NEXTCLOUD_SUBDIR=octopus_retrieval/preview/
NEXTCLOUD_URL=url
NEXTCLOUD_USERNAME=username
OCTOPUS_PEPPER=somepepper
OCTOPUS_PEPPER_ID=0
OCTOPUS_SERVER_PORT=8080
OCTOPUS_WS_SERVER_PORT=8081
OPENAI_API_KEY=api_key
SENDGRID_API_KEY=api_key
WASP_DATABASE_URL=postgres://postgres:somepassword@78.ip.address
WEB_DRIVER_URL=http://localhost:9515
```

You can read environment variables from this file.

```sh
set -a
source .env
set +a
```

Save the following config as a docker-compose.yml file.

```yaml
version: '3.8'
services:
  octopus_server:
    image: metricspaceai/octopus_server:latest
    restart: always
    cap_add:
      - SYS_ADMIN
    environment:
      - DATABASE_URL=${DATABASE_URL}
      - NEXT_PUBLIC_BASE_URL=${NEXT_PUBLIC_BASE_URL}
      - NEXT_PUBLIC_DOMAIN=${NEXT_PUBLIC_DOMAIN}
      - NEXT_PUBLIC_THEME_NAME=${NEXT_PUBLIC_THEME_NAME}
      - NEXTCLOUD_PASSWORD=${NEXTCLOUD_PASSWORD}
      - NEXTCLOUD_SUBDIR=${NEXTCLOUD_SUBDIR}
      - NEXTCLOUD_URL=${NEXTCLOUD_URL}
      - NEXTCLOUD_USERNAME=${NEXTCLOUD_USERNAME}
      - OCTOPUS_PEPPER=${OCTOPUS_PEPPER}
      - OCTOPUS_PEPPER_ID=${OCTOPUS_PEPPER_ID}
      - OCTOPUS_SERVER_PORT=${OCTOPUS_SERVER_PORT}
      - OCTOPUS_WS_SERVER_PORT=${OCTOPUS_WS_SERVER_PORT}
      - OPENAI_API_KEY=${OPENAI_API_KEY}
      - SENDGRID_API_KEY=${SENDGRID_API_KEY}
      - WASP_DATABASE_URL=${WASP_DATABASE_URL}
      - WEB_DRIVER_URL=${WEB_DRIVER_URL}
    networks:
      - octopus_server_network
    ports:
      - '80:3000'
      - '8080:8080'
      - '8081:8081'
    privileged: true
    volumes:
      - type: bind
        source: /mnt/octopus-server-huggingface
        target: /root/.cache/huggingface
      - type: bind
        source: /mnt/octopus-server-ollama
        target: /root/.ollama
      - type: bind
        source: /mnt/octopus-server-public
        target: /octopus_server/public
      - type: bind
        source: /mnt/octopus-server-services
        target: /octopus_server/services
      - type: bind
        source: /mnt/octopus-server-wasp-apps
        target: /octopus_server/wasp_apps
      - type: bind
        source: /mnt/octopus-server-wasp-generator
        target: /octopus_server/wasp_generator
networks:
  octopus_server_network:
    driver: bridge
```

You need to create directories for bind mounts.

```sh
mkdir /mnt/octopus-server-huggingface
mkdir /mnt/octopus-server-ollama
mkdir /mnt/octopus-server-public
mkdir /mnt/octopus-server-services
mkdir /mnt/octopus-server-wasp-apps
mkdir /mnt/octopus-server-wasp-generator
```

Now you can start docker-compose.

```sh
docker-compose up -d
```

It may take some time to download a container image.

You can check the latest [published version](https://hub.docker.com/r/metricspaceai/octopus_server/tags) on Docker Hub.

The configuration above is good for testing on a local machine. However, if you want to expose the project to the Internet, you need to use a slightly more complicated solution.

Instead of using an IP address, you need to use a domain name in two parameters.

```text
DATABASE_URL=postgres://postgres:somepassword@78.ip.address/octopus_server
NEXT_PUBLIC_BASE_URL=http://api.mydomain.com/
NEXT_PUBLIC_DOMAIN=mydomain.com/
NEXT_PUBLIC_THEME_NAME=default-dark
NEXTCLOUD_PASSWORD=password
NEXTCLOUD_SUBDIR=octopus_retrieval/preview/
NEXTCLOUD_URL=url
NEXTCLOUD_USERNAME=username
OCTOPUS_PEPPER=somepepper
OCTOPUS_PEPPER_ID=0
OCTOPUS_SERVER_PORT=8080
OCTOPUS_WS_SERVER_PORT=8081
OPENAI_API_KEY=api_key
SENDGRID_API_KEY=api_key
WASP_DATABASE_URL=postgres://postgres:somepassword@78.ip.address
WEB_DRIVER_URL=http://localhost:9515
```

You need to use the following configuration in the docker-compose.yml file.

```yaml
version: '3.8'
services:
  traefik:
    image: traefik:v3.3.2
    container_name: traefik
    command:
      - "--api.insecure=true"
      - "--providers.docker=true"
      - "--entrypoints.web.address=:80"
      - "--entrypoints.websecure.address=:443"
      - "--certificatesresolvers.myresolver.acme.tlschallenge=true"
      - "--certificatesresolvers.myresolver.acme.email=email@example.com"
      - "--certificatesresolvers.myresolver.acme.storage=/letsencrypt/acme.json"
    network_mode: "bridge"
    ports:
      - "80:80"
      - "443:443"
    volumes:
      - "/var/run/docker.sock:/var/run/docker.sock:ro"
      - "./letsencrypt:/letsencrypt"

  octopus_server:
    image: metricspaceai/octopus_server:latest
    container_name: octopus_server
    restart: always
    cap_add:
      - SYS_ADMIN
    environment:
      - DATABASE_URL=${DATABASE_URL}
      - NEXT_PUBLIC_BASE_URL=${NEXT_PUBLIC_BASE_URL}
      - NEXT_PUBLIC_DOMAIN=${NEXT_PUBLIC_DOMAIN}
      - NEXT_PUBLIC_THEME_NAME=${NEXT_PUBLIC_THEME_NAME}
      - NEXTCLOUD_PASSWORD=${NEXTCLOUD_PASSWORD}
      - NEXTCLOUD_SUBDIR=${NEXTCLOUD_SUBDIR}
      - NEXTCLOUD_URL=${NEXTCLOUD_URL}
      - NEXTCLOUD_USERNAME=${NEXTCLOUD_USERNAME}
      - OCTOPUS_PEPPER=${OCTOPUS_PEPPER}
      - OCTOPUS_PEPPER_ID=${OCTOPUS_PEPPER_ID}
      - OCTOPUS_SERVER_PORT=${OCTOPUS_SERVER_PORT}
      - OCTOPUS_WS_SERVER_PORT=${OCTOPUS_WS_SERVER_PORT}
      - OPENAI_API_KEY=${OPENAI_API_KEY}
      - SENDGRID_API_KEY=${SENDGRID_API_KEY}
      - WASP_DATABASE_URL=${WASP_DATABASE_URL}
      - WEB_DRIVER_URL=${WEB_DRIVER_URL}
    network_mode: "bridge"
    labels:
      - "traefik.enable=true"
      - "traefik.http.routers.octopus_server.rule=Host(`mydomain.com`)"
      - "traefik.http.routers.octopus_server.entrypoints=websecure"
      - "traefik.http.routers.octopus_server.tls=true"
      - "traefik.http.routers.octopus_server.tls.certresolver=myresolver"
      - "traefik.http.routers.octopus_server.service=octopus_server"
      - "traefik.http.services.octopus_server.loadbalancer.server.port=3000"

      - "traefik.http.routers.api_octopus_server.rule=Host(`api.mydomain.com`) && PathPrefix(`/api/`)"
      - "traefik.http.routers.api_octopus_server.priority=2"
      - "traefik.http.routers.api_octopus_server.entrypoints=websecure"
      - "traefik.http.routers.api_octopus_server.tls=true"
      - "traefik.http.routers.api_octopus_server.tls.certresolver=myresolver"
      - "traefik.http.routers.api_octopus_server.service=api_service"
      - "traefik.http.services.api_service.loadbalancer.server.port=8080"

      - "traefik.http.routers.ws_octopus_server.rule=Host(`api.mydomain.com`) && PathPrefix(`/ws/`)"
      - "traefik.http.routers.ws_octopus_server.priority=3"
      - "traefik.http.routers.ws_octopus_server.entrypoints=websecure"
      - "traefik.http.routers.ws_octopus_server.tls=true"
      - "traefik.http.routers.ws_octopus_server.tls.certresolver=myresolver"
      - "traefik.http.routers.ws_octopus_server.service=ws_service"
      - "traefik.http.services.ws_service.loadbalancer.server.port=8081"
    ports:
      - "3000:3000"
      - "8080:8080"
      - "8081:8081"
    privileged: true
    volumes:
      - type: bind
        source: /mnt/octopus-server-huggingface
        target: /root/.cache/huggingface
      - type: bind
        source: /mnt/octopus-server-ollama
        target: /root/.ollama
      - type: bind
        source: /mnt/octopus-server-public
        target: /octopus_server/public
      - type: bind
        source: /mnt/octopus-server-services
        target: /octopus_server/services
      - type: bind
        source: /mnt/octopus-server-wasp-apps
        target: /octopus_server/wasp_apps
      - type: bind
        source: /mnt/octopus-server-wasp-generator
        target: /octopus_server/wasp_generator
```
