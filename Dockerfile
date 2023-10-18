FROM rust:1.73.0-slim-bookworm AS chef
RUN apt-get update && apt-get install -y librust-openssl-dev
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

FROM rust:1.73.0-slim-bookworm AS prod
RUN apt-get update && apt-get install -y librust-openssl-dev
RUN apt-get install -y g++ git procps wget
RUN wget https://repo.anaconda.com/archive/Anaconda3-2023.09-0-Linux-x86_64.sh -O anaconda.sh -q && \
  /bin/bash anaconda.sh -b && \
  rm anaconda.sh
ARG AZURE_OPENAI_API_KEY
ARG AZURE_OPENAI_DEPLOYMENT_ID
ARG AZURE_OPENAI_ENABLED
ARG DATABASE_URL
ARG OCTOPUS_PEPPER
ARG OCTOPUS_PEPPER_ID
ARG OCTOPUS_SERVER_PORT
ARG OPENAI_API_KEY
ARG SENDGRID_API_KEY
ENV PATH="/root/anaconda3/bin:$PATH"
RUN conda init
WORKDIR /octopus_server
COPY --from=builder /usr/local/cargo/bin/cargo-sqlx ./
COPY --from=builder /usr/local/cargo/bin/sqlx ./
COPY --from=builder /octopus_server/target/release/octopus_server ./
COPY --from=builder /octopus_server/migrations ./migrations
COPY --from=builder /octopus_server/docker-entrypoint.sh ./
RUN chmod +x docker-entrypoint.sh
RUN mkdir ./public/
RUN mkdir ./services/
ENTRYPOINT ["./docker-entrypoint.sh"]
