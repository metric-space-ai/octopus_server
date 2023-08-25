FROM rust:1.72.0-slim-bookworm AS chef
RUN apt-get update && apt-get install -y librust-openssl-dev
RUN cargo install cargo-chef
WORKDIR /octopus_server

FROM chef AS planner
COPY octopus_server /octopus_server/
RUN cargo chef prepare --recipe-path recipe.json

FROM chef AS builder
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

FROM rust:1.72.0-slim-bookworm AS prod
ARG DATABASE_URL
ARG OCTOPUS_PEPPER
ARG OCTOPUS_PEPPER_ID
ARG OCTOPUS_SERVER_PORT
ARG OPENAI_API_KEY
ARG SENDGRID_API_KEY
RUN apt-get update && apt-get install -y librust-openssl-dev
WORKDIR /octopus_server
COPY --from=builder /usr/local/cargo/bin/cargo-sqlx ./
COPY --from=builder /usr/local/cargo/bin/sqlx ./
COPY --from=builder /octopus_server/target/release/octopus_server ./
COPY --from=builder /octopus_server/migrations ./migrations
COPY --from=builder /octopus_server/docker-entrypoint.sh ./
RUN chmod +x docker-entrypoint.sh
RUN mkdir ./public/
ENTRYPOINT ["./docker-entrypoint.sh"]
