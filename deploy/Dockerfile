# Multi-stage SeDat build (Linux primary)
FROM rust:latest AS builder
WORKDIR /src
COPY . .
RUN cargo test
RUN cargo build --release
RUN cargo clippy --all-targets -- -D warnings || true

FROM debian:bookworm-slim AS runtime
RUN apt-get update && apt-get install -y --no-install-recommends ca-certificates \
    && rm -rf /var/lib/apt/lists/* \
    && useradd -r -u 10001 -d /app sedat
WORKDIR /app
COPY --from=builder /src/target/release/sedat /usr/local/bin/sedat
RUN mkdir -p /app/state && chown -R sedat:sedat /app
USER sedat
EXPOSE 8080 8443
ENTRYPOINT ["sedat"]
CMD ["--config", "/app/config.toml", "--listen", "0.0.0.0:8080"]
