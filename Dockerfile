FROM rust:1.91-slim-bookworm AS chef
RUN apt-get update && \
    apt-get -y upgrade && \
    apt-get install -y \
        llvm \
        clang \
        libclang-dev \
        cmake \
        pkg-config \
        libssl-dev \
        libleveldb-dev \
        gcc \
        mold \
        ca-certificates && \
    rm -rf /var/lib/apt/lists/*
RUN cargo install --locked cargo-chef
WORKDIR /app

FROM chef AS planner
COPY . .
RUN cargo chef prepare --recipe-path recipe.json

FROM chef AS builder
# leveldb-sys fails on gcc's -Wthread-safety.
ENV CC=clang CXX=clang++
# Rustflags and env (tokio_unstable, RUST_MIN_STACK) must already apply when cooking dependencies.
COPY .cargo .cargo
COPY rust-toolchain.toml .
COPY --from=planner /app/recipe.json recipe.json
RUN cargo chef cook --release --locked --no-default-features -p neptune-privacy -p xnt-dashboard -p xnt-core-cli \
    --features neptune-privacy/rest --recipe-path recipe.json
COPY . .
RUN cargo build --release --locked --no-default-features -p neptune-privacy -p xnt-dashboard -p xnt-core-cli \
    --features neptune-privacy/rest --bin xnt-core --bin xnt-dashboard --bin xnt-cli \
    --bin triton-vm-prover

FROM debian:bookworm-slim AS runtime
RUN apt-get update && \
    apt-get install -y --no-install-recommends libleveldb1d curl && \
    rm -rf /var/lib/apt/lists/*
COPY --from=builder /app/target/release/xnt-core /usr/local/bin/xnt-core
COPY --from=builder /app/target/release/xnt-dashboard /usr/local/bin/xnt-dashboard
COPY --from=builder /app/target/release/xnt-cli /usr/local/bin/xnt-cli
COPY --from=builder /app/target/release/triton-vm-prover /usr/local/bin/triton-vm-prover

VOLUME /data
# JSON-RPC (9897), REST API (9900), peer port (9898)
EXPOSE 9897 9898 9900
CMD ["xnt-core", \
     "--network", "testnet", \
     "--compose", "--guess", \
     "--data-dir", "/data", \
     "--listen-rpc", "0.0.0.0:9897", \
     "--rest-api-enable", \
     "--rest-port", "9900", \
     "--rest-listening-address", "0.0.0.0", \
     "--max-num-peers", "0"]
