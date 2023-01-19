#######################################
# Builder
#######################################
FROM rust:1.65-bullseye AS rust-builder

RUN apt-get update && DEBIAN_FRONTEND=noninteractive apt-get install -y libssl-dev protobuf-compiler && rm -rf /var/lib/apt/lists/*

WORKDIR /usr/src/pathfinder
COPY . .
COPY ./.git .git

RUN CARGO_INCREMENTAL=0 cargo build --release -p p2p --example peer

#######################################
# Runner
#######################################
FROM debian:bullseye-slim AS runner

RUN apt-get update && DEBIAN_FRONTEND=noninteractive apt-get install -y libgmp10 tini && rm -rf /var/lib/apt/lists/*
RUN groupadd --gid 1000 pathfinder && useradd --no-log-init --uid 1000 --gid pathfinder --no-create-home pathfinder

COPY --from=rust-builder /usr/src/pathfinder/target/release/examples/peer /usr/local/bin/peer

USER 1000:1000
EXPOSE 4000
WORKDIR /tmp

ENTRYPOINT ["/usr/bin/tini", "--", "/usr/local/bin/peer"]
CMD []
