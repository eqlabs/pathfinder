# when developing this file, you might want to start by creating a copy of this
# file away from the source tree and then editing that, finally committing a
# changed version of this file. editing this file will render most of the
# layers unusable.
#
# our build process requires that all files are copied for the rust build,
# which uses `git describe --tags` to determine the build identifier.
# Dockerfile cannot be .dockerignore'd because of this as it would produce a
# false dirty flag.

########################################
# Stage 1: Build the pathfinder binary #
########################################
# Note that we're explicitly using the Debian bullseye image to make sure we're
# compatible with the Python container we'll be copying the pathfinder
# executable to.
FROM rust:1.65-bullseye AS rust-builder

RUN apt-get update && DEBIAN_FRONTEND=noninteractive apt-get install -y libssl-dev && rm -rf /var/lib/apt/lists/*

WORKDIR /usr/src/pathfinder

# Build only the dependencies first. This utilizes
# container layer caching for Rust builds
RUN mkdir crates \
    && cargo new --lib --vcs none crates/stark_curve \
    && cargo new --lib --vcs none crates/stark_hash \
    && cargo new --lib --vcs none crates/common \
    && cargo new --lib --vcs none crates/ethereum \
    && cargo new --lib --vcs none crates/gateway-client \
    && cargo new --lib --vcs none crates/gateway-test-fixtures \
    && cargo new --lib --vcs none crates/gateway-types \
    && cargo new --lib --vcs none crates/retry \
    && cargo new --lib --vcs none crates/serde \
    && cargo new --lib --vcs none crates/storage \
    && cargo new --lib --vcs none crates/pathfinder

COPY Cargo.toml Cargo.lock ./

COPY crates/stark_curve/Cargo.toml crates/stark_curve/Cargo.toml
COPY crates/stark_hash/Cargo.toml crates/stark_hash/
COPY crates/stark_hash/benches crates/stark_hash/benches

COPY crates/common/Cargo.toml crates/common/build.rs crates/common/
COPY crates/ethereum/Cargo.toml crates/ethereum/Cargo.toml
COPY crates/gateway-client/Cargo.toml crates/gateway-client/Cargo.toml
COPY crates/gateway-test-fixtures/Cargo.toml crates/gateway-test-fixtures/Cargo.toml
COPY crates/gateway-types/Cargo.toml crates/gateway-types/Cargo.toml
COPY crates/retry/Cargo.toml crates/retry/Cargo.toml
COPY crates/serde/Cargo.toml crates/serde/Cargo.toml
COPY crates/storage/Cargo.toml crates/storage/Cargo.toml

COPY crates/pathfinder/benches crates/pathfinder/benches

# refresh indices, do it with cli git for much better ram usage
RUN CARGO_NET_GIT_FETCH_WITH_CLI=true cargo search --limit 0

# DEPENDENCY_LAYER=1 should disable any vergen interaction, because the .git directory is not yet available
RUN CARGO_INCREMENTAL=0 DEPENDENCY_LAYER=1 cargo build --release -p pathfinder

# Compile the actual libraries and binary now
COPY . .
COPY ./.git /usr/src/pathfinder/.git

# Mark these for re-compilation
RUN touch crates/*/src/lib.rs crates/*/build.rs

RUN CARGO_INCREMENTAL=0 cargo build --release -p pathfinder --bin pathfinder

#######################################
# Stage 2: Build the Python libraries #
#######################################
FROM python:3.8-slim-bullseye AS python-builder

RUN apt-get update && DEBIAN_FRONTEND=noninteractive apt-get install -y libgmp-dev gcc && rm -rf /var/lib/apt/lists/*

WORKDIR /usr/share/pathfinder
COPY py py
RUN python3 -m pip --disable-pip-version-check install py/.

# This reduces the size of the python libs by about 50%
ENV PY_PATH=/usr/local/lib/python3.8/
RUN find ${PY_PATH} -type d -a -name test -exec rm -rf '{}' + \
    && find ${PY_PATH} -type d -a -name tests  -exec rm -rf '{}' + \
    && find ${PY_PATH} -type f -a -name '*.pyc' -exec rm -rf '{}' + \
    && find ${PY_PATH} -type f -a -name '*.pyo' -exec rm -rf '{}' +

#######################
# Final Stage: Runner #
#######################
# Note that we're explicitly using the Debian bullseye image to make sure we're
# compatible with the Rust builder we've built the pathfinder executable in.
FROM python:3.8-slim-bullseye AS runner

RUN apt-get update && DEBIAN_FRONTEND=noninteractive apt-get install -y libgmp10 tini && rm -rf /var/lib/apt/lists/*
RUN groupadd --gid 1000 pathfinder && useradd --no-log-init --uid 1000 --gid pathfinder --no-create-home pathfinder

COPY --from=rust-builder /usr/src/pathfinder/target/release/pathfinder /usr/local/bin/pathfinder
COPY --from=python-builder /usr/local/lib/python3.8/site-packages /usr/local/lib/python3.8/site-packages
COPY --from=python-builder /usr/local/bin/pathfinder_python_worker /usr/local/bin

# Create directory and volume for persistent data
RUN install --owner 1000 --group 1000 --mode 0755 -d /usr/share/pathfinder/data
VOLUME /usr/share/pathfinder/data

USER 1000:1000
EXPOSE 9545
WORKDIR /usr/share/pathfinder/data

# this is required to have exposing ports work from docker, the default is not this.
ENV PATHFINDER_HTTP_RPC_ADDRESS="0.0.0.0:9545"

# this has been changed in #335 to follow docker best practices example; every
# time it is changed it will be a breaking change. this allows `docker run
# eqlabs/pathfinder --help` to give an introductory path to configuration.
ENTRYPOINT ["/usr/bin/tini", "--", "/usr/local/bin/pathfinder"]

# empty CMD is needed and cannot be --help because otherwise configuring from
# environment variables only would be impossible and require a workaround.
CMD []
