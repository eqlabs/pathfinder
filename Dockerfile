########################################
# Stage 1: Build the pathfinder binary #
########################################
FROM rust:1.59-alpine AS rust-builder

RUN apk add --no-cache musl-dev gcc openssl-dev

WORKDIR /usr/src/pathfinder

# Build only the dependencies first. This utilizes
# container layer caching for Rust builds
RUN mkdir crates
RUN cargo new --lib --vcs none crates/pedersen
# Correct: --lib. We'll handle the binary later.
RUN cargo new --lib --vcs none crates/pathfinder
COPY Cargo.toml Cargo.toml
COPY Cargo.lock Cargo.lock

COPY crates/pathfinder/Cargo.toml crates/pathfinder/Cargo.toml
COPY crates/pathfinder/build.rs crates/pathfinder/build.rs
COPY crates/pedersen/Cargo.toml crates/pedersen/Cargo.toml
COPY crates/pedersen/benches crates/pedersen/benches

# DEPENDENCY_LAYER=1 should disable any vergen interaction, because the .git directory is not yet available
RUN DEPENDENCY_LAYER=1 RUSTFLAGS='-L/usr/lib -Ctarget-feature=-crt-static' cargo build --release

# Compile the actual libraries and binary now
COPY . .
COPY ./.git /usr/src/pathfinder/.git

# Mark these for re-compilation
RUN touch crates/pathfinder/src/lib.rs
RUN touch crates/pathfinder/src/build.rs
RUN touch crates/pedersen/src/lib.rs

RUN RUSTFLAGS='-L/usr/lib -Ctarget-feature=-crt-static' cargo build --release

#######################################
# Stage 2: Build the Python libraries #
#######################################
FROM python:3.8-alpine AS python-builder

RUN apk add --no-cache gcc musl-dev gmp-dev g++

WORKDIR /usr/share/pathfinder
COPY py py
RUN python3 -m pip install --upgrade pip
RUN python3 -m pip install -r py/requirements-dev.txt

# This reduces the size of the python libs by about 50%
ENV PY_PATH=/usr/local/lib/python3.8/
RUN find ${PY_PATH} -type d -a -name test -exec rm -rf '{}' +
RUN find ${PY_PATH} -type d -a -name tests  -exec rm -rf '{}' +
RUN find ${PY_PATH} -type f -a -name '*.pyc' -exec rm -rf '{}' +
RUN find ${PY_PATH} -type f -a -name '*.pyo' -exec rm -rf '{}' +

#######################
# Final Stage: Runner #
#######################
FROM python:3.8-alpine AS runner

RUN apk add --no-cache tini

COPY --from=rust-builder ["/usr/lib/libstdc++.so.6", "/usr/lib/libgcc_s.so.1", "/usr/lib/libgmp.so.10", "/usr/lib/" ]
COPY --from=rust-builder /usr/src/pathfinder/target/release/pathfinder /usr/local/bin/pathfinder
COPY --from=python-builder /usr/local/lib/python3.8/ /usr/local/lib/python3.8/

# Create directory and volume for persistent data
RUN mkdir -p /usr/share/pathfinder/data
RUN chown 1000:1000 /usr/share/pathfinder/data
VOLUME /usr/share/pathfinder/data

USER 1000:1000
EXPOSE 9545
EXPOSE 8080
WORKDIR /usr/share/pathfinder/data

ENV PATHFINDER_HTTP_RPC_ADDRESS="0.0.0.0:9545"

ENTRYPOINT ["/sbin/tini", "--"]
CMD ["/usr/local/bin/pathfinder"]
