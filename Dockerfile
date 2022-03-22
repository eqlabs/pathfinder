########################################
# Stage 1: Build the pathfinder binary #
########################################
FROM rust:1.59-bullseye AS rust-builder

RUN apt-get update && apt-get install -y musl-dev gcc libssl-dev

WORKDIR /usr/src/pathfinder

# Build only the dependencies first. This utilizes
# container layer caching for Rust builds
RUN mkdir crates
RUN cargo new --lib crates/pedersen
# Correct: --lib. We'll handle the binary later.
RUN cargo new --lib crates/pathfinder
COPY Cargo.toml Cargo.toml

COPY crates/pathfinder/Cargo.toml crates/pathfinder/Cargo.toml
COPY crates/pedersen/Cargo.toml crates/pedersen/Cargo.toml
COPY crates/pedersen/benches crates/pedersen/benches

RUN RUSTFLAGS='-L/usr/lib -Ctarget-feature=-crt-static' cargo build --release


# Compile the actual libraries and binary now
COPY . .

# Mark these for re-compilation
RUN touch crates/pathfinder/src/lib.rs
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

RUN apk add --no-cache tini libstdc++ libgcc gmp

COPY --from=rust-builder [ "/usr/lib/" ]

COPY --from=rust-builder /usr/src/pathfinder/target/release/pathfinder /usr/local/bin/pathfinder
COPY --from=python-builder /usr/local/lib/python3.8/ /usr/local/lib/python3.8/

# Create directory and volume for persistent data
RUN mkdir -p /usr/share/pathfinder/data
RUN chown 1000:1000 /usr/share/pathfinder/data
VOLUME /usr/share/pathfinder/data

# Move the start script in the Dockerfile
COPY start-node.sh /tmp/start-node.sh
RUN chmod +x /tmp/start-node.sh && mv /tmp/start-node.sh /usr/local/bin/start-node.sh && chmod 755 /usr/local/bin/start-node.sh

USER 1000:1000
EXPOSE 9545
WORKDIR /usr/share/pathfinder/data

ENTRYPOINT ["sh", "/usr/local/bin/start-node.sh"]

