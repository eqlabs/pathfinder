# Our Dockerfile relies on the PATHFINDER_FORCE_VERSION build-time variable being set.
# This is required so that we don't have to copy the .git directory into the layer which
# might cause caches to be invalidated even if that's unnecessary.

########################################
# Stage 1: Build the pathfinder binary #
########################################
# Note that we're explicitly using the Debian bullseye image to make sure we're
# compatible with the Python container we'll be copying the pathfinder
# executable to.
FROM --platform=$BUILDPLATFORM lukemathwalker/cargo-chef:0.1.50-rust-1.66-bullseye AS cargo-chef
WORKDIR /usr/src/pathfinder

# refresh indices, do it with cli git for much better ram usage
RUN CARGO_NET_GIT_FETCH_WITH_CLI=true cargo search --limit 0

FROM --platform=$BUILDPLATFORM cargo-chef AS rust-planner
COPY . .
# carg-chef prepare examines your project and builds a recipe that captures
# the set of information required to build your dependencies.
RUN cargo chef prepare --recipe-path recipe.json

FROM --platform=$BUILDPLATFORM cargo-chef AS rust-builder
ARG TARGETARCH
COPY ./build/prepare.sh prepare.sh
RUN TARGETARCH=${TARGETARCH} ./prepare.sh

# The recipe.json is the equivalent of the Python requirements.txt file - it is the only
# input required for cargo chef cook, the command that will build out our dependencies.
COPY --from=rust-planner /usr/src/pathfinder/recipe.json recipe.json
COPY ./build/cargo-chef-cook.sh ./cargo-chef-cook.sh
RUN TARGETARCH=${TARGETARCH} ./cargo-chef-cook.sh --release --recipe-path recipe.json

# Compile the actual libraries and binary now
COPY . .
ARG PATHFINDER_FORCE_VERSION
COPY ./build/cargo-build.sh ./cargo-build.sh
RUN TARGETARCH=${TARGETARCH} \
    PATHFINDER_FORCE_VERSION=${PATHFINDER_FORCE_VERSION} \
    ./cargo-build.sh --locked --release -p pathfinder --bin pathfinder \
    && cp target/*-unknown-linux-gnu/release/pathfinder pathfinder-${TARGETARCH}


#############################################
# Stage 1.5: Build the Python Pedersen hash #
#############################################
FROM --platform=$BUILDPLATFORM cargo-chef AS rust-python-starkhash-planner
COPY crates/stark_curve crates/stark_curve
COPY crates/stark_hash crates/stark_hash
COPY crates/stark_hash_python crates/stark_hash_python
RUN cd crates/stark_hash_python && \
    cargo chef prepare --recipe-path recipe.json


FROM --platform=$BUILDPLATFORM cargo-chef AS rust-python-starkhash-builder
ARG TARGETARCH
COPY ./build/prepare-stark_hash_python.sh prepare-stark_hash_python.sh
RUN TARGETARCH=${TARGETARCH} ./prepare-stark_hash_python.sh
COPY --from=rust-python-starkhash-planner /usr/src/pathfinder/crates/stark_hash_python/recipe.json /usr/src/pathfinder/crates/stark_hash_python/recipe.json
COPY crates/stark_curve crates/stark_curve
COPY crates/stark_hash crates/stark_hash
COPY ./build/cargo-chef-cook.sh ./crates/stark_hash_python/cargo-chef-cook.sh
RUN cd crates/stark_hash_python && TARGETARCH=${TARGETARCH} ./cargo-chef-cook.sh --release --recipe-path recipe.json

COPY crates/stark_hash_python crates/stark_hash_python
COPY ./build/cargo-build.sh ./crates/stark_hash_python/cargo-build.sh
RUN cd crates/stark_hash_python \
    && TARGETARCH=${TARGETARCH} ./cargo-build.sh --locked --release \
    && cp target/*-unknown-linux-gnu/release/libstark_hash_rust.so stark_hash_rust.so-${TARGETARCH}

#######################################
# Stage 2: Build the Python libraries #
#######################################
FROM python:3.9-slim-bullseye AS python-builder
ARG TARGETARCH

RUN apt-get update && DEBIAN_FRONTEND=noninteractive apt-get install -y libgmp-dev gcc && rm -rf /var/lib/apt/lists/*

WORKDIR /usr/share/pathfinder
COPY py py
RUN --mount=type=cache,target=/root/.cache/pip python3 -m pip --disable-pip-version-check install py/.
COPY --from=rust-python-starkhash-builder /usr/src/pathfinder/crates/stark_hash_python/stark_hash_rust.so-${TARGETARCH} /usr/local/lib/python3.9/site-packages/stark_hash_rust.so

# This reduces the size of the python libs by about 50%
ENV PY_PATH=/usr/local/lib/python3.9/
RUN find ${PY_PATH} -type d -a -name test -exec rm -rf '{}' + \
    && find ${PY_PATH} -type d -a -name tests  -exec rm -rf '{}' + \
    && find ${PY_PATH} -type f -a -name '*.pyc' -exec rm -rf '{}' + \
    && find ${PY_PATH} -type f -a -name '*.pyo' -exec rm -rf '{}' +

#######################
# Final Stage: Runner #
#######################
# Note that we're explicitly using the Debian bullseye image to make sure we're
# compatible with the Rust builder we've built the pathfinder executable in.
FROM python:3.9-slim-bullseye AS runner
ARG TARGETARCH

RUN apt-get update && DEBIAN_FRONTEND=noninteractive apt-get install -y libgmp10 tini && rm -rf /var/lib/apt/lists/*
RUN groupadd --gid 1000 pathfinder && useradd --no-log-init --uid 1000 --gid pathfinder --no-create-home pathfinder

COPY --from=rust-builder /usr/src/pathfinder/pathfinder-${TARGETARCH} /usr/local/bin/pathfinder
COPY --from=python-builder /usr/local/lib/python3.9/site-packages /usr/local/lib/python3.9/site-packages
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
