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
FROM lukemathwalker/cargo-chef:0.1.48-rust-1.65.0-bullseye AS cargo-chef
WORKDIR /usr/src/pathfinder

# refresh indices, do it with cli git for much better ram usage
RUN CARGO_NET_GIT_FETCH_WITH_CLI=true cargo search --limit 0

FROM cargo-chef AS rust-planner
COPY . .
# carg-chef prepare examines your project and builds a recipe that captures
# the set of information required to build your dependencies.
RUN cargo chef prepare --recipe-path recipe.json

FROM cargo-chef AS rust-builder
RUN apt-get update && DEBIAN_FRONTEND=noninteractive apt-get install -y libssl-dev && rm -rf /var/lib/apt/lists/*

# The recipe.json is the equivalent of the Python requirements.txt file - it is the only
# input required for cargo chef cook, the command that will build out our dependencies.
COPY --from=rust-planner /usr/src/pathfinder/recipe.json recipe.json
RUN cargo chef cook --release --recipe-path recipe.json

# Compile the actual libraries and binary now
COPY . .
COPY ./.git /usr/src/pathfinder/.git

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
