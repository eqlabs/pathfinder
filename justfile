default:
    just --summary --unsorted

test $RUST_BACKTRACE="1" *args="":
    cargo build --release -p pathfinder --bin pathfinder -F p2p
    cargo nextest run --no-fail-fast --all-targets --features p2p,consensus-integration-tests --workspace --locked \
    -E 'not test(/^p2p_network::sync_handlers::tests::prop/)' \
    {{args}}

test-all-features $RUST_BACKTRACE="1" *args="":
    cargo nextest run --no-fail-fast --all-targets --all-features --workspace --locked \
    -E 'not test(/^p2p_network::sync::sync_handlers::tests::prop/)' \
    {{args}}

proptest $RUST_BACKTRACE="1" *args="":
    cargo nextest run --no-fail-fast --all-targets --features p2p --workspace --locked \
    -E 'test(/^p2p_network::sync::sync_handlers::tests::prop/)' \
    {{args}}

build:
    cargo build --workspace --all-targets

build-all-features:
    cargo build --workspace --all-targets --all-features

check:
    cargo check --workspace --all-targets

check-all-features:
    cargo check --workspace --all-targets --all-features

fmt:
    cargo +nightly fmt --all

clippy *args="":
    cargo clippy --workspace --all-targets --features p2p --locked {{args}} -- -D warnings -D rust_2018_idioms

clippy-all-features *args="":
    cargo clippy --workspace --all-targets --all-features --locked {{args}} -- -D warnings -D rust_2018_idioms

dep-sort:
    cargo sort --check --workspace

doc:
    cargo doc --no-deps --document-private-items

release version:
    scripts/release.sh {{version}}

alias b := build 
alias t := test 
alias c := check 
alias f := fmt 
alias r := release
