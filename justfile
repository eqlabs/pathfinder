default:
    just --summary --unsorted

test $RUST_BACKTRACE="1" *args="":
    cargo nextest run --no-fail-fast --all-targets --features p2p --workspace --locked \
    -E 'not test(/^p2p_network::sync_handlers::tests::prop/)' \
    {{args}}

proptest $RUST_BACKTRACE="1" *args="":
    cargo nextest run --no-fail-fast --all-targets --features p2p --workspace --locked \
    -E 'test(/^p2p_network::sync_handlers::tests::prop/)' \
    {{args}}

build:
    cargo build --workspace --all-targets

check:
    cargo check --workspace --all-targets

fmt:
    cargo +nightly fmt --all

clippy *args="":
    cargo clippy --workspace --all-targets --features p2p --locked {{args}} -- -D warnings -D rust_2018_idioms

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
