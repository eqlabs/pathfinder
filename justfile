default:
    just --summary --unsorted

test $RUST_BACKTRACE="1" *args="":
    cargo nextest run --no-fail-fast --all-targets --all-features --workspace --locked \
    -E 'not test(/^p2p_network::sync_handlers::tests::prop/)' \
    {{args}}

proptest $RUST_BACKTRACE="1" *args="":
    cargo nextest run --no-fail-fast --all-targets --all-features --workspace --locked \
    -E 'test(/^p2p_network::sync_handlers::tests::prop/)' \
    {{args}}

build:
    cargo build --workspace --all-targets

check:
    cargo check --workspace --all-targets

fmt:
    cargo fmt --all

clippy:
    cargo clippy --workspace --all-targets --all-features --locked -- -D warnings -D rust_2018_idioms

dep-sort:
    cargo sort --check --workspace

doc:
    cargo doc --no-deps --document-private-items

alias b := build 
alias t := test 
alias c := check 
alias f := fmt 
