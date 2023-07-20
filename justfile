default:
    just --summary --unsorted

test $RUST_BACKTRACE="1" *args="":
    . .venv/bin/activate && \
    cargo nextest run --no-fail-fast --all-targets --all-features --workspace --locked {{args}}

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

alias b := build 
alias t := test 
alias c := check 
alias f := fmt 