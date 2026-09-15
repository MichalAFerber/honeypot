.PHONY: build test fmt lint pi-gnu pi-musl pi-armv7

build:
	cargo build --release

test:
	cargo test

fmt:
	cargo fmt

lint:
	cargo clippy --all-targets -- -D warnings

# Cross-compile on a machine with Docker + `cargo install cross --git https://github.com/cross-rs/cross`
pi-gnu:
	cross build --release --target aarch64-unknown-linux-gnu

pi-musl:
	cross build --release --target aarch64-unknown-linux-musl

# Raspberry Pi OS 32-bit (`uname -m` = armv7l). The aarch64 builds above do not run there.
pi-armv7:
	cross build --release --target armv7-unknown-linux-musleabihf
