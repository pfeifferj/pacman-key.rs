VERSION = 0.1.0

.PHONY: all build clean lint test check doc fmt

all: build

build:
	cargo build --release

clean:
	cargo clean

lint:
	cargo clippy -- -D warnings

test:
	cargo test

check: lint
	cargo fmt --check
	$(MAKE) test

doc:
	cargo doc --no-deps

fmt:
	cargo fmt
