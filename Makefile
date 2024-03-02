MAKEFLAGS			+=	--jobs 1 --environment-overrides --silent
SHELL				:=	/bin/bash

.PHONY: all check test check_nostd
.ONESHELL: all check test check_nostd

all: | check test check_nostd

check:
	cargo check

test:
	cargo test --release --features="reference-sentinel"

check_nostd:
	utilities/precompiled/linux/amd64/cargo-no-std-check -p nagara-identities
	utilities/precompiled/linux/amd64/cargo-no-std-check -p nagara-logging
	utilities/precompiled/linux/amd64/cargo-no-std-check -p nagara-mnemonic
	utilities/precompiled/linux/amd64/cargo-no-std-check -p nagara-proto-structs
