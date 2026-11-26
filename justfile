# Adapted from Rust-Toolchain's template; public interface: rust-tc.
set shell := ["bash", "-euo", "pipefail", "-c"]

fmt:
    cargo fmt --all -- --check

native:
    python3 scripts/prepare_sqlite.py

check: native
    cargo check --locked --workspace --all-targets --all-features

clippy: native
    cargo clippy --locked --workspace --all-targets --all-features -- -D warnings

test: native
    cargo nextest run --locked --workspace --all-features
    cargo test --locked --doc --workspace --all-features
    sh lab/dev/test_prune_deploys.sh
    sh lab/dev/test_install_guest.sh
    just product-profile

# W287: the product host profile is a second build of the executor crate. Its
# own target directory keeps the default (lab) build cache intact.
product-profile: native
    RUSTFLAGS='--cfg rustiron_profile="product"' cargo clippy --locked -p rustiron-executor --target-dir target/product-profile --lib --bins --test product_profile -- -D warnings
    RUSTFLAGS='--cfg rustiron_profile="product"' cargo test --locked -p rustiron-executor --target-dir target/product-profile --test product_profile

quick: fmt check clippy test

deps:
    cargo deny --locked check
    cargo shear --deny-warnings

features: native
    python3 scripts/check_features.py

doctor: fmt clippy test deps features
    @echo "Rust-Toolchain: PASS"

features-deep: native
    python3 scripts/check_features.py --deep

deep: features-deep

coverage:
    mkdir -p target/rust-toolchain
    cargo llvm-cov --lcov --output-path target/rust-toolchain/lcov.info nextest --workspace --all-features

toolchain-help:
    @echo "Rust-Toolchain: rust-tc check | quick | doctor | deep | coverage | fuzz-check | fuzz"

# Maintained, real parser targets; deeper campaigns remain opt-in.
fuzz:
    python3 scripts/check_fuzz.py

fuzz-check:
    python3 scripts/check_fuzz.py --check-only
