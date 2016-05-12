# `script` phase: you usually build, test and generate docs in this phase

set -ex

# modify this function as you see fit
# PROTIP Always pass `--target $TARGET` to cargo commands, this makes cargo output build artifacts
# to target/$TARGET/{debug,release} which can reduce the number of needed conditionals in the
# `before_deploy`/packaging phase
run_test_suite() {
  ls -l /usr/local/musl/bin
  export OPENSSL_INCLUDE_DIR=/usr/local/musl/include/
  export OPENSSL_LIB_DIR=/usr/local/musl/lib/
  export OPENSSL_STATIC=1
  export PATH=$PATH:/usr/local/musl/bin
  which musl-gcc

  cargo build --release --target $TARGET
  cargo test --release --target $TARGET

  # sanity check the file type
  file target/$TARGET/release/spyglass
}

main() {
  run_test_suite
}

main
