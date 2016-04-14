# `install` phase: install stuff needed for the `script` phase

set -ex

case "$TRAVIS_OS_NAME" in
  linux)
    host=x86_64-unknown-linux-gnu
    ;;
  osx)
    host=x86_64-apple-darwin
    ;;
esac

mktempd() {
  echo $(mktemp -d 2>/dev/null || mktemp -d -t tmp)
}

install_rustup() {
  local td=$(mktempd)

  pushd $td
  curl -O https://static.rust-lang.org/rustup/dist/$host/rustup-setup
  chmod +x rustup-setup
  ./rustup-setup -y
  popd

  rm -r $td

  rustup default $CHANNEL
  rustc -V
  cargo -V
}

install_standard_crates() {
  if [ "$host" != "$TARGET" ]; then
    if [ ! "$CHANNEL" = "stable" ]; then
      rustup target add $TARGET
    else
      local version=$(rustc -V | cut -d' ' -f2)
      local tarball=rust-std-${version}-${TARGET}

      local td=$(mktempd)
      curl -s https://static.rust-lang.org/dist/${tarball}.tar.gz | \
        tar --strip-components 1 -C $td -xz

      $td/install.sh --prefix=$(rustc --print sysroot)

      rm -r $td
    fi
  fi
}

configure_cargo() {
  local prefix=
  case "$TARGET" in
    arm*-gnueabihf)
      prefix=arm-linux-gnueabihf
      ;;
    *)
      return
      ;;
  esac

  # information about the cross compiler
  $prefix-gcc -v

  # tell cargo which linker to use for cross compilation
  mkdir -p .cargo
  cat >>.cargo/config <<EOF
[target.$TARGET]
linker = "$prefix-gcc"
EOF
}

main() {
  install_rustup
  install_standard_crates
  configure_cargo

  # if you need to install extra stuff add it here
}

main
