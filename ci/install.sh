# `install` phase: install stuff needed for the `script` phase

set -ex

DATE="2016-04-15"

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

install_rust() {
  local td=$(mktempd)

  pushd $td
  
  wget http://static.rust-lang.org/dist/$DATE/rust-nightly-$host.tar.gz
  tar -xf rust-nightly-$host.tar.gz
  sudo rust-nightly-$host/install.sh
  
  popd

  rm -r $td

  rustc -V
  cargo -V
}

install_standard_crates() {
  if [ "$host" != "$TARGET" ]; then
	  local td=$(mktempd)
	  
	  curl -s https://static.rust-lang.org/dist/$DATE/rust-std-nightly-$TARGET.tar.gz | \
		tar --strip-components 1 -C $td -xz

	  $td/install.sh --prefix=$(rustc --print sysroot)

	  rm -r $td
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
  install_rust
  install_standard_crates
  configure_cargo

  # if you need to install extra stuff add it here
}

main
