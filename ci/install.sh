# `install` phase: install stuff needed for the `script` phase

set -ex

case "$TRAVIS_OS_NAME" in
  linux)
    host=x86_64-unknown-linux-musl
    ;;
  osx)
    host=x86_64-apple-darwin
    ;;
esac

mktempd() {
  echo $(mktemp -d 2>/dev/null || mktemp -d -t tmp)
}

install_openssl() {
	export VERS=1.0.2g
	curl -O https://www.openssl.org/source/openssl-$VERS.tar.gz
	tar xvzf openssl-$VERS.tar.gz
	cd openssl-$VERS
	env CC=musl-gcc ./config --prefix=/usr/local/musl
	env C_INCLUDE_PATH=/usr/local/musl/include/ make depend
	make
	sudo make install
	export OPENSSL_INCLUDE_DIR=/usr/local/musl/include/
	export OPENSSL_LIB_DIR=/usr/local/musl/lib/
	export OPENSSL_STATIC=1
	cd ..
}

install_musl() {
	git clone git://git.musl-libc.org/musl
	cd musl
	./configure
	make
	sudo make install
	cd ..
	export PATH=$PATH:/usr/local/musl/bin
}

install_rustup() {
  local td=$(mktempd)

  pushd $td
  curl -O https://static.rust-lang.org/rustup.sh
  chmod +x rustup.sh
  ./rustup.sh -y
  popd

  rm -r $td

  export PATH=$PATH:".cargo/bin/"
  rustup default nightly-2016-04-14
  rustup target add x86_64-unknown-linux-musl

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
  install_musl
  install_openssl
  install_rustup
  install_standard_crates
  configure_cargo

  # if you need to install extra stuff add it here
}

main
