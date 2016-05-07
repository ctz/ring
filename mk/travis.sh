#!/usr/bin/env bash
#
# Copyright 2015 Brian Smith.
#
# Permission to use, copy, modify, and/or distribute this software for any
# purpose with or without fee is hereby granted, provided that the above
# copyright notice and this permission notice appear in all copies.
#
# THE SOFTWARE IS PROVIDED "AS IS" AND AND THE AUTHORS DISCLAIM ALL WARRANTIES
# WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
# MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHORS BE LIABLE FOR ANY
# SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
# WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN ACTION
# OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF OR IN
# CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.

set -eux -o pipefail
IFS=$'\n\t'

printenv

case $TARGET_X in
aarch64-unknown-linux-gnu)
  DL_TARGET=aarch64-linux-gnu
  DL_DIGEST=b9137008744d9009877f662dbac7481d673cdcb1798e727e325a37c98a0f63da
  ;;
arm-unknown-linux-gnueabi)
  DL_TARGET=arm-linux-gnueabi
  DL_DIGEST=1c11a944d3e515405e01effc129f3bbf24effb300effa10bf486c9119378ccd7
  ;;
*)
  ;;
esac

if [[ -n ${DL_TARGET-} ]]; then
  # We need a newer QEMU than Travis has.
  sudo add-apt-repository ppa:pietro-monteiro/qemu-backport -y
  sudo apt-get update -qq
  sudo apt-get install binfmt-support qemu-user-binfmt -y

  DL_ROOT=https://releases.linaro.org/components/toolchain/binaries/
  DL_RELEASE=5.1-2015.08
  DL_BASENAME=gcc-linaro-$DL_RELEASE-x86_64_$DL_TARGET
  wget $DL_ROOT/$DL_RELEASE/$DL_TARGET/$DL_BASENAME.tar.xz
  echo "$DL_DIGEST  $DL_BASENAME.tar.xz" | sha256sum -c
  tar xf $DL_BASENAME.tar.xz
  export PATH=$PWD/$DL_BASENAME/bin:$PATH
fi

if [[ ! "$TARGET_X" =~ "x86_64-" ]]; then
  ./mk/travis-install-rust-std.sh

  # By default cargo/rustc seems to use cc for linking, We installed the
  # multilib support that corresponds to $CC_X and $CXX_X but unless cc happens
  # to match #CC_X, that's not the right version. The symptom is a linker error
  # where it fails to find -lgcc_s.
  mkdir .cargo
  echo "[target.$TARGET_X]" > .cargo/config
  echo "linker= \"$CC_X\"" >> .cargo/config
  cat .cargo/config
fi

$CC_X --version
$CXX_X --version
make --version

cargo version
rustc --version

if [[ "$MODE_X" == "RELWITHDEBINFO" ]]; then mode=--release; fi

case $TARGET_X in
aarch64-unknown-linux-gnu)
  export QEMU_LD_PREFIX=$DL_BASENAME/aarch64-linux-gnu/libc
  ;;
arm-unknown-linux-gnueabi)
  export QEMU_LD_PREFIX=$DL_BASENAME/arm-linux-gnueabi/libc
    ;;
*)
  ;;
esac

CC=$CC_X CXX=$CXX_X cargo test -j2 ${mode-} --verbose --target=$TARGET_X

if [[ "$KCOV" == "1" ]]; then
  # kcov reports coverage as a percentage of code *linked into the executable*
  # (more accurately, code that has debug info linked into the executable), not
  # as a percentage of source code. Thus, any code that gets discarded by the
  # linker due to lack of usage isn't counted at all. Thus, we have to re-link
  # with "-C link-dead-code" to get accurate code coverage reports.
  # Alternatively, we could link pass "-C link-dead-code" in the "cargo test"
  # step above, but then "cargo test" we wouldn't be testing the configuration
  # we expect people to use in production.
  CC=$CC_X CXX=$CXX_X cargo clean
  CC=$CC_X CXX=$CXX_X RUSTFLAGS="-C link-dead-code" \
    cargo test --no-run -j2  ${mode-} --verbose --target=$TARGET_X
  mk/travis-install-kcov.sh
  ${HOME}/kcov-${TARGET_X}/bin/kcov --verify \
                                    --coveralls-id=$TRAVIS_JOB_ID \
                                    --exclude-path=/usr/include \
                                    --include-pattern="ring/crypto,ring/src" \
                                    target/kcov \
                                    target/$TARGET_X/debug/ring-*
fi

# Verify that `cargo build`, independent from `cargo test`, works; i.e. verify
# that non-test builds aren't trying to use test-only features. For platforms
# for which we don't run tests, this is the only place we even verify that the
# code builds.
CC=$CC_X CXX=$CXX_X cargo build -j2 ${mode-} --verbose --target=$TARGET_X

echo end of mk/travis.sh
