#!/bin/bash

# Need to uninstall oclint to get newer gcc installed https://github.com/travis-ci/travis-ci/issues/8826
if [[ "${LABEL:0:3}" == "osx" ]]; then brew cask uninstall --force oclint || true ; fi

# Need a newer version of llvm to link against to get std::filesystem / std::experimental::filesystem
if [[ "${LABEL:0:3}" == "osx" ]]; then brew install llvm || brew upgrade llvm ; fi

# Neeed to install ccache
if [[ "${LABEL:0:3}" == "osx" ]]; then brew install ccache ; fi
if [[ "${LABEL:0:3}" == "osx" ]]; then export PATH="/usr/local/opt/ccache/libexec:$PATH" ; fi

if [[ "$LABEL" == "aarch64" ]]; then export BASEDIR=`pwd` ; fi
if [[ "$LABEL" == "aarch64" ]]; then cd $HOME ; fi
if [[ "$LABEL" == "aarch64" ]]; then wget https://armkeil.blob.core.windows.net/developer/Files/downloads/gnu-a/8.2-2018.08/gcc-arm-8.2-2018.08-x86_64-aarch64-linux-gnu.tar.xz ; fi
if [[ "$LABEL" == "aarch64" ]]; then mkdir toolchain && cd toolchain ; fi
if [[ "$LABEL" == "aarch64" ]]; then tar xfv ../gcc-arm-8.2-2018.08-x86_64-aarch64-linux-gnu.tar.xz >/dev/null ; fi
if [[ "$LABEL" == "aarch64" ]]; then cd gcc-arm-8.2-2018.08-x86_64-aarch64-linux-gnu ; fi
if [[ "$LABEL" == "aarch64" ]]; then export CUSTOM_TOOLCHAIN="-DCMAKE_TOOLCHAIN_FILE=../scripts/cross-aarch64.cmake" ; fi
if [[ "$LABEL" == "aarch64" ]]; then cd $BASEDIR ; fi

mkdir build && cd build
cmake .. ${CUSTOM_TOOLCHAIN}
make -j2
if [[ "$LABEL" != "aarch64" ]]; then ./cryptotest ; fi
cd $BASEDIR
