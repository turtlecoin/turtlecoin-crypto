#!/bin/bash
BASE_DIR=`pwd`
BUILD_DIR="build.js"

if [[ -z "${EMSDK}" ]]; then
  cd external/emsdk || exit 1
  ./emsdk install latest
  ./emsdk activate latest
  source ./emsdk_env.sh
  rm -rf emsdk_set_env.bat
  cd $BASE_DIR || exit 1
fi

emcmake --help

if [ "$?" -eq 127 ]; then
  source ./external/emsdk/emsdk_env.sh
fi

mkdir -p $BUILD_DIR && cd $BUILD_DIR || exit 1

if [ "$1" = "clean" ] || [ "$2" = "clean" ] ; then
  rm -rf *
fi

if [ "$1" = "debug" ] || [ "$2" = "debug" ]; then
  emcmake cmake .. -DBUILD_JS=1 -DBUILD_JS_DEBUG=1
else
  emcmake cmake .. -DBUILD_JS=1
fi

emcmake make

cd $BASE_DIR || exit 1
