#!/bin/bash

set -e -x

if [ -z "$(uname -a | grep -i cygwin)" ]; then
  sdk=/Developer/SDKs/MacOSX10.5.sdk
  flags=(-arch i386 -arch x86_64)
  [ -e $sdk ] && flags+=(-mmacosx-version-min=10.4 -isysroot "$sdk")
fi

g++ "${flags[@]}" -o ldid ldid.cpp -I. -x c lookup2.c sha1.c
