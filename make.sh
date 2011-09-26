#!/bin/bash

set -e -x

flags=()

sdk=/Developer/SDKs/MacOSX10.5.sdk
if [[ -e $sdk ]]; then
    flags+=(-mmacosx-version-min=10.4 -isysroot "$sdk")
fi

g++ -arch i386 -arch x86_64 "${flags[@]}" -o ldid ldid.cpp -I. -x c lookup2.c sha1.c
