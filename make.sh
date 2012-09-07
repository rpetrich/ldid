#!/bin/bash

set -e

flags=()

sdk=/Developer/SDKs/MacOSX10.4u.sdk
if [[ -e $sdk ]]; then
    flags+=(-mmacosx-version-min=10.4 -isysroot "$sdk")
fi

g++ -arch ppc -arch i386 -arch x86_64 "${flags[@]}" -o ldid ldid.cpp -I. -x c lookup2.c sha1.c
