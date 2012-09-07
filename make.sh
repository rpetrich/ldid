#!/bin/bash

set -e

flags=()

sdk=/Developer/SDKs/MacOSX10.4u.sdk
if [[ -e $sdk ]]; then
    flags+=(-mmacosx-version-min=10.4 -isysroot "$sdk")
fi

for arch in i386 x86_64 ppc armv6; do
    if g++ -arch "${arch}" --version &>/dev/null; then
        flags+=(-arch "${arch}")
    fi
done

set -x
g++ "${flags[@]}" -o ldid ldid.cpp -I. -x c lookup2.c sha1.c
