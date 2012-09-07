#!/bin/bash

set -e -x

cycc -i2.0 -m10.5 -oldid.arm -- ldid.cpp sha1.c -x c lookup2.c -I .

rm -rf _
mkdir -p _/usr/bin
cp -a ldid.arm _/usr/bin
mkdir -p _/DEBIAN
./control.sh _ >_/DEBIAN/control
mkdir -p debs
ln -sf debs/ldid_$(./version.sh)_iphoneos-arm.deb ldid.deb
dpkg-deb -b _ ldid.deb
readlink ldid.deb
