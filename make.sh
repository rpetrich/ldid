#!/bin/bash
g++ -arch ppc -arch i386 -arch x86_64 -o ldid ldid.cpp -I. -x c lookup2.c sha1.c
