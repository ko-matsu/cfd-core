#!/bin/sh
cd `git rev-parse --show-toplevel`

# use old buildsystem
cmake -S . -B build -G "Xcode" -T buildsystem=1 -DENABLE_SHARED=off -DENABLE_TESTS=on -DENABLE_ELEMENTS=on -DCMAKE_BUILD_TYPE=Release -DTARGET_RPATH=./build/Release

cmake --build build --config Release --parallel 4
