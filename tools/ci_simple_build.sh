#!/bin/sh
cmake -S . -B build_ci -G "Unix Makefiles" -DENABLE_SHARED=off -DENABLE_TESTS=on -DENABLE_ELEMENTS=on -DCMAKE_BUILD_TYPE=Debug -DTARGET_RPATH=./build_ci/Debug

cmake --build build_ci --config Debug --parallel 4

valgrind -v --tool=memcheck --leak-check=full --valgrind-stacksize=10485760 --log-file=./valgrind.log --time-stamp=yes ./build_ci/Debug/cfdcore_test
