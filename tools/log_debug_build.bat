setlocal
@echo off

if exist "log_debug_build.bat" (
  cd ..
)

CALL cmake -S . -B build -G "Visual Studio 16 2019" -DENABLE_SHARED=on -DENABLE_TESTS=on -DENABLE_ELEMENTS=on -DCMAKE_BUILD_TYPE=Debug -DCFDCORE_LOG_CONSOLE=off -DCFDCORE_LOG_LEVEL=trace -DCFDCORE_DEBUG=on -DSTD_CPP_VERSION=20

CALL cmake --build build --config Debug --parallel 4
