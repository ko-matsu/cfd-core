// Copyright 2019 CryptoGarage
/**
 * @file cfdcore_exception.cpp
 *
 * @brief 例外関連クラス定義
 */

#include <iterator>
#include <random>
#include <set>
#include <sstream>
#include <string>
#include <vector>

#if !defined(CFD_USE_BACKTRACE)
// do nothing
#elif defined(_WIN32)
#include <imagehlp.h>
#include <windows.h>
#pragma comment(lib, "imagehlp.lib")

#elif defined(__GNUC__)
// backtrace, backtrace_symbols
#include <execinfo.h>
#elif defined(TARGET_OS_MAC)

#else
#define __USE_GNU
#include <dlfcn.h>
#endif

#include "cfdcore/cfdcore_exception.h"
#include "cfdcore/cfdcore_logger.h"

namespace cfd {
namespace core {

using logger::info;
using logger::trace;
using logger::warn;

// https://rti7743.hatenadiary.org/entry/20110109/1294605380
// https://puarts.com/?pid=1109
// https://qiita.com/koara-local/items/012b917111a96f76d27c
#if !defined(CFD_USE_BACKTRACE)
/**
 * @brief dump stacktrace.
 * @param[in] error_code    error code
 * @param[in] message       error message
 */
void DumpStack(int error_code, const std::string& message) {
  trace(CFD_LOG_SOURCE, "exception: ecode[{}] msg[{}]", error_code, message);
}
#elif defined(_WIN32)
/**
 * @brief dump stacktrace.
 * @param[in] error_code    error code
 * @param[in] message       error message
 */
void DumpStack(int error_code, const std::string& message) {
  static constexpr int kSymbolInfoSize =
      sizeof(SYMBOL_INFO) + 256 * sizeof(char);
  static constexpr int kStackTraceNum = 100;
  static constexpr int kStackNameSize = 255;
  unsigned int count;
  unsigned short frames;
  void* stack[kStackTraceNum];
  SYMBOL_INFO* symbol;
  HANDLE process;
  warn(CFD_LOG_SOURCE, "exception: ecode[{}] msg[{}]", error_code, message);
  process = GetCurrentProcess();
  SymInitialize(process, NULL, TRUE);
  frames = CaptureStackBackTrace(0, kStackTraceNum, stack, NULL);

  symbol = (SYMBOL_INFO*)malloc(kSymbolInfoSize);
  if (symbol != nullptr) {
    symbol->MaxNameLen = kStackNameSize;
    symbol->SizeOfStruct = sizeof(SYMBOL_INFO);
    for (count = 0; count < frames; ++count) {
      SymFromAddr(process, (DWORD64)(stack[count]), 0, symbol);
      // printf("[backtrace:win] [%02d]: %s\n", count, symbol->Name);
      warn(CFD_LOG_SOURCE, "[backtrace] [{}]: {}", count, symbol->Name);
    }
    free(symbol);
  }
}
#elif defined(__GNUC__)
/**
 * @brief dump stacktrace.
 * @param[in] error_code    error code
 * @param[in] message       error message
 */
void DumpStack(int error_code, const std::string& message) {
#ifdef CFD_USE_BACKTRACE_COUNT
  static const int kTraceSize = CFD_USE_BACKTRACE_COUNT;
#else
  static constexpr const size_t kTraceSize = 20;
#endif
  warn(CFD_LOG_SOURCE, "exception: ecode[{}] msg[{}]", error_code, message);
  void* trace[kTraceSize];
  auto size = backtrace(trace, kTraceSize);
  auto symbols = backtrace_symbols(trace, size);
  if (symbols) {
    std::vector<std::string> stack_list(symbols, symbols + size);
    free(symbols);

    int count = stack_list.size();
    for (auto text : stack_list) {
      count--;
      // fprintf(stderr, "[backtrace] [%02d]: %s\n", count, text.c_str());
      warn(CFD_LOG_SOURCE, "[backtrace] [{}]: {}", count, text);
    }
  }
}
#elif defined(TARGET_OS_MAC)
/**
 * @brief dump stacktrace.
 * @param[in] error_code    error code
 * @param[in] message       error message
 */
void DumpStack(int error_code, const std::string& message) {
  // do nothing
  warn(CFD_LOG_SOURCE, "exception: ecode[{}] msg[{}]", error_code, message);
  // fprintf(stderr, "exception: ecode[%d] msg[%s]\n", error_code, message.c_str());
}
#else
/**
 * @brief dump stacktrace.
 * @param[in] error_code    error code
 * @param[in] message       error message
 */
void DumpStack(int error_code, const std::string& message) {
#ifdef CFD_USE_BACKTRACE_COUNT
  static const int kBacktraceCount = CFD_USE_BACKTRACE_COUNT;
#else
  static const int kBacktraceCount = 3;
#endif
  warn(CFD_LOG_SOURCE, "exception: ecode[{}] msg[{}]", error_code, message);
  Dl_info info;
  for (int index = 0; index < kBacktraceCount; ++index) {
    dladdr(__builtin_return_address(index), &info);
    // fprintf(stderr, "[backtrace] %s (%s)\n", info.dli_sname, info.dli_fname);
    warn(
        CFD_LOG_SOURCE, "[backtrace] {} ({})", info.dli_sname, info.dli_fname);
    // __builtin_return_address(index)
    // info.dli_fbase
    // info.dli_saddr
  }
}
#endif

}  // namespace core
}  // namespace cfd
