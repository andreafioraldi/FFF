#pragma once

#include "Bytes.hpp"

namespace FFF {

enum struct ExitType {
  NORMAL,
  STOP,
  CRASH,
  SEGV,
  BUS,
  ABRT,
  ILL,
  FPE,
  TIMEOUT,
  OOM,
};

void dumpCrashToFile(ExitType type, const Bytes& bytes);

typedef void (*CrashHandlerFunction)(ExitType type, void* data);

void installCrashHandlers(CrashHandlerFunction callback);

// Handlers

void dumpInMemoryCrashToFileHandler(ExitType type, void* data);
void fillSharedCrashReport(ExitType type, void* data);

};
