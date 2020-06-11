#pragma once

namespace FFF {

enum struct CrashType {
  GENERIC,
  SEGV,
  BUS,
  ABRT,
  ILL,
  FPE,
  TIMEOUT,
  OOM,
};

typedef void (*CrashHandlerFunction)(CrashType type, void* data);

void installCrashHandlers(CrashHandlerFunction callback);

// Handlers

void dumpInMemoryCrashToFileHandler(CrashType type, void* data);

};
