#include "OS/Crash.hpp"
#include <assert.h>
#include <signal.h>
#include <stdlib.h>

using namespace FFF;

namespace FFF {

static CrashHandlerFunction crash_callback;

static void posixCrashHandler(int signum, siginfo_t * siginfo, void * ucontext) {
  CrashType type = CrashType::GENERIC;
  if (signum == SIGSEGV)
    type = CrashType::SEGV;
  else if (signum == SIGBUS)
    type = CrashType::BUS;
  else if (signum == SIGABRT)
    type = CrashType::ABRT;
  else if (signum == SIGILL)
    type = CrashType::ILL;
  else if (signum == SIGFPE)
    type = CrashType::FPE;
  if (crash_callback)
    crash_callback(type, nullptr);
  exit(1);
}

static void installSigHandler(int signum, void (*callback)(int, siginfo_t *, void *)) {
  struct sigaction sigact = {};
  sigact.sa_flags = SA_SIGINFO;
  sigact.sa_sigaction = callback;
  assert (sigaction(signum, &sigact, 0) == 0);
}

void installCrashHandlers(CrashHandlerFunction callback) {
  crash_callback = callback;
  installSigHandler(SIGSEGV, posixCrashHandler);
  installSigHandler(SIGBUS, posixCrashHandler);
  installSigHandler(SIGABRT, posixCrashHandler);
  installSigHandler(SIGILL, posixCrashHandler);
  installSigHandler(SIGFPE, posixCrashHandler);
}

}
