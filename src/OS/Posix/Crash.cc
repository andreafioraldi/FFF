#include "OS/Crash.hpp"
#include <assert.h>
#include <signal.h>
#include <stdlib.h>

using namespace FFF;

namespace FFF {

CrashHandlerFunction crash_callback;
void (*saved_sigactions[32])(int, siginfo_t *, void *);
void (*saved_sighandlers[32])(int);

static void posixCrashHandler(int signum, siginfo_t * siginfo, void * ucontext) {
  ExitType type = ExitType::CRASH;
  if (signum == SIGSEGV)
    type = ExitType::SEGV;
  else if (signum == SIGBUS)
    type = ExitType::BUS;
  else if (signum == SIGABRT)
    type = ExitType::ABRT;
  else if (signum == SIGILL)
    type = ExitType::ILL;
  else if (signum == SIGFPE)
    type = ExitType::FPE;
  if (crash_callback)
    crash_callback(type, nullptr);
  if (saved_sigactions[signum])
    saved_sigactions[signum](signum, siginfo, ucontext);
  else if (saved_sighandlers[signum])
    saved_sighandlers[signum](signum);
}

static void installSigHandler(int signum, void (*callback)(int, siginfo_t *, void *)) {
  struct sigaction sigact = {};
  struct sigaction old_sigact = {};
  sigact.sa_flags = SA_SIGINFO;
  sigact.sa_sigaction = callback;
  assert (sigaction(signum, &sigact, &old_sigact) == 0);
  if (old_sigact.sa_flags & SA_SIGINFO)
    saved_sigactions[signum] = old_sigact.sa_sigaction;
  else
    saved_sighandlers[signum] = old_sigact.sa_handler;
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
