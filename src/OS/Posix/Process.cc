#include "OS/Process.hpp"

#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>
#include <signal.h>

#include <stdexcept>

using namespace FFF;

namespace FFF {

static Process* current_process;

Process* Process::current() {
  if (current_process)
    return current_process;
  Process* p = new Process();
  p->handle = (void*)(intptr_t)getpid();
  current_process = p;
  return p;
}

ForkResult Process::fork() {
  pid_t child = ::fork();
  if (child == 0)
    return ForkResult::CHILD;
  else if (child < 0)
    return ForkResult::FAILED;
  handle = (void*)(intptr_t)child;
  return ForkResult::PARENT;
}

void Process::suspend() {
  kill((pid_t)(intptr_t)handle, SIGSTOP);
}

void Process::resume() {
  kill((pid_t)(intptr_t)handle, SIGCONT);
}

ExitType Process::wait(bool untraced) {
  int status;
  if (waitpid((pid_t)(intptr_t)handle, &status, untraced ? WUNTRACED : 0) < 0)
    throw std::runtime_error("Process::wait: waitpid() failed");
  if (WIFSTOPPED(status))
    return ExitType::STOP;
  if (WIFSIGNALED(status)) {
    int signum = WTERMSIG(status);
    if (signum == SIGKILL)
      return ExitType::TIMEOUT;
    else return ExitType::CRASH; // TODO distinguish crashes
  }
  return ExitType::NORMAL;
}

}
