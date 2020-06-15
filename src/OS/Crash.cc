#include "Executor/InMemoryExecutor.hpp"
#include "Executor/InMemoryExternalExecutor.hpp"
#include "OS/Crash.hpp"
#include "OS/IPC.hpp"
#include "Bytes.hpp"
#include "Logger.hpp"

#include "third_party/sha1.hpp"
#include <cstdlib>

using namespace FFF;

namespace FFF {

void dumpCrashToFile(ExitType type, const Bytes& bytes) {
  SHA1 checksum;
  std::istringstream is(bytes);
  checksum.update(is);
  std::string filename = "crash-" + checksum.final();
  Logger::log("Crashing input found, saving at ", filename, "\n");
  std::ofstream outfile(filename, std::ofstream::binary);
  outfile.write(bytes.data(), bytes.size());
  outfile.close();
}


void dumpInMemoryCrashToFileHandler(ExitType type, void* data) {
  if (InMemoryExecutor::current_executor == nullptr) {
    Logger::log("FATAL! current_executor is NULL, there is a bug in the fuzzer\n");
    return;
  }
  Bytes bytes = InMemoryExecutor::current_executor->getCurrentInput()->serialize();
  dumpCrashToFile(type, bytes);
}

void fillSharedCrashReport(ExitType type, void* data) {
  if (InMemoryExternalExecutor::current_executor == nullptr) {
    Logger::log("FATAL! current_executor is NULL, there is a bug in the fuzzer\n");
    return;
  }
  InMemoryExternalExecutor::current_executor->writeSharedExitType(type);
  exit(0);
}

}
