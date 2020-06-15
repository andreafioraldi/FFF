#include "Monitor.hpp"
#include "Engine.hpp"

#include <sstream>

using namespace FFF;

namespace FFF {

Monitor* Monitor::instance = nullptr;
std::vector<Engine*> Monitor::engines;

void Monitor::handleEvent(Object* sender, const std::string& info) {
  //std::stringstream ss;
  uint64_t cur_time = std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::system_clock::now().time_since_epoch()).count();
  uint64_t total_exec_sec = 0;
  uint64_t total_execs = 0;
  for (auto e : engines) {
    uint64_t diff = cur_time - e->getStartTime();
    uint64_t exec_sec = diff ? e->getExecs() * 1000 / diff : 0;
    total_exec_sec += exec_sec;
    total_execs += e->getExecs();
    //ss << e->toString() << " < execs = " << e->getExecs() << " exec/sec = " << exec_sec << " > ";
  }
  //Logger::logLine(sender->toString(), " ", info, ": Total execs = ", total_execs, " Total exec/sec = ", total_exec_sec, ", ", ss.str());
  Logger::logLine(sender->toString(), " ", info, ": Total execs = ", total_execs, " Total exec/sec = ", total_exec_sec);
}

}
