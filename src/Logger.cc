#include "Logger.hpp"

#include <iomanip>
#include <thread>
#include <ctime>

using namespace FFF;

namespace FFF {

std::ostream* Logger::outstream = &std::cerr;
LogHeaderFunctionType Logger::log_header = defaultLogHeader;

void defaultLogHeader(std::stringstream& ss) {
  auto t = time(NULL);
  auto tm = *std::localtime(&t);
  ss << "[ " << std::put_time(&tm, "%d-%m-%Y %H:%M:%S") << " ] ";
}

}
