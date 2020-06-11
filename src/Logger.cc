#include "Logger.hpp"

using namespace FFF;

std::ostream* Logger::outstream = &std::cerr;
std::string Logger::header = "[FFF] ";
