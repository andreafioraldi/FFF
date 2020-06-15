#include "Input/RawInput.hpp"

#include <fstream>

using namespace FFF;

VirtualInput* RawInput::copy() {
  return new RawInput(bytes);
}

VirtualInput* RawInput::empty() {
 return new RawInput();
}

void RawInput::loadFromFile(std::string path) {
  std::ifstream ifile(path.c_str(), std::ios::binary);
  bytes = Bytes((std::istreambuf_iterator<char>(ifile)), (std::istreambuf_iterator<char>()));
  ifile.close();
}

void RawInput::saveToFile(std::string path) {
  std::ofstream ofile(path.c_str(), std::ios::binary);
  ofile.write(bytes.data(), bytes.size());
  ofile.close();
}
