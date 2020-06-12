#include "Input/RawInput.hpp"

#include <fstream>

using namespace FFF;

std::shared_ptr<VirtualInput> RawInput::copy() {
  return std::shared_ptr<VirtualInput>(new RawInput(bytes));
}

void RawInput::loadFromFile(std::string path) {
  std::ifstream ifile(path.c_str(), std::ios::binary);
  bytes = Bytes((std::istreambuf_iterator<char>(ifile)), (std::istreambuf_iterator<char>()));
  ifile.close();
  is_empty = false;
}

void RawInput::saveToFile(std::string path) {
  std::ofstream ofile(path.c_str(), std::ios::binary);
  ofile.write(bytes.data(), bytes.size());
  ofile.close();
}
