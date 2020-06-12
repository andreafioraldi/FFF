#include "Input/RawInput.hpp"

using namespace FFF;

std::shared_ptr<VirtualInput> RawInput::copy() {
  return std::shared_ptr<VirtualInput>(new RawInput(bytes));
}
