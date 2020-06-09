#include "Engine.hpp"
#include "Logger.hpp"

#include <filesystem>

using namespace FFF;

void Engine::execute(VirtualInput* input) {
  executor->resetObservers();
  executor->placeInput(input);
  executor->runTarget();
  for (auto obs : executor->getObservers())
    obs->postExec(executor);
  
  bool add_to_queue = false;
  for(auto feedback : feedbacks)
    add_to_queue = add_to_queue || feedback->isInteresting(executor);
  if (add_to_queue)
    queue->add(new QueueEntry(input, true));
}

void Engine::loadTestcasesFromDir(const std::string& path) {
  for (const auto & entry : std::filesystem::directory_iterator(path)) {
    if (!entry.is_regular_file())
      std::cerr << "LOADING: Skipping " << entry << " because is not a regular file\n";
    else {
      std::ifstream input(entry.path().c_str(), std::ios::binary);
      Bytes bytes((std::istreambuf_iterator<char>(input)), (std::istreambuf_iterator<char>()));
      input.close();
      RawInput* raw = new RawInput(bytes);
      std::cerr << "LOADING: Executing " << entry << "\n";
      execute(raw);
    }
  }
}

void Engine::loadZeroTestcase(size_t size) {
  RawInput* zero = new RawInput(Bytes(size, 0));
  execute(zero);
}
