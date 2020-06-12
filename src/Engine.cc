#include "FuzzOne/FuzzOne.hpp"
#include "Input/RawInput.hpp"
#include "Engine.hpp"
#include "Logger.hpp"

#include <filesystem>
#include <fstream>

using namespace FFF;

void Engine::execute(const std::shared_ptr<VirtualInput>& input) {
  executor->resetObservationChannels();
  executor->placeInput(input);
  executor->runTarget();
  for (auto obs : executor->getObservationChannels())
    obs->postExec(executor);
  
  bool add_to_queue = false;
  for(auto feedback : feedbacks)
    add_to_queue = add_to_queue || feedback->isInteresting(executor);
  if (add_to_queue)
    queue->add(new QueueEntry(input->copy(), queue));
}

void Engine::loop() {
  while (true)
    fuzz_one->perform();
}

void Engine::loadTestcasesFromDir(const std::string& path) {
  for (const auto & entry : std::filesystem::directory_iterator(path)) {
    if (!entry.is_regular_file())
      Logger::log("LOADING: Skipping ", entry, " because is not a regular file\n");
    else {
      std::ifstream input(entry.path().c_str(), std::ios::binary);
      Bytes bytes((std::istreambuf_iterator<char>(input)), (std::istreambuf_iterator<char>()));
      input.close();
      auto raw = std::make_shared<RawInput>(bytes);
      Logger::log("LOADING: Executing ", entry, "\n");
      execute(raw);
    }
  }
}

void Engine::loadZeroTestcase(size_t size) {
  auto raw = std::make_shared<RawInput>(Bytes(size, 0));
  execute(raw);
}
