#include "Queue/GlobalQueue.hpp"
#include "Queue/FeedbackQueue.hpp"
#include "Mutator/ScheduledMutator.hpp"
#include "Input/RawInput.hpp"
#include "Stage/FuzzingStage.hpp"
#include "FuzzOne/FuzzOne.hpp"
#include "Executor/InMemoryExecutor.hpp"
#include "Feedback/MaximizeMapFeedback.hpp"
#include "Observation/MapObservationChannel.hpp"
#include "OS/Crash.hpp"
#include "Engine.hpp"
#include "Random.hpp"

#include "Instrumentation/Config.h"

#include "third_party/argparse.h"
#include <filesystem>
#include <iostream>

using namespace FFF;
using namespace argparse;

extern "C" {

extern uint8_t* __fff_edges_map;
extern uint32_t __fff_max_edges_size;

int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size);
__attribute__((weak)) int LLVMFuzzerInitialize(int *argc, char ***argv);

}

int main(int argc, char** argv) {

  ArgumentParser cmd("libFuzzer-FFF", "libFuzzer-FFF");
  cmd.add_argument("-i", "--input", "Input corpus directory", false);
  cmd.add_argument("-o", "--output", "Output corpus directory", true);
  cmd.enable_help();
  auto err = cmd.parse(argc, (const char**)argv);
  if (err) {
    std::cerr << err << std::endl;
    return -1;
  }

  if (cmd.exists("help")) {
    cmd.print_help();
    return 0;
  }
  
  std::cerr << __fff_max_edges_size << "\n";
  
  __fff_edges_map = new uint8_t[__fff_max_edges_size];
  
  Random::init();  
  installCrashHandlers(&dumpInMemoryCrashToFileHandler);
  
  GlobalQueue main_queue;
  main_queue.setDirectory(cmd.get<std::string>("output") + "/GlobalQueue");
  std::filesystem::create_directories(main_queue.getDirectory());
  
  InMemoryExecutor exe(&LLVMFuzzerTestOneInput);
  Engine engine(&exe, &main_queue);
  
  exe.createObservationChannel<HitcountsMapObservationChannel>(__fff_edges_map, __fff_max_edges_size);
  engine.createFeedback< MaximizeMapFeedback<uint8_t, HitcountsMapObservationChannel> >(__fff_max_edges_size);
  
  engine.createFuzzOne<StagedFuzzOne>()
        ->createStage<FuzzingStage>()
        ->createMutator<HavocMutator>();
  
  if (LLVMFuzzerInitialize) LLVMFuzzerInitialize(&argc, &argv);
  
  Monitor::addEngine(&engine);
  
  if (!cmd.exists("i"))
    engine.loadZeroTestcase(4);
  else
    engine.loadTestcasesFromDir<RawInput>(cmd.get<std::string>("input"));
  
  engine.loop();

}
