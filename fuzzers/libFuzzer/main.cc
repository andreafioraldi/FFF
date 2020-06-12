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

#include "Config.h"

#include "third_party/argparse.h"
#include <iostream>

using namespace FFF;
using namespace argparse;

extern "C" {

extern uint8_t __fff_edges_map[MAP_SIZE];
extern uint8_t __fff_cmp_map[MAP_SIZE];

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

  Random::init();  
  installCrashHandlers(&dumpInMemoryCrashToFileHandler);
  
  InMemoryExecutor exe(&LLVMFuzzerTestOneInput);
  GlobalQueue q;
  Engine engine(&exe, &q);
  
  exe.createObservationChannel<HitcountsMapObservationChannel>(__fff_edges_map, MAP_SIZE);
  engine.createFeedback< MaximizeMapFeedback<uint8_t, HitcountsMapObservationChannel> >(MAP_SIZE);
  exe.createObservationChannel<CmpMapObservationChannel>(__fff_cmp_map, MAP_SIZE);
  
  Feedback* f = engine.createFeedback< MaximizeMapFeedback<uint8_t, CmpMapObservationChannel> >(MAP_SIZE);
  FeedbackQueue fq(f, "CmpQueue");
  f->setFeedbackQueue(&fq);
  q.addFeedbackQueue(&fq);
  
  engine.createFuzzOne<StagedFuzzOne>()
        ->createStage<FuzzingStage>()
        ->createMutator<HavocMutator>();
  
  if (LLVMFuzzerInitialize) LLVMFuzzerInitialize(&argc, &argv);
  
  if (!cmd.exists("i"))
    engine.loadZeroTestcase(4);
  else
    engine.loadTestcasesFromDir(cmd.get<std::string>("input"));
  
  engine.loop();

}
