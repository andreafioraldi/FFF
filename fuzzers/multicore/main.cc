#include "Queue/GlobalQueue.hpp"
#include "Queue/FeedbackQueue.hpp"
#include "Mutator/ScheduledMutator.hpp"
#include "Input/RawInput.hpp"
#include "Stage/FuzzingStage.hpp"
#include "FuzzOne/FuzzOne.hpp"
#include "Executor/InMemoryExternalExecutor.hpp"
#include "Feedback/MaximizeMapFeedback.hpp"
#include "Observation/MapObservationChannel.hpp"
#include "OS/IPC.hpp"
#include "Engine.hpp"
#include "Random.hpp"

#include "Instrumentation/Config.h"

#include "third_party/argparse.h"
#include <filesystem>
#include <iostream>
#include <thread>

using namespace FFF;
using namespace argparse;

extern "C" {

extern uint8_t* __fff_edges_map;
extern uint8_t* __fff_cmp_map;

int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size);
__attribute__((weak)) int LLVMFuzzerInitialize(int *argc, char ***argv);

}

void loop_engine(Engine* e) {

  e->loop();

}

int main(int argc, char** argv) {

  ArgumentParser cmd("libFuzzer-FFF", "libFuzzer-FFF");
  cmd.add_argument("-i", "--input", "Input corpus directory", false);
  cmd.add_argument("-n", "--threads", "Number of threads", true);
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

  __fff_edges_map = (uint8_t*)createAnonSharedMem(MAP_SIZE);
  __fff_cmp_map = (uint8_t*)createAnonSharedMem(MAP_SIZE);

  Random::init();
  
  GlobalQueue main_queue;
  main_queue.setDirectory(cmd.get<std::string>("output") + "/GlobalQueue");
  std::filesystem::create_directories(main_queue.getDirectory());
  
  InMemoryForkExecutor exe(&LLVMFuzzerTestOneInput);
  Engine engine(&exe, &main_queue);
  
  exe.createObservationChannel<HitcountsMapObservationChannel>(__fff_edges_map, MAP_SIZE);
  Feedback* edges_feedback = engine.createFeedback< MaximizeMapFeedback<uint8_t, HitcountsMapObservationChannel> >(MAP_SIZE);
  
  exe.createObservationChannel<CmpMapObservationChannel>(__fff_cmp_map, MAP_SIZE);
  Feedback* cmp_feedback = engine.createFeedback< MaximizeMapFeedback<uint8_t, CmpMapObservationChannel> >(MAP_SIZE);
  
  FeedbackQueue cmp_queue(cmp_feedback, "CmpQueue");
  cmp_queue.setDirectory(cmd.get<std::string>("output") + "/CmpQueue");
  std::filesystem::create_directories(cmp_queue.getDirectory());
  
  cmp_feedback->setFeedbackQueue(&cmp_queue);
  main_queue.addFeedbackQueue(&cmp_queue);
  
  engine.createFuzzOne<StagedFuzzOne>()
        ->createStage<FuzzingStage>()
        ->createMutator<HavocMutator>();
  
  std::vector<Engine*> engines;
  
  for (size_t i = 1; i < cmd.get<int>("n"); ++i) {
    InMemoryForkExecutor* exec = new InMemoryForkExecutor(&LLVMFuzzerTestOneInput);
    Engine* e = new Engine(exec, &main_queue);
    
    exec->createObservationChannel<HitcountsMapObservationChannel>(__fff_edges_map, MAP_SIZE);
    e->addFeedback(edges_feedback);
    exec->createObservationChannel<CmpMapObservationChannel>(__fff_cmp_map, MAP_SIZE);
    e->addFeedback(cmp_feedback);
    
    e->createFuzzOne<StagedFuzzOne>()
        ->createStage<FuzzingStage>()
        ->createMutator<HavocMutator>();
    engines.push_back(e);
  }
  
  if (LLVMFuzzerInitialize) LLVMFuzzerInitialize(&argc, &argv);
  
  for (auto e : engines) {
  
    if (!cmd.exists("i"))
      e->loadZeroTestcase(4);
    else
      e->loadTestcasesFromDir<RawInput>(cmd.get<std::string>("input"));
  
    std::thread * t = new std::thread(loop_engine, e);
  }
  
  if (!cmd.exists("i"))
    engine.loadZeroTestcase(4);
  else
    engine.loadTestcasesFromDir<RawInput>(cmd.get<std::string>("input"));
  
  engine.loop();

}
