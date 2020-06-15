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

#include <pthread.h>

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

  __fff_edges_map = (uint8_t*)createAnonSharedMem(__fff_max_edges_size);

  Random::init();
  
  GlobalQueue main_queue;
  main_queue.setDirectory(cmd.get<std::string>("output") + "/GlobalQueue");
  std::filesystem::create_directories(main_queue.getDirectory());
  
  InMemoryForkExecutor exe(&LLVMFuzzerTestOneInput);
  Engine engine(&exe, &main_queue);
  
  exe.createObservationChannel<HitcountsMapObservationChannel>(__fff_edges_map, __fff_max_edges_size);
  Feedback* edges_feedback = engine.createFeedback< AtomicMaximizeMapFeedback<uint8_t, HitcountsMapObservationChannel> >(__fff_max_edges_size);
  
  engine.createFuzzOne<StagedFuzzOne>()
        ->createStage<FuzzingStage>()
        ->createMutator<HavocMutator>();
  
  std::vector<Engine*> engines;
  
  Monitor::addEngine(&engine);
  
  for (size_t i = 1; i < cmd.get<int>("n"); ++i) {
    InMemoryForkExecutor* exec = new InMemoryForkExecutor(&LLVMFuzzerTestOneInput);
    Engine* e = new Engine(exec, &main_queue, i);
    
    exec->createObservationChannel<HitcountsMapObservationChannel>(__fff_edges_map, __fff_max_edges_size);
    e->addFeedback(edges_feedback);

    e->createFuzzOne<StagedFuzzOne>()
        ->createStage<FuzzingStage>()
        ->createMutator<HavocMutator>();
    engines.push_back(e);
    
    Monitor::addEngine(e);
  }
  
  if (LLVMFuzzerInitialize) LLVMFuzzerInitialize(&argc, &argv);

  cpu_set_t cpuset;
  CPU_ZERO(&cpuset);
  CPU_SET(0, &cpuset);
  pthread_setaffinity_np(pthread_self(), sizeof(cpu_set_t), &cpuset);

  if (!cmd.exists("i"))
    engine.loadZeroTestcase(4);
  else
    engine.loadTestcasesFromDir<RawInput>(cmd.get<std::string>("input"));

  for (size_t i = 0; i < engines.size(); ++i) {
  
    auto e = engines[i];
  
    std::thread * t = new std::thread([](Engine* e) {
      e->loop();
    }, e);

    CPU_ZERO(&cpuset);
    CPU_SET(i+1, &cpuset);
    pthread_setaffinity_np(t->native_handle(), sizeof(cpu_set_t), &cpuset);
  }
  
  engine.loop();

}
