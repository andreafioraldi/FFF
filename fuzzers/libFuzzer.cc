#include "Engine.hpp"
#include "Queue.hpp"
#include "Mutator.hpp"
#include "Stage.hpp"
#include "FuzzOne.hpp"
#include "Impl/InMemoryExecutor.hpp"
#include "Impl/MaximizeMapFeedback.hpp"
#include "Impl/MapObvservationChannel.hpp"

#include "Config.h"

#include "argparse.h"
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

  Engine engine;

  InMemoryExecutor exe(&LLVMFuzzerTestOneInput);
  
  HitcountsMapObvservationChannel hits_obs(__fff_edges_map, MAP_SIZE);
  MaximizeMapFeedback<uint8_t, HitcountsMapObvservationChannel> hits_feed(MAP_SIZE);
  exe.addObserver(&hits_obs);
  
  CmpMapObvservationChannel cmp_obs(__fff_cmp_map, MAP_SIZE);
  MaximizeMapFeedback<uint8_t, CmpMapObvservationChannel> cmp_feed(MAP_SIZE);
  FeedbackQueue cmp_queue(&cmp_feed, "CmpQueue");
  cmp_feed.setFeedbackQueue(&cmp_queue);
  exe.addObserver(&cmp_obs);
  
  GlobalQueue queue;
  queue.addFeedbackQueue(&cmp_queue);
  MutationalFuzzOne fuzz_one(&engine, &queue);
  Stage havoc(&engine);
  HavocMutator havoc_mut;
  havoc.addMutator(&havoc_mut);
  fuzz_one.addStage(&havoc);
  
  engine.setExecutor(&exe);
  engine.setFuzzOne(&fuzz_one);
  engine.setQueue(&queue);
  engine.addFeedback(&hits_feed);
  engine.addFeedback(&cmp_feed);
  
  if (LLVMFuzzerInitialize) LLVMFuzzerInitialize(&argc, &argv);
  
  if (!cmd.exists("i"))
    engine.loadZeroTestcase(4);
  else
    engine.loadTestcasesFromDir(cmd.get<std::string>("input"));
  
  engine.loop();

}
