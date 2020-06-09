#include "Engine.hpp"
#include "Queue.hpp"
#include "Mutator.hpp"
#include "Stage.hpp"
#include "FuzzOne.hpp"
#include "Impl/InMemoryExecutor.hpp"
#include "Impl/MaximizeMapFeedback.hpp"
#include "Impl/HitcountsMapObvservationChannel.hpp"
#include "Impl/CmpMapObvservationChannel.hpp"

#include "Config.h"

using namespace FFF;

extern "C" {

extern uint8_t __fff_edges_map[MAP_SIZE];
extern uint8_t __fff_cmp_map[MAP_SIZE];

int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size);
__attribute__((weak)) int LLVMFuzzerInitialize(int *argc, char ***argv);

}

int main(int argc, char** argv) {

  Engine engine;

  InMemoryExecutor exe(&LLVMFuzzerTestOneInput);
  
  HitcountsMapObvservationChannel hits_obs(__fff_edges_map, MAP_SIZE);
  MaximizeMapFeedback<uint8_t> hits_feed(MAP_SIZE);
  exe.addObserver(&hits_obs);
  
  CmpMapObvservationChannel cmp_obs(__fff_cmp_map, MAP_SIZE);
  MaximizeMapFeedback<uint8_t> cmp_feed(MAP_SIZE);
  FeedbackQueue cmp_queue(&cmp_feed);
  cmp_feed.setFeedbackQueue(&cmp_queue);
  exe.addObserver(&cmp_obs);
  
  GlobalQueue queue;
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
  
  engine.loadZeroTestcase(32);
  engine.loop();

}
