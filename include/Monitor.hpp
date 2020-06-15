#pragma once

#include "Logger.hpp"
#include "Object.hpp"

#include <vector>

namespace FFF {

struct Engine;

struct Monitor {

  static void setInstance(Monitor* monitor) {
    instance = monitor;
  }
  static Monitor* getInstance() {
    if (instance == nullptr)
      instance = new Monitor();
    return instance;
  }
  
  static void addEngine(Engine* engine) {
    engines.push_back(engine);
  }
  static Engine* getEngine(size_t idx) {
    return engines[idx];
  }
  static size_t numEngines() {
    return engines.size();
  }
  
  static void event(Object* sender, const std::string& info) {
    getInstance()->handleEvent(sender, info);
  }
  
protected:
  void handleEvent(Object* sender, const std::string& info);

  Monitor() {}

  static Monitor* instance;
  static std::vector<Engine*> engines;

};

}
