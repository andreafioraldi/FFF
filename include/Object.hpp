#pragma once

#include <string>

namespace FFF {

struct Object {

  virtual std::string getObjectName() {
    return "[Object]";
  }

  virtual std::string toString() {
    return getObjectName();
  }

};

}
