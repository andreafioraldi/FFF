#pragma once

#include "Bytes.hpp"
#include "Object.hpp"

#include <memory>

namespace FFF {

struct VirtualInput : public Object {

  virtual ~VirtualInput() = default;

  virtual void deserialize(const Bytes& bytes) = 0;
  virtual Bytes serialize() = 0;

  bool hasBackup() {
    return has_backup;
  }
  virtual void createBackup() = 0;
  virtual void resetBackup() = 0;

  virtual std::shared_ptr<VirtualInput> copy() = 0;

protected:
  bool has_backup;

};

}
