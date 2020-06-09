#pragma once

#include <cstdint>
#include <string>

namespace FFF {

struct Bytes : public std::basic_string<char> {

  using std::basic_string<char>::basic_string;

  template<typename T>
  T& get(size_t idx) {
    return *(T*)(&(*this)[idx]);
  }
  
  template<typename T>
  T getEndian(size_t idx, int endian) {
    if (endian == 0)
      return *(T*)(&(*this)[idx]);
    T num = *(T*)(&(*this)[idx]);
    for (size_t i = 0; i < sizeof(T)/2; ++i) {
      T tmp = ((char*)&num)[i];
      ((char*)&num)[i] = ((char*)&num)[sizeof(T)/2 -1 - i];
      ((char*)&num)[sizeof(T)/2 -1 - i] = tmp;
    }
    return num;
  }
  
  template<typename T>
  void setEndian(size_t idx, T num, int endian) {
    if (endian == 0)
      *(T*)(&(*this)[idx]) = num;
    else {
      for (size_t i = 0; i < sizeof(T)/2; ++i) {
        T tmp = ((char*)&num)[i];
        ((char*)&num)[i] = ((char*)&num)[sizeof(T)/2 -1 - i];
        ((char*)&num)[sizeof(T)/2 -1 - i] = tmp;
      }
      *(T*)(&(*this)[idx]) = num;
    }
  }

};

struct VirtualInput {

  virtual void deserialize(const Bytes& bytes);
  virtual Bytes serialize() = 0;
  virtual bool alreadySerialized() = 0;
  virtual Bytes& raw() = 0;

  virtual void saveClone() = 0;
  virtual void cleanClone() = 0;
  virtual void resetClone() = 0;
  bool hasClone() {
    return hasCloneFlag;
  }

protected:
  bool hasCloneFlag = false;

};

struct RawInput : VirtualInput {

  RawInput() {}
  RawInput(const Bytes& bytes) {
    this->bytes = bytes;
  }
  
  virtual void deserialize(const Bytes& bytes) {
    this->bytes = bytes;
  }
  Bytes serialize() {
    return bytes;
  }
  bool alreadySerialized() {
    return true;
  }
  Bytes& raw() {
    return bytes;
  }
  
  void saveClone() {
    clone = bytes;
    hasCloneFlag = true;
  }
  void cleanClone() {
    clone.clear();
    hasCloneFlag = false;
  }
  void resetClone() {
    bytes = clone;
  }
  
protected:
  Bytes bytes;
  Bytes clone;

};

}
