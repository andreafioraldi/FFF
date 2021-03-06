#include "Mutator/ScheduledMutator.hpp"
#include "Input/RawInput.hpp"
#include "Random.hpp"

#define ARITH_MAX 35

#define HAVOC_BLK_SMALL 32
#define HAVOC_BLK_MEDIUM 128
#define HAVOC_BLK_LARGE 1500
#define HAVOC_BLK_XL 32768

using namespace FFF;

static size_t chooseBlockLen(size_t limit) {

  size_t min_value, max_value;
  switch (Random::below(3)) {
    case 0:
      min_value = 1;
      max_value = HAVOC_BLK_SMALL;
      break;
    case 1:
      min_value = HAVOC_BLK_SMALL;
      max_value = HAVOC_BLK_MEDIUM;
      break;
    default:
      if (Random::below(10)) {
        min_value = HAVOC_BLK_MEDIUM;
        max_value = HAVOC_BLK_LARGE;
      } else {
        min_value = HAVOC_BLK_LARGE;
        max_value = HAVOC_BLK_XL;
      }
  }

  if (min_value >= limit) min_value = 1;

  return min_value + Random::below((max_value < limit ? max_value : limit) - min_value + 1);

}

namespace FFF {

void FlipBitMutation(Mutator* mutator, VirtualInput* input) {
  RawInput* i = static_cast<RawInput*>(input);
  size_t size = i->getBytes().size();
  if (!size) return;
  size_t bit = Random::below(size << 3);
  i->getBytes()[bit >> 3] ^= (128 >> (bit & 7));
}

void Flip2BitsMutation(Mutator* mutator, VirtualInput* input) {
  RawInput* i = static_cast<RawInput*>(input);
  size_t size = i->getBytes().size();
  if (!size) return;
  size_t bit = Random::below(size << 3);
  if ((size << 3) - bit < 2) return;
  i->getBytes()[bit >> 3] ^= (128 >> (bit & 7));
  bit++;
  i->getBytes()[bit >> 3] ^= (128 >> (bit & 7));
}

void Flip4BitsMutation(Mutator* mutator, VirtualInput* input) {
  RawInput* i = static_cast<RawInput*>(input);
  size_t size = i->getBytes().size();
  if (!size) return;
  size_t bit = Random::below(size << 3);
  if ((size << 3) - bit < 4) return;
  i->getBytes()[bit >> 3] ^= (128 >> (bit & 7));
  bit++;
  i->getBytes()[bit >> 3] ^= (128 >> (bit & 7));
  bit++;
  i->getBytes()[bit >> 3] ^= (128 >> (bit & 7));
  bit++;
  i->getBytes()[bit >> 3] ^= (128 >> (bit & 7));
}

void Flip8BitsMutation(Mutator* mutator, VirtualInput* input) {
  RawInput* i = static_cast<RawInput*>(input);
  size_t size = i->getBytes().size();
  if (!size) return;
  size_t idx = Random::below(size);
  i->getBytes()[idx] ^= 0xff;
}

void Flip16BitsMutation(Mutator* mutator, VirtualInput* input) {
  RawInput* i = static_cast<RawInput*>(input);
  size_t size = i->getBytes().size();
  if (size < 2) return;
  size_t idx = Random::below(size -1);
  i->getBytes().get<uint16_t>(idx) ^= 0xffff;
}

void Flip32BitsMutation(Mutator* mutator, VirtualInput* input) {
  RawInput* i = static_cast<RawInput*>(input);
  size_t size = i->getBytes().size();
  if (size < 4) return;
  size_t idx = Random::below(size -3);
  i->getBytes().get<uint32_t>(idx) ^= 0xffffffff;
}

void RandomByteAddSubMutation(Mutator* mutator, VirtualInput* input) {
  RawInput* i = static_cast<RawInput*>(input);
  size_t size = i->getBytes().size();
  if (!size) return;
  size_t idx = Random::below(size);
  i->getBytes()[idx] -= 1 + Random::below(ARITH_MAX);
  i->getBytes()[idx] += 1 + Random::below(ARITH_MAX);
}

void RandomWordAddSubMutation(Mutator* mutator, VirtualInput* input) {
  RawInput* i = static_cast<RawInput*>(input);
  size_t size = i->getBytes().size();
  if (size < 2) return;
  int endian = Random::below(2);
  size_t idx = Random::below(size -1);
  uint16_t val = i->getBytes().getEndian<uint16_t>(idx, endian);
  i->getBytes().setEndian(idx, val - 1 + Random::below(ARITH_MAX), endian);
  idx = Random::below(size -1);
  val = i->getBytes().getEndian<uint16_t>(idx, endian);
  i->getBytes().setEndian(idx, val + 1 + Random::below(ARITH_MAX), endian);
}

void RandomDwordAddSubMutation(Mutator* mutator, VirtualInput* input) {
  RawInput* i = static_cast<RawInput*>(input);
  size_t size = i->getBytes().size();
  if (size < 4) return;
  int endian = Random::below(2);
  size_t idx = Random::below(size -3);
  uint32_t val = i->getBytes().getEndian<uint32_t>(idx, endian);
  i->getBytes().setEndian(idx, val - 1 + Random::below(ARITH_MAX), endian);
  idx = Random::below(size -1);
  val = i->getBytes().getEndian<uint32_t>(idx, endian);
  i->getBytes().setEndian(idx, val + 1 + Random::below(ARITH_MAX), endian);
}

void RandomByteMutation(Mutator* mutator, VirtualInput* input) {
  RawInput* i = static_cast<RawInput*>(input);
  size_t size = i->getBytes().size();
  if (!size) return;
  size_t idx = Random::below(size);
  i->getBytes()[idx] ^= 1 + Random::below(255);
}

void DeleteBytesMutation(Mutator* mutator, VirtualInput* input) {
  RawInput* i = static_cast<RawInput*>(input);
  size_t size = i->getBytes().size();
  if (size < 2) return;
  size_t del_len = chooseBlockLen(size -1);
  size_t del_from = Random::below(size - del_len + 1);
  i->getBytes().erase(del_from, del_len);
}

void CloneBytesMutation(Mutator* mutator, VirtualInput* input) {
  RawInput* i = static_cast<RawInput*>(input);
  size_t size = i->getBytes().size();
  if (!size) return;
  int actually_clone = Random::below(4);
  size_t clone_from, clone_to, clone_len;
  clone_to = Random::below(size);
  if (actually_clone) {
    clone_len = chooseBlockLen(size);
    clone_from = Random::below(size - clone_len + 1);
    i->getBytes().insert(clone_to, i->getBytes().data() + clone_from, clone_len);
  } else {
    clone_len = chooseBlockLen(HAVOC_BLK_XL);
    clone_from = 0;
    i->getBytes().insert(clone_to, clone_len, Random::below(2) ? Random::below(256) : i->getBytes()[Random::below(size)]);
  }
}

void OverwriteBytesMutation(Mutator* mutator, VirtualInput* input) {
  RawInput* i = static_cast<RawInput*>(input);
  size_t size = i->getBytes().size();
  if (!size) return;
  int actually_clone = Random::below(4);
  size_t clone_from, clone_to, clone_len;
  clone_to = Random::below(size);
  if (actually_clone) {
    clone_len = chooseBlockLen(size);
    clone_from = Random::below(size - clone_len + 1);
    i->getBytes().insert(clone_to, i->getBytes().data() + clone_from, clone_len);
  } else {
    clone_len = chooseBlockLen(HAVOC_BLK_XL);
    clone_from = 0;
    i->getBytes().insert(clone_to, clone_len, Random::below(2) ? Random::below(256) : i->getBytes()[Random::below(size)]);
  }
}


void addHavocMutations(ScheduledMutator* mut) {
  mut->addMutation(&FlipBitMutation);
  mut->addMutation(&Flip2BitsMutation);
  mut->addMutation(&Flip4BitsMutation);
  mut->addMutation(&Flip8BitsMutation);
  mut->addMutation(&Flip16BitsMutation);
  mut->addMutation(&Flip32BitsMutation);
  /*mut->addMutation(&RandomByteAddSubMutation);
  mut->addMutation(&RandomWordAddSubMutation);
  mut->addMutation(&RandomDwordAddSubMutation);*/

  mut->addMutation(&RandomByteMutation);
  mut->addMutation(&RandomByteMutation);
  mut->addMutation(&RandomByteMutation);
  mut->addMutation(&RandomByteMutation);
  mut->addMutation(&RandomByteMutation);
  
  mut->addMutation(&DeleteBytesMutation);
  mut->addMutation(&DeleteBytesMutation); // delete is 2 times more likely
  mut->addMutation(&CloneBytesMutation);
  mut->addMutation(&OverwriteBytesMutation);
}

}
