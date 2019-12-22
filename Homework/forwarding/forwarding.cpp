#include <stdint.h>
#include <stdlib.h>
#include <stdio.h>

class Checksum_checker {
public:
  uint16_t value;
  Checksum_checker(uint8_t hi, uint8_t lo){
    this->value = ((uint16_t)hi) << 8;
    this->value += (uint16_t)lo;
  }
  Checksum_checker(uint16_t v){
    value = v;
  }
  Checksum_checker operator+(const Checksum_checker c){
    Checksum_checker* a = new Checksum_checker(c.value);
    a->value = add_with_overflow(a->value,value);
    return *a;
  }
  uint16_t add_with_overflow(uint16_t a, uint16_t b){
    uint16_t c = a + b;
    if(c < a){
      return c + 1;
    }else {
      return c;
    }
  }
};

/**
 * @brief 进行转发时所需的 IP 头的更新：
 *        你需要先检查 IP 头校验和的正确性，如果不正确，直接返回 false ；
 *        如果正确，请更新 TTL 和 IP 头校验和，并返回 true 。
 *        你可以从 checksum 题中复制代码到这里使用。
 * @param packet 收到的 IP 包，既是输入也是输出，原地更改
 * @param len 即 packet 的长度，单位为字节
 * @return 校验和无误则返回 true ，有误则返回 false
 */
bool forward(uint8_t *packet, size_t len) {
  // TODO:
  Checksum_checker checksum_right(packet[10],packet[11]);
  Checksum_checker checksum_cache(packet[10],packet[11]);
  packet[10] = 0;
  packet[11] = 0;
  uint8_t head_length = packet[0] & 0x0f;
  /*if(len < (size_t)(head_length << 2)){
    return false;
  }*/
  //printf("in fowarding \n");
  Checksum_checker checksum_test(0,0);
  Checksum_checker *adder;
  for(uint8_t i = 0;i<head_length;i++){
    adder = (new Checksum_checker( packet[4 * i] , packet[4 * i + 1]));
    checksum_test = checksum_test + *adder;
    delete adder;
    adder = (new Checksum_checker( packet[4 * i + 2], packet[4 * i + 3]));
    checksum_test = checksum_test + *adder;
    delete adder;
  }
  if (!(checksum_test.value + checksum_right.value == 0xffff)){
    //printf("checksum failed.\n");
    return false;
  }
  //printf("in fowarding: before ttl \n",packet[8]);
  packet[8] -= 1;
  //printf("in fowarding: after ttl %u \n",packet[8]);
  Checksum_checker checksum_test1(0,0);
  Checksum_checker *adder1;
  for(uint8_t i = 0;i<head_length;i++){
    adder1 = (new Checksum_checker( packet[4 * i] , packet[4 * i + 1]));
    checksum_test1 = checksum_test1 + *adder1;
    delete adder1;
    adder1 = (new Checksum_checker( packet[4 * i + 2], packet[4 * i + 3]));
    checksum_test1 = checksum_test1 + *adder1;
    delete adder1;
  }
  uint16_t ans = 0xffff - checksum_test1.value;
  checksum_cache.value = checksum_cache.add_with_overflow(checksum_cache.value,0x100);
  if(checksum_cache.value == 0xffff) {
    checksum_cache.value = 0;
  }
  //printf("--------------- %x %x\n",checksum_cache.value,ans);
  packet[10] = (checksum_cache.value & 0xff00) >> 8;
  packet[11] = checksum_cache.value & 0x00ff;
  //printf("in fowarding: checksum calc %u %u",packet[8]);
  return true;
}
