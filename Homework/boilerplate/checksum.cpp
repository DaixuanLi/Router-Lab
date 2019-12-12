#include <stdint.h>
#include <stdlib.h>
#include <cstdio>
using namespace std;
#include <iostream>

class Checksum_checker {
public:
  uint16_t value;
  Checksum_checker(uint8_t hi, uint8_t lo){
    this->value = ((uint16_t)hi) << 8;
    this->value += (uint16_t)lo; 
    //printf("Debug:generate checksum %hu from %hhu %hhu\n",this->value,hi,lo);
    //cout << print() << endl;
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
  string print(){
    string a = "";
    for(int j = 0;j < 16;j++){
      a += ((unsigned(value) & (1 << (15-j))) == 0) ? "0":"1";
    }
    return a;
  }
};

/**
 * @brief 进行 IP 头的校验和的验证
 * @param packet 完整的 IP 头和载荷
 * @param len 即 packet 的长度，单位是字节，保证包含完整的 IP 头
 * @return 校验和无误则返回 true ，有误则返回 false
 */
bool validateIPChecksum(uint8_t *packet, size_t len) {
  // TODO:
  // printf("Debug:len is %zu\n",len);
  // for(int i = 0;i < len;i++){
  //   string a = "";
  //   for(int j = 0;j < 8;j++){
  //     a += ((unsigned(packet[i]) & (1 << (7-j))) == 0) ? "0":"1";
  //   }
  //   cout << "number at " << i << " is " << a << endl;
  // }
  if(len < 20){
    return false;
  }
  Checksum_checker checksum_right(packet[10],packet[11]);
  packet[10] = 0;
  packet[11] = 0;
  uint8_t head_length = packet[0] & 0x0f;
  //cout << "ans is " << checksum_right.print() << endl;
  //cout << "packet 0 is " << unsigned(packet[0]) << endl;
  //cout << "head length is " << unsigned(head_length) << endl;
  if(len < (size_t)(head_length << 2)){
    return false;
  }
  Checksum_checker checksum_test(0,0);
  Checksum_checker *adder;
  for(uint8_t i = 0;i<head_length;i++){
    adder = (new Checksum_checker( packet[4 * i] , packet[4 * i + 1]));
    //cout << checksum_test.print() << "+" << adder->print() << endl;
    checksum_test = checksum_test + *adder;
    //cout << checksum_test.print() << " is result." << endl;
    delete adder;
    adder = (new Checksum_checker( packet[4 * i + 2], packet[4 * i + 3]));
    //cout << checksum_test.print() << "+" << adder->print() << endl;
    checksum_test = checksum_test + *adder;
    //cout << checksum_test.print() << " is result." << endl;
    delete adder;
  }
  if (checksum_test.value + checksum_right.value == 0xffff){
    return true;
  }
  return false;
}


/**
 * @brief 进行 IP 头的校验和的计算
 * @param packet 完整的 IP 头和载荷
 * @param len 即 packet 的长度，单位是字节，保证包含完整的 IP 头
 * @return 校验和无误则返回 true ，有误则返回 false
 */
uint16_t calculateIPChecksum(uint8_t *packet, size_t len) {
  // TODO:
  // printf("Debug:len is %zu\n",len);
  // for(int i = 0;i < len;i++){
  //   string a = "";
  //   for(int j = 0;j < 8;j++){
  //     a += ((unsigned(packet[i]) & (1 << (7-j))) == 0) ? "0":"1";
  //   }
  //   cout << "number at " << i << " is " << a << endl;
  // }
  Checksum_checker checksum_right(packet[10],packet[11]);
  packet[10] = 0;
  packet[11] = 0;
  uint8_t head_length = packet[0] & 0x0f;
  //cout << "ans is " << checksum_right.print() << endl;
  //cout << "packet 0 is " << unsigned(packet[0]) << endl;
  //cout << "head length is " << unsigned(head_length) << endl;
  Checksum_checker checksum_test(0,0);
  Checksum_checker *adder;
  for(uint8_t i = 0;i<head_length;i++){
    adder = (new Checksum_checker( packet[4 * i] , packet[4 * i + 1]));
    //cout << checksum_test.print() << "+" << adder->print() << endl;
    checksum_test = checksum_test + *adder;
    //cout << checksum_test.print() << " is result." << endl;
    delete adder;
    adder = (new Checksum_checker( packet[4 * i + 2], packet[4 * i + 3]));
    //cout << checksum_test.print() << "+" << adder->print() << endl;
    checksum_test = checksum_test + *adder;
    //cout << checksum_test.print() << " is result." << endl;
    delete adder;
  }
  return 0xffff - checksum_test.value;
}

