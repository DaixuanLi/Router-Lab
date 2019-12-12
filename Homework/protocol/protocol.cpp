#include "rip.h"
#include <stdint.h>
#include <stdlib.h>
#include <stdio.h>
#include <iostream>
using namespace std;
/*
  在头文件 rip.h 中定义了如下的结构体：
  #define RIP_MAX_ENTRY 25
  typedef struct {
    // all fields are big endian
    // we don't store 'family', as it is always 2(for response) and 0(for request)
    // we don't store 'tag', as it is always 0
    uint32_t addr;
    uint32_t mask;
    uint32_t nexthop;
    uint32_t metric;
  } RipEntry;

  typedef struct {
    uint32_t numEntries;
    // all fields below are big endian
    uint8_t command; // 1 for request, 2 for response, otherwsie invalid
    // we don't store 'version', as it is always 2
    // we don't store 'zero', as it is always 0
    RipEntry entries[RIP_MAX_ENTRY];
  } RipPacket;

  你需要从 IPv4 包中解析出 RipPacket 结构体，也要从 RipPacket 结构体构造出对应的 IP 包
  由于 Rip 包结构本身不记录表项的个数，需要从 IP 头的长度中推断，所以在 RipPacket 中额外记录了个数。
  需要注意这里的地址都是用 **大端序** 存储的，1.2.3.4 对应 0x04030201 。
*/

uint32_t join8(uint8_t a, uint8_t b)
{
  return ((uint32_t)a << 8) + ((uint32_t)b);
}

uint32_t join8(uint8_t a, uint8_t b, uint8_t c, uint8_t d)
{
  return ((uint32_t)a << 24) + ((uint32_t)b << 16) + ((uint32_t)c << 8) + ((uint32_t)d);
}

bool testMask(uint32_t mask)
{
  int i = 0;
  for (; i < 32; i++)
  {
    if ((mask & (1 << i)) == 0)
    {
      break;
    }
  }
  for (; i < 32; i++)
  {
    if ((mask & (1 << i)) != 0)
    {
      return false;
    }
  }
  return true;
}

void set_reverse(const uint32_t from, uint8_t &to1, uint8_t &to2, uint8_t &to3, uint8_t &to4)
{
  to1 = (uint8_t)((from & 0x000000ff));
  to2 = (uint8_t)((from & 0x0000ff00) >> 8);
  to3 = (uint8_t)((from & 0x00ff0000) >> 16);
  to4 = (uint8_t)((from & 0xff000000) >> 24);
}

/**
 * @brief 从接受到的 IP 包解析出 Rip 协议的数据
 * @param packet 接受到的 IP 包
 * @param len 即 packet 的长度
 * @param output 把解析结果写入 *output
 * @return 如果输入是一个合法的 RIP 包，把它的内容写入 RipPacket 并且返回 true；否则返回 false
 * 
 * IP 包的 Total Length 长度可能和 len 不同，当 Total Length 大于 len 时，把传入的 IP 包视为不合法。
 * 你不需要校验 IP 头和 UDP 的校验和是否合法。
 * 你需要检查 Command 是否为 1 或 2，Version 是否为 2， Zero 是否为 0，
 * Family 和 Command 是否有正确的对应关系（见上面结构体注释），Tag 是否为 0，
 * Metric 转换成小端序后是否在 [1,16] 的区间内，
 * Mask 的二进制是不是连续的 1 与连续的 0 组成等等。
 */
bool disassemble(const uint8_t *packet, uint32_t len, RipPacket *output)
{
  // TODO:
  // printf("Debug:len is %u\n",len);
  // for(int i = 0;i < len;i++){
  //   std::string a = "";
  //   for(int j = 0;j < 8;j++){
  //     a += ((unsigned(packet[i]) & (1 << (7-j))) == 0) ? "0":"1";
  //   }
  //   cout << "number at " << i << " is " << a << endl;
  // }
  if (len < 20)
  {
    return false;
  }
  uint32_t iplen = (((uint32_t)packet[2]) << 8) + ((uint32_t)packet[3]);
  if (iplen != len)
  {
    return false;
  }
  uint32_t ipheadlen = ((uint32_t)(packet[0] & 0x0f));
  ipheadlen = ipheadlen * 4;
  uint32_t ripbegin = ipheadlen + 8;
  if (len < ripbegin + 4)
  {
    //printf("1");
    return false;
  }
  uint32_t riplen = len - ripbegin;
  if ((riplen - 4) % 20 != 0 || riplen - 4 == 0)
  {
    //printf("2");
    return false;
  }
  // version && zero
  if (packet[ripbegin + 1] != 2 || packet[ripbegin + 2] != 0 || packet[ripbegin + 3] != 0)
  {
    //printf("3");
    return false;
  }
  // command
  RipPacket *ans = new RipPacket();
  if (packet[ripbegin] == 1)
  {
    uint32_t ripnum = (riplen - 4) / 20;
    if (ripnum > 25)
    {
      //printf("4");
      return false;
    }
    ans->numEntries = ripnum;
    ans->command = 1;
    for (uint32_t i = 0; i < ripnum; i++)
    {
      uint32_t thisBegin = ripbegin + 4 + 20 * i;
      if (packet[thisBegin] != 0 || packet[thisBegin + 1] != 0)
      {
        //printf("5");
        return false;
      }
      if (join8(packet[thisBegin + 2], packet[thisBegin + 3]) != 0)
      {
        //printf("6");
        return false;
      }
      RipEntry newEntry;
      newEntry.addr = join8(packet[thisBegin + 7], packet[thisBegin + 6], packet[thisBegin + 5], packet[thisBegin + 4]);
      newEntry.mask = join8(packet[thisBegin + 11], packet[thisBegin + 10], packet[thisBegin + 9], packet[thisBegin + 8]);
      newEntry.nexthop = join8(packet[thisBegin + 15], packet[thisBegin + 14], packet[thisBegin + 13], packet[thisBegin + 12]);
      newEntry.metric = join8(packet[thisBegin + 19], packet[thisBegin + 18], packet[thisBegin + 17], packet[thisBegin + 16]);
      uint32_t testMet = join8(packet[thisBegin + 16], packet[thisBegin + 17], packet[thisBegin + 18], packet[thisBegin + 19]);
      if (!testMask(newEntry.mask))
      {
        //printf("7");
        return false;
      }
      if (testMet != 16)
      {
        //printf("8");
        return false;
      }
      ans->entries[i] = newEntry;
    }
  }
  else if (packet[ripbegin] == 2)
  {
    uint32_t ripnum = (riplen - 4) / 20;
    if (ripnum > 25)
    {
      //printf("9");
      return false;
    }
    ans->numEntries = ripnum;
    ans->command = 2;
    for (uint32_t i = 0; i < ripnum; i++)
    {
      uint32_t thisBegin = ripbegin + 4 + 20 * i;
      // cout << "print rip:" << endl;
      // for(uint32_t j = thisBegin;j<thisBegin+20;j++) {
      //   cout << hex << unsigned(packet[j]) << endl;
      // }
      // cout << "print rip finished." << endl;
      if (packet[thisBegin] != 0 || packet[thisBegin + 1] != 2)
      {
        //printf("10");
        return false;
      }
      if (join8(packet[thisBegin + 2], packet[thisBegin + 3]) != 0)
      {
        //printf("11");
        return false;
      }
      RipEntry newEntry;
      newEntry.addr = join8(packet[thisBegin + 7], packet[thisBegin + 6], packet[thisBegin + 5], packet[thisBegin + 4]);
      newEntry.mask = join8(packet[thisBegin + 11], packet[thisBegin + 10], packet[thisBegin + 9], packet[thisBegin + 8]);
      newEntry.nexthop = join8(packet[thisBegin + 15], packet[thisBegin + 14], packet[thisBegin + 13], packet[thisBegin + 12]);
      newEntry.metric = join8(packet[thisBegin + 19], packet[thisBegin + 18], packet[thisBegin + 17], packet[thisBegin + 16]);
      uint32_t testMet = join8(packet[thisBegin + 16], packet[thisBegin + 17], packet[thisBegin + 18], packet[thisBegin + 19]);
      if (!testMask(newEntry.mask))
      {
        //printf("12");
        return false;
      }
      if (testMet == 0 || testMet > 16)
      {
        //printf("13");
        return false;
      }
      ans->entries[i] = newEntry;
    }
  }
  else
  {

    //printf("14");
    return false;
  }
  *output = *ans;
  return true;
}

/**
 * @brief 从 RipPacket 的数据结构构造出 RIP 协议的二进制格式
 * @param rip 一个 RipPacket 结构体
 * @param buffer 一个足够大的缓冲区，你要把 RIP 协议的数据写进去
 * @return 写入 buffer 的数据长度
 * 
 * 在构造二进制格式的时候，你需要把 RipPacket 中没有保存的一些固定值补充上，包括 Version、Zero、Address Family 和 Route Tag 这四个字段
 * 你写入 buffer 的数据长度和返回值都应该是四个字节的 RIP 头，加上每项 20 字节。
 * 需要注意一些没有保存在 RipPacket 结构体内的数据的填写。
 */
uint32_t assemble(const RipPacket *rip, uint8_t *buffer)
{
  // TODO:
  buffer[1] = 2;
  buffer[2] = 0;
  buffer[3] = 0;
  if (rip->command == 1)
  {
    buffer[0] = 1;
    for (uint32_t i = 0; i < rip->numEntries; i++)
    {
      uint32_t thisBegin = 4 + i * 20;
      buffer[thisBegin] = 0;
      buffer[thisBegin + 1] = 0;
      buffer[thisBegin + 2] = 0;
      buffer[thisBegin + 3] = 0;
      set_reverse((rip->entries[i]).addr,buffer[thisBegin + 4],buffer[thisBegin + 5],buffer[thisBegin + 6],buffer[thisBegin + 7]);
      set_reverse((rip->entries[i]).mask,buffer[thisBegin + 8],buffer[thisBegin + 9],buffer[thisBegin + 10],buffer[thisBegin + 11]);
      set_reverse((rip->entries[i]).nexthop,buffer[thisBegin + 12],buffer[thisBegin + 13],buffer[thisBegin + 14],buffer[thisBegin + 15]);
      set_reverse((rip->entries[i]).metric,buffer[thisBegin + 16],buffer[thisBegin + 17],buffer[thisBegin + 18],buffer[thisBegin + 19]);
    }
  }
  else
  {
    buffer[0] = 2;
    for (uint32_t i = 0; i < rip->numEntries; i++)
    {
      uint32_t thisBegin = 4 + i * 20;
      buffer[thisBegin] = 0;
      buffer[thisBegin + 1] = 2;
      buffer[thisBegin + 2] = 0;
      buffer[thisBegin + 3] = 0;
      set_reverse((rip->entries[i]).addr,buffer[thisBegin + 4],buffer[thisBegin + 5],buffer[thisBegin + 6],buffer[thisBegin + 7]);
      set_reverse((rip->entries[i]).mask,buffer[thisBegin + 8],buffer[thisBegin + 9],buffer[thisBegin + 10],buffer[thisBegin + 11]);
      set_reverse((rip->entries[i]).nexthop,buffer[thisBegin + 12],buffer[thisBegin + 13],buffer[thisBegin + 14],buffer[thisBegin + 15]);
      set_reverse((rip->entries[i]).metric,buffer[thisBegin + 16],buffer[thisBegin + 17],buffer[thisBegin + 18],buffer[thisBegin + 19]);
    }
  }
  return 20 * (rip->numEntries) + 4;
}