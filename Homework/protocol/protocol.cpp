#include "rip.h"
#include <stdint.h>
#include <stdlib.h>
#include <iostream>
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
bool disassemble(const uint8_t *packet, uint32_t len, RipPacket *output) {
  // TODO:
  if (len != packet[3]) {
printf("------error1\n");
    return false;
  }
  for (int i = 28; i < len; i+=2) {
    if (i == 28) {
      if (packet[i] != 1 && packet[i] != 2) {
printf("------error2\n");
        
        return false;
      }
      output->command = packet[i];
      if (packet[i+1] != 2){
printf("------error3\n");
        return false;

      }
    } else if ((i == 30) && (packet[i] != 0 || packet[i+1] != 0)) {
printf("------error4\n");
      return false;
    }
    //printf("%x %x\n", packet[i], packet[i+1]);
  }
  output->numEntries = (len  - 32) / 20;
  for (int i = 0; i < output->numEntries; i++) {
    int begin = 32 + 20 * i;
    int end = begin + 20;
    for (int j = 0; j < 20; j+=2) {
      int curr = begin+j;
      if (j == 0) {
        if ((output->command == 2 && packet[curr+1] != 2) || (output->command == 1 && packet[curr+1] != 0)){
printf("------error5\n");
          return false;

        }
        //output[i]->
      } else if (j == 2) {
        if (packet[curr] != 0 || packet[curr+1] != 0 ){

printf("------error6\n");
          return false;
        }
      } else if (j == 4) {
        //printf("in addr: %x\n", packet[curr]);
        output->entries[i].addr = (packet[curr]) + (packet[curr+1] << 8) + (packet[curr+2] << 16) + (packet[curr+3] << 24);
        j += 2;
        //output->entries[i].addr = ntohl(output->entries[i].addr);
        //printf("%x\n", output->entries[i].addr);
      } else if (j == 8) {
        output->entries[i].mask = (packet[curr]) + (packet[curr+1] << 8) + (packet[curr+2] << 16) + (packet[curr+3] << 24);
        j += 2;
        int tmp = (packet[curr] << 24) + (packet[curr+1] << 16) + (packet[curr+2] << 8) + packet[curr+3];
//printf("tmp:%x\n", tmp);
        int flag = 0;
        for (int k = 0; k < 32; k++) {
          //printf("%d %d %d %d\n", k, flag, (tmp >> k), ((tmp >> k) % 2));
          if (flag == 0 && ((tmp >> k) % 2) == 0) continue;
          else if (flag == 0 && ((tmp >> k) % 2)) flag = 1;
          else if (flag == 1 && (((tmp >> k) % 2) == 0)) 
          {
            printf("------------here\n");
            printf("tmp::%x\n", tmp);
          return false;

          }
        }
      } else if (j == 12) {
        output->entries[i].nexthop = (packet[curr]) + (packet[curr+1] << 8) + (packet[curr+2] << 16) + (packet[curr+3]<<24);
        j += 2;
      } else if (j == 16) {
        output->entries[i].metric = (packet[curr]) + (packet[curr+1] << 8) + (packet[curr+2] << 16) + (packet[curr+3]<<24);
        j += 2;
        //printf("%x\n", output->entries[i].metric);
        int tmp = (packet[curr] << 24) + (packet[curr+1] << 16) + (packet[curr+2] << 8) + packet[curr+3];
        //printf("metric: %d", tmp);
        if (tmp < 1 || tmp > 16){
printf("------error7\n");
          return false;
        }
      }
    }
  }
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
uint32_t assemble(const RipPacket *rip, uint8_t *buffer) {
  // TODO:
  buffer[0] = rip->command;
  buffer[1] = 2;
  buffer[2] = buffer[3] = 0;
  for (int i = 0; i < rip->numEntries; i++) {
    int begin = 4 + i * 20;
    buffer[begin] = 0;
    if (buffer[0] == 2)
      buffer[begin+1] = 2;
    else buffer[begin+1] = 0;
    buffer[begin+2] = buffer[begin+3] = 0;
    for (int j = 0; j < 4; j++) {
      buffer[begin+4+3-j] = rip->entries[i].addr >> (8 * (3-j));
    }
    for (int j = 0; j < 4; j++) {
      buffer[begin+8+3-j] = rip->entries[i].mask >> (8 * (3-j));
    }
    for (int j = 0; j < 4; j++) {
      buffer[begin+12+3-j] = rip->entries[i].nexthop >> (8 * (3-j));
    }
    for (int j = 0; j < 4; j++) {
      buffer[begin+16+3-j] = rip->entries[i].metric >> (8 * (3-j));
    }
  }
  return (4+20*rip->numEntries);
}
