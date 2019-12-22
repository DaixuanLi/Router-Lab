#include <stdint.h>
#include <stdlib.h>

/**
 * @brief 进行转发时所需的 IP 头的更新：
 *        你需要先检查 IP 头校验和的正确性，如果不正确，直接返回 false ；
 *        如果正确，请更新 TTL 和 IP 头校验和，并返回 true 。
 *        你可以从 checksum 题中复制代码到这里使用。
 * @param packet 收到的 IP 包，既是输入也是输出，原地更改
 * @param len 即 packet 的长度，单位为字节
 * @return 校验和无误则返回 true ，有误则返回 false
 */

uint16_t convert(uint16_t x) {
    uint16_t result = 0;
    result |= (x << 8);
    result |= (x >> 8);
    return result;
}

bool forward(uint8_t *packet, size_t len) {
  // TODO:
  uint32_t checkSum32 = 0;
  uint16_t* pCheckSum = (uint16_t*)(packet + 10);
  uint16_t realCheckSum = convert(*pCheckSum);
  *pCheckSum = 0;
  uint8_t IHL = (packet[0] & 0xf) * 2;
  uint16_t* p = (uint16_t*)packet;
  for (int i = 0; i < IHL; ++i, ++p) {
      checkSum32 += convert(*p);
  }
  while (checkSum32 >> 16) {
      uint32_t high = (checkSum32 >> 16);
      checkSum32 &= 0xffff;
      checkSum32 += high;
  }
  uint16_t checkSum = (uint16_t)(~checkSum32);
  if (checkSum != realCheckSum) {
    return false;
  }

  uint8_t* pTTL = packet + 8;
  *pTTL -= 1;
  checkSum += 0x100;
  if (checkSum == 0xffff) {
    checkSum = 0;
  }
  *pCheckSum = convert(checkSum);

  return true;
}
