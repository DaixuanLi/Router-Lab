#include <stdint.h>
#include <stdlib.h>
#include <stdio.h>

/**
 * @brief 进行 IP 头的校验和的验证
 * @param packet 完整的 IP 头和载荷
 * @param len 即 packet 的长度，单位是字节，保证包含完整的 IP 头
 * @return 校验和无误则返回 true ，有误则返回 false
 */

uint16_t big2little(uint16_t x) {
    uint16_t result = 0;
    result |= (x << 8);
    result |= (x >> 8);
    return result;
}

bool validateIPChecksum(uint8_t *packet, size_t len) {
    // TODO:
    uint32_t checkSum = 0;
    uint16_t* pCheckSum = (uint16_t*)(packet + 10);
    uint16_t realCheckSum = big2little(*pCheckSum);
    *pCheckSum = 0;
    uint8_t IHL = (packet[0] & 0xf) * 2;
    uint16_t* p = (uint16_t*)packet;
    for (int i = 0; i < IHL; ++i, ++p) {
        checkSum += big2little(*p);
    }
    while (checkSum >> 16) {
        uint32_t high = (checkSum >> 16);
        checkSum &= 0xffff;
        checkSum += high;
    }

  return ((uint16_t)(~checkSum)) == realCheckSum;
}
