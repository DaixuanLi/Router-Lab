#include <stdint.h>
#include <stdlib.h>
#include <iostream>
/**
 * @brief 进行 IP 头的校验和的验证
 * @param packet 完整的 IP 头和载荷
 * @param len 即 packet 的长度，单位是字节，保证包含完整的 IP 头
 * @return 校验和无误则返回 true ，有误则返回 false
 */
bool validateIPChecksum(uint8_t *packet, size_t len) {
  // TODO:
	int n = packet[0] & 15;
	int sum = 0;
	for (int i = 0; i < n * 4; i+=2) {
		sum += (packet[i] << 8) + packet[i + 1];
		while (sum >> 16) {
			sum -= (1 << 16);
			sum += 1;
		}
	}
	if (sum == 65535)
		return true;
	else return false;
}
