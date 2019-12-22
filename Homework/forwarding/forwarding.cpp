#include <stdint.h>
#include <stdlib.h>
#include <iostream>
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
	int n = packet[0] & 15;
	int sum = 0;
	for (int i = 0; i < n * 4; i+=2) {
		sum += (packet[i] << 8) + packet[i + 1];
		while (sum >> 16) {
			//sum -= (1 << 16);
			sum &= 0xffff;
			sum += 1;
		}
	}
	if (sum == 65535) {
		int tmp = (packet[10] << 8) + packet[11];
		//printf("%d\n", packet[10]);
		//printf("%d\n", tmp);
		packet[8]--;
		tmp += 256;
		// if (tmp >> 16)
		// 	tmp -= 16;
		while (tmp >> 16) {
			tmp &= 0xffff;
			tmp += 1;
		}
		// //printf("%d\n", tmp);
		packet[10] = tmp >> 8;//
		// //printf("%d\n", packet[10]);
		packet[11] = tmp & 255;
		if (packet[10] == 255 && packet[11] == 255) 
			packet[10] = packet[11] = 0;

		// sum = 0;
		// for (int i = 0; i < n * 4; i+=2) {
		// 	if (i == 10) continue;
		// 	sum += (packet[i] << 8) + packet[i + 1];
		// 	while (sum >> 16) {
		// 		sum -= (1 << 16);
		// 		sum += 1;
		// 	}
		// }
		// int tmp = 65535 - sum;
		// packet[10] = tmp >> 8;
		// packet[11] = tmp & 255;


		return true;
	}
	else return false;
}
