#include "rip.h"
#include "router.h"
#include "router_hal.h"
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <map>
#include <iostream>
#include <arpa/inet.h>

extern bool validateIPChecksum(uint8_t *packet, size_t len);
extern void update(bool insert, RoutingTableEntry entry);
extern bool query(uint32_t addr, uint32_t *nexthop, uint32_t *if_index, uint32_t *metric);
extern bool forward(uint8_t *packet, size_t len);
extern bool disassemble(const uint8_t *packet, uint32_t len, RipPacket *output);
extern uint32_t assemble(const RipPacket *rip, uint8_t *buffer);
extern std::map<std::pair<int, int>, RoutingTableEntry> router;
extern uint32_t masks[33];


uint32_t multi_cast_addr = 0x090000e0;
macaddr_t multi_cast_dst_mac = {0x01, 0x00, 0x5e, 0x00, 0x00, 0x09};
uint8_t packet[2048];
uint8_t output[2048];
// 0: 10.0.0.1
// 1: 10.0.1.1
// 2: 10.0.2.1
// 3: 10.0.3.1
// 你可以按需进行修改，注意端序
in_addr_t addrs[N_IFACE_ON_BOARD] = {0x0204a8c0, 0x0205a8c0, 0x0202a8c0,
                                     0x0100000a};
void calcChecksum()
{
  output[10] = output[11] = 0;
  uint32_t sum = 0;
  for (size_t i = 0; i < 20; i += 2)
  {
    sum += (output[i] << 8) | (output[i + 1]);
  }
  while ((sum >> 16) > 0)
  {
    sum = (sum >> 16) + (sum & 0xffff);
  }
  *(uint16_t *)(output + 10) = htons(~sum & 0xffff);
}

bool query_exact(uint32_t addr, uint32_t len, RoutingTableEntry& rte) {
  if (router.find(std::pair<int, int>(addr, len)) != router.end()) {
    std::map<std::pair<int, int>, RoutingTableEntry>::iterator iter = router.find(std::pair<int, int>(addr, len));
    rte = iter->second;
    return true;
  }
  return false;
}

void fill_static_head()
{
  output[0] = 0x45;
  output[1] = 0x00;
  output[4] = output[5] = output[6] = output[7] = 0;
  output[8] = 1;
  output[9] = 0x11;
  output[20] = output[22] = 0x02;
  output[21] = output[23] = 0x08;
  output[26] = output[27] = 0x0;
}
void fill_dymatic_head(uint32_t packet_length, uint32_t src, uint32_t dst)
{

  output[2] = (packet_length >> 8) & 0xff;
  output[3] = packet_length & 0xff;

  //10 11 checksum;
  // output[12] = src && 0xff;
  *((uint32_t *)(output + 12)) = src;
  *((uint32_t *)(output + 16)) = dst;

  output[24] = ((packet_length - 20) >> 8) & 0xff;
  output[25] = (packet_length - 20) & 0xff;
  calcChecksum();
}
// uint32_t masks[33] = {0x00000000,
//     0x80000000, 0xC0000000, 0xE0000000, 0xF0000000,
//     0xF8000000, 0xFC000000, 0xFE000000, 0xFF000000,
//     0xFF800000, 0xFFC00000, 0xFFE00000, 0xFFF00000,
//     0xFFF80000, 0xFFFC0000, 0xFFFE0000, 0xFFFF0000,
//     0xFFFF8000, 0xFFFFC000, 0xFFFFE000, 0xFFFFF000,
//     0xFFFFF800, 0xFFFFFC00, 0xFFFFFE00, 0xFFFFFF00,
//     0xFFFFFF80, 0xFFFFFFC0, 0xFFFFFFE0, 0xFFFFFFF0,
//     0xFFFFFFF8, 0xFFFFFFFC, 0xFFFFFFFE, 0xFFFFFFFF};
void RoutingEntry2RipEntry(RoutingTableEntry& routing_entry, RipEntry& rip_entry) {
  rip_entry.addr = routing_entry.addr;
  rip_entry.mask = ntohl(masks[(int)(routing_entry.len)]);
  rip_entry.nexthop = routing_entry.nexthop;
  rip_entry.metric = routing_entry.metric;
}
uint32_t mask2len(uint32_t mask) {
  uint32_t len = 32;
  for (int i = 0; i < 32; i++) {
    if ((mask & 1) == 0) {
      len--;
      mask >>= 1;
    }
    else break;
  }
  return len;
}
// void RipEntry2RoutingEntry(RipEntry& rip_entry, RoutingTableEntry& routing_entry) {
//   routing_entry.addr = rip_entry.addr;
//   routing_entry.len = 
//   routing_entry.if_index = 
// }

void print_addr(uint32_t addr) {
  uint32_t tmp = ntohl(addr);
  std::cout << ((tmp & 0xff000000) >> 24) << "." 
            << ((tmp & 0x00ff0000) >> 16) << "."
            << ((tmp & 0x0000ff00) >> 8) << "." << ((tmp & 0x000000ff));
}

int main(int argc, char *argv[]) {
  // 0a.
  int res = HAL_Init(1, addrs);
  if (res < 0) {
    return res;
  }

  // 0b. Add direct routes
  // For example:
  // 10.0.0.0/24 if 0
  // 10.0.1.0/24 if 1
  // 10.0.2.0/24 if 2
  // 10.0.3.0/24 if 3
  for (uint32_t i = 0; i < N_IFACE_ON_BOARD; i++) {
    RoutingTableEntry entry = {
        .addr = addrs[i] & 0x00FFFFFF, // big endian
        .len = 24,        // small endian
        .if_index = i,    // small endian
        .nexthop = 0,      // big endian, means direct
        .metric = ntohl(1)
    };
    update(true, entry);
  }

  uint64_t last_time = 0;
  while (1) {
    uint64_t time = HAL_GetTicks();
    if (time > last_time + 5 * 1000) {
      // printf("send timeout packet\n");
      // fflush(stdout);
      // What to do?
      // send complete routing table to every interface
      // ref. RFC2453 3.8
      // multicast MAC for 224.0.0.9 is 01:00:5e:00:00:09
      fill_static_head();
      
      std::map<std::pair<int, int>, RoutingTableEntry>::iterator iter;
      iter = router.begin();
      
      
      for (int i = 0; i < N_IFACE_ON_BOARD; i++)
      {
        RipPacket rp;
        iter = router.begin();
        // rp.numEntries = 3;
        rp.command = 2;
        int pos = 0;
        iter = router.begin();
        while (iter != router.end())
        {
          
          if (iter->second.if_index != i)
            RoutingEntry2RipEntry(iter->second, rp.entries[pos++]);
          
          if (pos == 25) {
            rp.numEntries = pos;
            int len = assemble(&rp, output + 28);
            len += 28;
            fill_dymatic_head(len, addrs[i], multi_cast_addr);
            HAL_SendIPPacket(i, output, len, multi_cast_dst_mac);//???
            pos = 0;
      //       printf("send an IP packet");
      // fflush(stdout);
          }
          iter++;
        }
      //   printf("after while\n");
      // fflush(stdout);
        if (pos == 0) continue;

        rp.numEntries = pos;
        int len = assemble(&rp, output + 28);
        len += 28;
        //int length = 32 + 4 * 20;
        fill_dymatic_head(len, addrs[i], multi_cast_addr);

        HAL_SendIPPacket(i, output, len, multi_cast_dst_mac);//???
      }
      //输出表项
      iter = router.begin();
      printf("table head: addr, index, len, metric, nexthop\n");
      while (iter != router.end()) {
        RoutingTableEntry tmp = iter->second;
        std::cout << "Routing Info: ";
        print_addr(tmp.addr);
        std::cout << " ";
        std::cout << tmp.if_index << " " << tmp.len << " " << ntohl(tmp.metric) << " ";
        print_addr(tmp.nexthop);
        std::cout << std::endl;
        //printf("routing info: %0x, %u, %u, %u, %0x\n", tmp.addr, tmp.if_index, tmp.len, ntohl(tmp.metric), tmp.nexthop);
        iter++;
      }
      printf("5s Timer\n");
      printf("total length: %d\n", router.size());
      fflush(stdout);
      last_time = time;
    }

    int mask = (1 << N_IFACE_ON_BOARD) - 1;
    macaddr_t src_mac;
    macaddr_t dst_mac;
    int if_index;
    res = HAL_ReceiveIPPacket(mask, packet, sizeof(packet), src_mac, dst_mac,
                              1000, &if_index);
    if (res == HAL_ERR_EOF) {
      break;
    } else if (res < 0) {
      return res;
    } else if (res == 0) {
      // Timeout
      continue;
    } else if (res > sizeof(packet)) {
      // packet is truncated, ignore it
      continue;
    }

    // 1. validate
    if (!validateIPChecksum(packet, res)) {
      printf("Invalid IP Checksum\n");
      continue;
    }
    in_addr_t src_addr, dst_addr;
    // extract src_addr and dst_addr from packet
    // big endian
    src_addr = *((uint32_t*) (packet + 12));
    dst_addr = *((uint32_t*) (packet + 16));
    // 2. check whether dst is me
    bool dst_is_me = false;
    for (int i = 0; i < N_IFACE_ON_BOARD; i++) {
      if (memcmp(&dst_addr, &addrs[i], sizeof(in_addr_t)) == 0) {
        dst_is_me = true;
        break;
      }
      
    }
    // TODO: Handle rip multicast address(224.0.0.9)?
    if (memcmp(&dst_addr, &multi_cast_addr, sizeof(in_addr_t)) == 0) {
      dst_is_me = true;
    }
    if (dst_is_me) {
      // 3a.1
      RipPacket rip;
      // check and validate
      if (disassemble(packet, res, &rip)) {
        if (rip.command == 1) {
          // 3a.3 request, ref. RFC2453 3.9.1
          // only need to respond to whole table requests in the lab
          RipPacket resp;
          fill_static_head();

          std::map<std::pair<int, int>, RoutingTableEntry>::iterator iter;

        //   iter = router.begin();
        // while (iter != router.end())
        // {
          
        //   if (iter->second.if_index != i)
        //     RoutingEntry2RipEntry(iter->second, rp.entries[pos++]);
        //   if (pos == 25) {
        //     rp.numEntries = pos;
        //     int len = assemble(&rp, output + 28);
        //     len += 28;
        //     fill_dymatic_head(len, addrs[i], multi_cast_addr);
        //     HAL_SendIPPacket(i, output, len, multi_cast_dst_mac);//???
        //     pos == 0;
        //   }
        //   iter++;
        // }
        // if (pos == 0) continue;

        // rp.numEntries = pos;
        // int len = assemble(&rp, output + 28);
        // len += 28;
        // //int length = 32 + 4 * 20;
        // fill_dymatic_head(len, addrs[i], multi_cast_addr);

        // HAL_SendIPPacket(i, output, len, multi_cast_dst_mac);//???

          iter = router.begin();

          
          RipPacket rp;
          // rp.numEntries = 3;
          rp.command = 2;
          int pos = 0;
          while (iter != router.end())
          {
            if (iter->second.if_index != if_index)
              RoutingEntry2RipEntry(iter->second, rp.entries[pos++]);
              if (pos == 25) {
                rp.numEntries = pos;
                int len = assemble(&rp, output + 28);
                len += 28;
                fill_dymatic_head(len, addrs[if_index], src_addr);
                HAL_SendIPPacket(if_index, output, len, src_mac);//???
                pos == 0;
              }
              iter++;
          }
          rp.numEntries = pos;
          int len = assemble(&rp, output + 28);
          len += 28;
          //int length = 32 + 4 * 20;
          fill_dymatic_head(len, addrs[if_index], src_addr);

          HAL_SendIPPacket(if_index, output, len, src_mac); //???
          
          //resp.
          // TODO: fill resp
          // assemble
          // IP
          // output[0] = 0x45;
          // ...
          // UDP
          // port = 520
          // output[20] = 0x02;
          // output[21] = 0x08;
          // ...
          // RIP
          // uint32_t rip_len = assemble(&resp, &output[20 + 8]);
          // checksum calculation for ip and udp
          // if you don't want to calculate udp checksum, set it to zero
          // send it back
          // HAL_SendIPPacket(if_index, output, rip_len + 20 + 8, src_mac);
        } else {
          //printf("--------in for\n");
          for (int i = 0; i < rip.numEntries; i++) {
            //uint32_t _next_hop, _if_index, _metric;
            
            RipEntry tmp = rip.entries[i];
            uint32_t metric_small = ntohl(tmp.metric) + 1;
            uint32_t riplen = mask2len(ntohl(tmp.mask));
            RoutingTableEntry result;
            if (query_exact(tmp.addr, riplen, result))
            {

              //RoutingTableEntry rte;
              //rte.addr = tmp.addr;
              // rte.if_index = if_index;
              // rte.len = mask2len(ntohl(tmp.mask));
              // rte.metric = ntohl(metric_small);
              // rte.nexthop = src_addr;

              // result.if_index = if_index;
              // result.metric = ntohl(metric_small);
              // result.nexthop = src_addr;
              // update(true, rte);
             // if (tmp.addr == (addrs[if_index] & 0x00ffffff))
             if (result.nexthop == 0)
                continue;
              if (metric_small > 16) {
            //reversing poison
                //update(false, result);
              } else if (metric_small < ntohl(result.metric) || if_index == result.if_index){
                result.if_index = if_index;
                result.metric = ntohl(metric_small);
                result.nexthop = src_addr;
                //update(true, result);--------------------------
              }
            } else if (metric_small <= 16) {
              RoutingTableEntry rte;
              rte.addr = tmp.addr;
              rte.if_index = if_index;
              rte.len = mask2len(ntohl(tmp.mask));
              rte.metric = ntohl(metric_small);
              rte.nexthop = src_addr;
              update(true, rte);
            }
          }
          //printf("--------out for\n");

          // 3a.2 response, ref. RFC2453 3.9.2
          // update routing table
          // new metric = ?
          // update metric, if_index, nexthop
          // what is missing from RoutingTableEntry?
          // TODO: use query and update
          // triggered updates? ref. RFC2453 3.10.1
        }
      } else {
        printf("--------------disassemble failed\n");
      }
    } else {
      // 3b.1 dst is not me
      // forward
      // beware of endianness
      uint32_t nexthop, dest_if, metric;
      if (query(dst_addr, &nexthop, &dest_if, &metric)) {
        // found
        macaddr_t dest_mac;
        // direct routing
        if (nexthop == 0) {
          nexthop = dst_addr;
        }
        if (HAL_ArpGetMacAddress(dest_if, nexthop, dest_mac) == 0) {
          // found
          memcpy(output, packet, res);
          // update ttl and checksum
          forward(output, res);
          // TODO: you might want to check ttl=0 case
          HAL_SendIPPacket(dest_if, output, res, dest_mac);
        } else {
          // not found
          // you can drop it
          printf("ARP not found for %x\n", nexthop);
        }
      } else {
        // not found
        // optionally you can send ICMP Host Unreachable
        // printf("IP not found for %x\n", dst_addr);
      }
    }
  }
  return 0;
}
