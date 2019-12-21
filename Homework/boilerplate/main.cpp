#include "rip.h"
#include "router.h"
#include "router_hal.h"
#include <arpa/inet.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <iostream>

extern bool validateIPChecksum(uint8_t *packet, size_t len);
extern void update(bool insert, RoutingTableEntry entry);
extern bool query(uint32_t addr, uint32_t *nexthop, uint32_t *if_index, uint32_t* metric);
extern bool if_exist(uint32_t addr, uint32_t len, uint32_t *nexthop, uint32_t *if_index, uint32_t* metric);
extern bool forward(uint8_t *packet, size_t len);
extern bool disassemble(const uint8_t *packet, uint32_t len, RipPacket *output);
extern uint32_t assemble(const RipPacket *rip, uint8_t *buffer);

extern RoutingTableEntry table[200];
extern bool hasEntry[200];
extern int top;

uint8_t packet[2048];
uint8_t output[2048];
// 0: 10.0.0.1
// 1: 10.0.1.1
// 2: 10.0.2.1
// 3: 10.0.3.1
// 你可以按需进行修改，注意端序
in_addr_t addrs[N_IFACE_ON_BOARD] = {0x0107a8c0, 0x0205a8c0, 0x0106a8c0,
                                     0x0103000a};
in_addr_t multi_addr = 0x090000e0;
macaddr_t multi_mac = {0x01, 0x00, 0x5e, 0x00, 0x00, 0x09}; //01 : 00 : 5e : 00 : 00 : 09

void print_addr(uint32_t addr) {
    uint32_t temp = ntohl(addr);
    std::cout << ((temp & 0xff000000) >> 24) << "."
              << ((temp & 0x00ff0000) >> 16) << "."
              << ((temp & 0x0000ff00) >> 8) << "." << ((temp & 0x000000ff));
}

void print_table() {
  std::cout << "*****************************" << std::endl;
  for (int i = 0; i < top; ++i) {
    if (hasEntry[i]) {
      if (table[i].nexthop == 0) {
        print_addr(table[i].addr);
        std::cout << "/" << table[i].len << " " 
                  << table[i].if_index << " " 
                  << "scope link metric " << table[i].metric << std::endl; 
      }
      else {
        print_addr(table[i].addr);
        std::cout << " via ";
        print_addr(table[i].nexthop); 
        std::cout << " dev " << table[i].if_index << " " << "metric " << table[i].metric << std::endl;
      }
    }
  }
  std::cout << "*****************************" << std::endl;
}

size_t build_rip_packet(in_addr_t src_addr, in_addr_t dst_addr, RipPacket *rip_packet) {
    // rip
    uint32_t rip_len = assemble(rip_packet, &output[20 + 8]);

    // IP
    // version & length
    uint8_t *ip_head_8 = output;
    uint16_t *ip_head_16 = (uint16_t *)output;
    uint32_t *ip_head_32 = (uint32_t *)output;
    ip_head_8[0] = 0x45;
    // tos
    ip_head_8[1] = 0x00;
    // total length
    ip_head_16[1] = htons(rip_len + 20 + 8);
    
    // ID
    ip_head_16[2] = 0x0000;
    // flags / offset
    ip_head_16[3] = 0x0000;
    // ttl
    ip_head_8[8] = 0x01;
    // version: udp(17)
    ip_head_8[9] = 0x11;
    // checksum
    ip_head_16[5] = 0x0000;
    // src
    ip_head_32[3] = src_addr;
    // dst
    ip_head_32[4] = dst_addr;
    // calculate checksum
    uint32_t check_sum = 0;
    uint16_t *p = ip_head_16;
    for (int i = 0; i < 10; ++i, ++p) {
        check_sum += *p;
    }
    while (check_sum >> 16) {
        uint32_t high = (check_sum >> 16);
        check_sum &= 0xffff;
        check_sum += high;
    }
    ip_head_16[5] = ((uint16_t)(~check_sum));

    // UDP
    uint8_t *udp_head_8 = output + 20;
    uint16_t *udp_head_16 = (uint16_t *)(output + 20);
    uint32_t *udp_head_32 = (uint32_t *)(output + 20);
    // src port
    udp_head_16[0] = htons(0x0208);
    // dst port
    udp_head_16[1] = htons(0x0208);
    // length
    udp_head_16[2] = htons(rip_len + 8);
    ;
    // checksum
    udp_head_16[3] = 0x0000;

    return rip_len + 20 + 8;
}

uint32_t len2mask(uint32_t len) { return 0xffffffff << (32 - len); }

uint32_t mask2len(uint32_t mask) {
    int len = 0;
    while (0x80000000 & mask) {
        mask <<= 1;
        len++;
    }
    return len;
}

void fill_resp(RipPacket* rip_packet, uint32_t if_index) {
    int entry_num = 0;
    for (int i = 0; i < top; ++i) {
        if (hasEntry[i]) {
          if (if_index != table[i].if_index) {
            //水平分割
              // print_addr(table[i].addr);
              // std::cout << std::endl;
              // std::cout << table[i].len << std::endl;
              // print_addr(len2mask(table[i].len));
              // std::cout << std::endl;
              rip_packet->entries[entry_num].addr = table[i].addr;
              rip_packet->entries[entry_num].mask = htonl(len2mask(table[i].len));
              rip_packet->entries[entry_num].metric = htonl(table[i].metric);
              rip_packet->entries[entry_num].nexthop = table[i].nexthop;
              entry_num++;
          }
        }
    }
    rip_packet->command = 0x2;  // response
    rip_packet->numEntries = entry_num;
}

bool in_same_sub_net(uint32_t addr, uint32_t more_addr, uint32_t len) {
  uint32_t addr_l = ntohl(addr);
  uint32_t more_addr_l = ntohl(more_addr_l);
  uint32_t temp = addr_l ^ more_addr_l;
  if ((temp >> (32 - len))) {
    return false;
  }
  return true;
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
        .metric = 1,      //small endian
        .timestemp = 0,   //small endian
    };
    update(true, entry);
  }
  std::cout << "Routing Table Init" << std::endl;
  print_table();

  uint64_t last_time = 0;
  while (1) {
    uint64_t time = HAL_GetTicks();
    if (time > last_time + 5 * 1000) {
      // What to do?
      // send complete routing table to every interface
      // ref. RFC2453 3.8
      // multicast MAC for 224.0.0.9 is 01:00:5e:00:00:09

      //build rip packet
      RipPacket rip_packet;
      for (int index = 0; index < N_IFACE_ON_BOARD; ++index) {
        fill_resp(&rip_packet, index);
        size_t length = build_rip_packet(addrs[index], multi_addr, &rip_packet);
        HAL_SendIPPacket(index, output, length, multi_mac);
      }
      print_table();
      printf("5s Timer\n");
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

    uint8_t* ip_head_8 = packet;
    uint16_t* ip_head_16 = (uint16_t*)packet;
    uint32_t* ip_head_32 = (uint32_t*)packet;
    in_addr_t src_addr, dst_addr;
    // extract src_addr and dst_addr from packet
    // big endian
    src_addr = ip_head_32[3];
    dst_addr = ip_head_32[4];

    // 2. check whether dst is me
    bool dst_is_me = false;
    for (int i = 0; i < N_IFACE_ON_BOARD; i++) {
      if (memcmp(&dst_addr, &addrs[i], sizeof(in_addr_t)) == 0) {
        dst_is_me = true;
        break;
      }
    }
    // TODO: Handle rip multicast address(224.0.0.9)?
    if (memcmp(&dst_addr, &multi_addr, sizeof(in_addr_t)) == 0) {
      dst_is_me = true;
    }

    if (dst_is_me) {
      // 3a.1
      RipPacket rip;
      // check and validate
      if (disassemble(packet, res, &rip)) {
        if (rip.command == 1) {
          // 3a.3 request, ref. RFC2453 Section 3.9.1
          // only need to respond to whole table requests in the lab

          RipPacket resp;
          // TODO: fill resp
          fill_resp(&resp, if_index);
          // int entry_num = 0;
          // for (int i = 0; i < top; ++i) {
          //     if (hasEntry[i]) {
          //       if (!in_same_sub_net(src_addr, table[i].addr, table[i].len)) {
          //         resp.entries[entry_num].addr = table[i].addr;
          //         resp.entries[entry_num].mask = htonl(len2mask(table[i].len));
          //         resp.entries[entry_num].metric = htonl(table[i].metric);
          //         resp.entries[entry_num].nexthop = table[i].nexthop;
          //         entry_num++;
          //       }
          //     }
          // }
          // resp.command = 0x2;  // response
          // resp.numEntries = entry_num;

          size_t length = build_rip_packet(dst_addr, src_addr, &resp);
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
          HAL_SendIPPacket(if_index, output, length, src_mac);
        } else {
          // 3a.2 response, ref. RFC2453 3.9.2
          for (int i = 0; i < rip.numEntries; ++i) {
            int new_metric = htonl(rip.entries[i].metric) + 1;
            RoutingTableEntry route_entry = {
              .addr = rip.entries[i].addr,
              .len = mask2len(htonl(rip.entries[i].mask)),
              //next hop is where the response comes from
              .if_index = if_index,
              .nexthop = src_addr,
              .metric = new_metric,
              .timestemp = 0,
            };
            // std::cout << "receive response" << std::endl;
            // print_addr(rip.entries[i].addr);
            // std::cout << " metric: " << new_metric << std::endl;
            if (new_metric > 16) {
              //meric 较大
              //delete this route
              uint32_t route_nexthop, route_if_index, route_metric;
              if (if_exist(rip.entries[i].addr, mask2len(ntohl(rip.entries[i].mask)), &route_nexthop, &route_if_index, &route_metric)) {
                //路由存在
                if ((route_if_index == if_index) && (route_nexthop != 0)) {
                  //同一网口且不是直连路由
                  std::cout << "Routing Table Delete Entry" << std::endl;
                  update(false, route_entry);
                  // print_table();
                }
              }
              //didn't send the invalid packet
            }
            else {
              //meric 没有超过16
              uint32_t route_nexthop, route_if_index, route_metric;
              // std::cout << "may be update" << std::endl;
              if (query(rip.entries[i].addr, &route_nexthop, &route_if_index, &route_metric)) {
                //路由存在
                if (route_if_index == if_index) {
                    //同一网口则不管新路由好坏都更新
                    std::cout << "Routing Table Update Entry" << std::endl;
                    update(true, route_entry);
                    // print_table();
                }
                else {
                    if (new_metric <= route_metric) {
                        //如果不是同一网口则只有好路由才更新
                        std::cout << "Routing Table Update Entry" << std::endl;
                        update(true, route_entry);
                        // print_table();
                    }
                }
              }
              else {
                //no route
                std::cout << "Routing Table Insert Entry" << std::endl;
                update(true, route_entry);
                // print_table();
              }
            }
          }
          // update routing table
          // new metric = ?
          // update metric, if_index, nexthop
          // HINT: handle nexthop = 0 case
          // HINT: what is missing from RoutingTableEntry?
          // you might want to use `query` and `update` but beware of the difference between exact match and longest prefix match
          // optional: triggered updates? ref. RFC2453 3.10.1
        }
      }
      else {
        std::cout << "valid failed" << std::endl; 
      }
    } else {
      // std::cout << "forward" << std::endl;
      // 3b.1 dst is not me
      // forward
      // beware of endianness
      uint32_t nexthop, dest_if, metric;
      if (query(dst_addr, &nexthop, &dest_if, &metric)) {
        // found
        std::cout << "Forward ";
        print_addr(nexthop);
        std::cout << " dest_if: " << dest_if << std::endl;
        macaddr_t dest_mac;
        // direct routing
        if (nexthop == 0) {
          nexthop = dst_addr;
        }
        if (HAL_ArpGetMacAddress(dest_if, nexthop, dest_mac) == 0) {
          // found
          // std::cout << "found mac" << std::endl;
          memcpy(output, packet, res);
          // update ttl and checksum
          forward(output, res);
          // TODO(optional): check ttl=0 case
          HAL_SendIPPacket(dest_if, output, res, dest_mac);
        } else {
          // not found
          // you can drop it
          printf("ARP not found for nexthop %x\n", nexthop);
        }
      } else {
        // not found
        // TODO(optional): send ICMP Host Unreachable
        printf("IP not found for src %x dst %x\n", src_addr, dst_addr);
      }
    }
  }
  return 0;
}
