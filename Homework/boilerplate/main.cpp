#include "router_hal.h"
#include "rip.h"
#include "router.h"
#include <stdint.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <list>

#define BROADCAST_ADDR 0x090000e0
typedef std::list<RoutingTableEntry> ROUTINGLIST;
extern ROUTINGLIST RoutingList;

extern bool validateIPChecksum(uint8_t *packet, size_t len);
extern uint16_t calculateIPChecksum(uint8_t *packet, size_t len);
extern void update(bool insert, RoutingTableEntry entry);
extern bool query(uint32_t addr, uint32_t *nexthop, uint32_t *if_index);
extern bool query(uint32_t addr, uint32_t *nexthop, uint32_t *if_index, uint32_t *metric);
extern bool forward(uint8_t *packet, size_t len);
extern bool disassemble(const uint8_t *packet, uint32_t len, RipPacket *output);
extern uint32_t assemble(const RipPacket *rip, uint8_t *buffer);

bool isMatch(uint32_t addr, uint32_t len, uint32_t target)
{
  for (int i = 0; i < len; i++)
  {
    if ((addr & (1 << i)) != (target & (1 << i)))
    {
      return false;
      //printf("not found in %d",i);
    }
  }
  //printf("found!");
  return true;
}

uint8_t packet[2048];
uint8_t output[2048];
// 0: 192.168.3.2
// 1: 10.0.1.1
// 2: 10.0.2.1
// 3: 10.0.3.1
// 你可以按需进行修改，注意端序
in_addr_t addrs[N_IFACE_ON_BOARD] = {0x0203a8c0, 0x0104a8c0, 0x0102000a, 0x0103000a};

int main(int argc, char *argv[])
{
  int res = HAL_Init(1, addrs);
  if (res < 0)
  {
    return res;
  }

  // Add direct routes
  // For example:
  // 10.0.0.0/24 if 0
  // 10.0.1.0/24 if 1
  // 10.0.2.0/24 if 2
  // 10.0.3.0/24 if 3
  for (uint32_t i = 0; i < N_IFACE_ON_BOARD; i++)
  {
    RoutingTableEntry entry = {
        .addr = addrs[i], // big endian
        .len = 24,        // small endian
        .if_index = i,    // small endian
        .nexthop = 0,     // big endian, means direct
        .metric = 0};
    update(true, entry);
  }

  uint64_t last_time = 0;
  while (1)
  {
    uint64_t time = HAL_GetTicks();
    if (time > last_time + 30 * 1000)
    {
      // What to do? send Rip Response.
      printf("Timer\n");
      RipPacket *pkg2send = new RipPacket();
      pkg2send->command = 2;
      pkg2send->numEntries = 0;
      for (uint32_t i = 0; i < N_IFACE_ON_BOARD; i++)
      {
        for (auto it = RoutingList.begin(); it != RoutingList.end(); it++)
        {
          if (pkg2send->numEntries == 25)
          {
            uint32_t len = assemble(pkg2send, &output[28]);
            len = writeIpUdpHead(output, len, addrs[i], BROADCAST_ADDR);
            macaddr_t broadcast_macaddr;
            HAL_ArpGetMacAddress(i, BROADCAST_ADDR, broadcast_macaddr);
            HAL_SendIPPacket(i, output, len, broadcast_macaddr);
            pkg2send->numEntries = 0;
          }
          RipEntry *insert = RoutingEntry2RipEntry(*it);
          if (insert->addr == addrs[i])
          {
            continue;
          }
          if (isMatch(insert->addr, (*it).len, addrs[i]))
          {
            continue;
          }
          // poison reverse
          if (isMatch(insert->nexthop, (*it).len, addrs[i]))
          {
            insert->metric = 16;
          }
          pkg2send->entries[pkg2send->numEntries++] = *insert;
        }
        uint32_t len = assemble(pkg2send, &output[28]);
        len = writeIpUdpHead(output, len, addrs[i], BROADCAST_ADDR);
        macaddr_t broadcast_macaddr;
        HAL_ArpGetMacAddress(i, BROADCAST_ADDR, broadcast_macaddr);
        HAL_SendIPPacket(i, output, len, broadcast_macaddr);
        pkg2send->numEntries = 0;
      }
    }

    int mask = (1 << N_IFACE_ON_BOARD) - 1;
    macaddr_t src_mac;
    macaddr_t dst_mac;
    int if_index;
    res = HAL_ReceiveIPPacket(mask, packet, sizeof(packet), src_mac,
                              dst_mac, 1000, &if_index);
    if (res == HAL_ERR_EOF)
    {
      break;
    }
    else if (res < 0)
    {
      return res;
    }
    else if (res == 0)
    {
      // Timeout
      continue;
    }
    else if (res > sizeof(packet))
    {
      // packet is truncated, ignore it
      continue;
    }

    if (!validateIPChecksum(packet, res))
    {
      printf("Invalid IP Checksum\n");
      continue;
    }
    in_addr_t src_addr, dst_addr;
    // extract src_addr and dst_addr from packet
    // big endian
    src_addr = 

    bool dst_is_me = false;
    for (int i = 0; i < N_IFACE_ON_BOARD; i++)
    {
      if (memcmp(&dst_addr, &addrs[i], sizeof(in_addr_t)) == 0)
      {
        dst_is_me = true;
        break;
      }
    }
    // TODO: Handle rip multicast address?

    if (dst_is_me)
    {
      // TODO: RIP?
      RipPacket rip;
      if (disassemble(packet, res, &rip))
      {
        if (rip.command == 1)
        {
          // request
          RipPacket *pkg2send = new RipPacket();
          pkg2send->numEntries = 0;
          pkg2send->command = 2;
          for (auto it = RoutingList.begin(); it != RoutingList.end(); it++)
          {
            if (pkg2send->numEntries == 25)
            {
              uint32_t len = assemble(pkg2send, &output[28]);
              len = writeIpUdpHead(output, len, dst_addr, src_addr);
              HAL_SendIPPacket(if_index, output, len, src_mac);
              pkg2send->numEntries = 0;
            }
            RipEntry *insert = RoutingEntry2RipEntry(*it);
            if (insert->addr == src_addr)
            {
              continue;
            }
            if (isMatch(insert->addr, (*it).len, src_addr))
            {
              continue;
            }
            // poison reverse
            if (isMatch(insert->nexthop, (*it).len, src_addr))
            {
              insert->metric = 16;
            }
            pkg2send->entries[pkg2send->numEntries++] = *insert;
          }
          uint32_t len = assemble(pkg2send, &output[28]);
          len = writeIpUdpHead(output, len, dst_addr, src_addr);
          HAL_SendIPPacket(if_index, output, len, src_mac);
          pkg2send->numEntries = 0;
        }
        else
        {
          // response
          // TODO: use query and update
          uint32_t nexthop1;
          uint32_t if_index1;
          uint32_t metric1;
          for(int i = 0;i<rip.numEntries;i++) {
            if(query(rip.entries[i].addr, &nexthop1, &if_index1,&metric1)) {
              if(rip.entries[i].metric + 1 <= metric1) {
                rip.entries[i].metric += 1;
                update(false, *RipEntry2RoutingTableEntry((rip.entries[i])));
              } else if (rip.entries[i].metric + 1 > 16) {

              }
            }
          }
        }
      }
    }
    else
    {
      // forward
      // beware of endianness
      uint32_t nexthop, dest_if;
      if (query(dst_addr, &nexthop, &dest_if))
      {
        // found
        macaddr_t dest_mac;
        // direct routing
        if (nexthop == 0)
        {
          nexthop = dst_addr;
        }
        if (HAL_ArpGetMacAddress(dest_if, nexthop, dest_mac) == 0)
        {
          // found
          memcpy(output, packet, res);
          // update ttl and checksum
          forward(output, res);
          // TODO: you might want to check ttl=0 case
          HAL_SendIPPacket(dest_if, output, res, dest_mac);
        }
        else
        {
          // not found
        }
      }
      else
      {
        // not found
      }
    }
  }
  return 0;
}

RoutingTableEntry *RipEntry2RoutingTableEntry(RipEntry in) {
  RoutingTableEntry *rentry = new RoutingTableEntry();
  rentry->addr = in.addr;
  rentry->len = mask2len(in.mask);
  rentry->metric = in.metric;
  rentry->nexthop = in.nexthop;
  return rentry;
}

RipEntry *RoutingEntry2RipEntry(RoutingTableEntry in)
{
  RipEntry *rentry = new RipEntry();
  rentry->addr = in.addr;
  rentry->mask = len2mask(in.len);
  rentry->metric = in.metric;
  rentry->nexthop = in.nexthop;
  return rentry;
}

uint32_t mask2len(uint32_t mask)
{
  int i = 0;
  for (; i < 32; i++)
  {
    if ((mask & (1 << i)) == 0)
    {
      break;
    }
  }
  return 32 - i;
}

uint32_t len2mask(uint32_t len)
{
  uint32_t mask = 0;
  int i = len;
  for (; i > 0; i--)
  {
    mask |= (1 << (31 - i));
  }
  return mask;
}

uint32_t writeIpUdpHead(uint8_t *buffer, uint32_t body_len, uint32_t src_addr, uint32_t dst_addr)
{
  /**
   * 代码中在发送 RIP 包的时候，会涉及到 IP 头的构造，由于不需要用各种高级特性，
   * 可以这么设定：V=4，IHL=5，TOS(DSCP/ECN)=0，ID=0，FLAGS/OFF=0，
   * TTL=1，其余按照要求实现即可。
   */
  uint16_t tot_len = body_len + 20 + 8; // 20 for ip, 8 for udp
  buffer[0] = 0x45;
  buffer[1] = 0xC0;
  buffer[2] = (uint8_t)(tot_len >> 8), buffer[3] = (uint8_t)tot_len; // total length
  buffer[4] = 0, buffer[5] = 0;                                      // identification
  buffer[6] = 0x40, buffer[7] = 0;                                   // fragment
  buffer[8] = 1;                                                     // TTL
  buffer[9] = 0x11;                                                  // protocol: udp
  // buffer[10], buffer[11]: checksum
  memcpy(&buffer[12], &src_addr, sizeof(src_addr)); // src ip
  memcpy(&buffer[16], &dst_addr, sizeof(dst_addr)); // dst_ip
  uint16_t checksum = calculateIPChecksum(buffer, 20);
  buffer[10] = (uint8_t)(checksum >> 8), buffer[11] = (uint8_t)checksum; // checksum
  // UDP
  // port = 520
  buffer[20] = 0x02;
  buffer[21] = 0x08;
  return tot_len;
}
