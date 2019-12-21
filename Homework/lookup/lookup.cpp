#include <arpa/inet.h>
#include <stdint.h>
#include <stdlib.h>
#include <stdio.h>
#include <map>
#include <utility>
#include <iostream>
#include "router.h"

/*
  RoutingTable Entry 的定义如下：
  typedef struct {
    uint32_t addr; // 大端序，IPv4 地址
    uint32_t len; // 小端序，前缀长度
    uint32_t if_index; // 小端序，出端口编号
    uint32_t nexthop; // 大端序，下一跳的 IPv4 地址
  } RoutingTableEntry;

  约定 addr 和 nexthop 以 **大端序** 存储。
  这意味着 1.2.3.4 对应 0x04030201 而不是 0x01020304。
  保证 addr 仅最低 len 位可能出现非零。
  当 nexthop 为零时这是一条直连路由。
  你可以在全局变量中把路由表以一定的数据结构格式保存下来。
*/

MapTable map_table;
RoutingTableEntry table[6000];
int top = 0;
bool hasEntry[6000];

/**
 * @brief 插入/删除一条路由表表项
 * @param insert 如果要插入则为 true ，要删除则为 false
 * @param entry 要插入/删除的表项
 * 
 * 插入时如果已经存在一条 addr 和 len 都相同的表项，则替换掉原有的。
 * 删除时按照 addr 和 len 匹配。
 */

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

void print_table2() {
  std::cout << "*****************************" << std::endl;
  for (MapTable::iterator it = map_table.begin(); it != map_table.end(); ++it) {
    RoutingTableEntry entry = it->second;
    if (entry.nexthop == 0) {
      print_addr(entry.addr);
      std::cout << "/" << entry.len << " " 
                << entry.if_index << " " 
                << "scope link metric " << entry.metric << std::endl; 
    }
    else {
      print_addr(entry.addr);
      std::cout << " via ";
      print_addr(entry.nexthop); 
      std::cout << " dev " << entry.if_index << " " << "metric " << entry.metric << std::endl;
    }
  }
  std::cout << "*****************************" << std::endl;
}


void update(bool insert, RoutingTableEntry &entry) {
  // TODO:
  if (insert) {
    for (int i = 0 ; i < top; ++i) {
      if (hasEntry[i]) {
        if ((entry.addr == table[i].addr) && (entry.len == table[i].len)) {
          table[i] = entry;
          return;
        }
      }
    }
    table[top] = entry;
    hasEntry[top] = true;
    ++top;
  }
  else {
    for (int i = 0; i < top; ++i) {
      if (hasEntry[i]) {
        if ((entry.addr == table[i].addr) && (entry.len == table[i].len)) {
          hasEntry[i] = 0;
          return;
        }
      }
    }
  }
}

void update_2(bool insert, RoutingTableEntry &entry) {
  if (insert) {
    map_table[Key(ntohl(entry.addr), entry.len)] = entry;
  }
}

/**
 * @brief 进行一次路由表的查询，按照最长前缀匹配原则
 * @param addr 需要查询的目标地址，大端序
 * @param nexthop 如果查询到目标，把表项的 nexthop 写入
 * @param if_index 如果查询到目标，把表项的 if_index 写入
 * @return 查到则返回 true ，没查到则返回 false
 */
bool query(uint32_t addr, uint32_t *nexthop, uint32_t *if_index, uint32_t *metric) {
  // TODO:
  uint32_t max_len = 0;
  bool found = false;
  for (int i = 0; i < top; ++i) {
    if (hasEntry[i]) {
      uint32_t addr_l = ntohl(addr);
      uint32_t table_addr_l = ntohl(table[i].addr);
      uint32_t temp = addr_l ^ table_addr_l;
      if (!(temp >> (32 - table[i].len))) {
        if (table[i].len > max_len) {
            *nexthop = table[i].nexthop;
            *if_index = table[i].if_index;
            *metric = table[i].metric;
            max_len = table[i].len;
            found = true;
        }
      }
    }
  }
  if (found) {
    return true;
  }
  return false;
}

bool query2(uint32_t addr, uint32_t *nexthop, uint32_t *if_index, uint32_t *metric) {
  uint32_t addr_h = ntohl(addr);
  uint32_t mask_h = 0xffffffff;
  uint32_t len = 32;
  while (len >= 0) {
    uint32_t tmp = addr_h & mask_h;
    MapTable::iterator iter = map_table.find(Key(tmp, len));
    if (iter != map_table.end()) {
      *nexthop = iter->second.nexthop;
      *if_index = iter->second.if_index;
      *metric = iter->second.metric;
      return true;
    }
  }
  return false;
}


bool if_exist(uint32_t addr, uint32_t len, uint32_t *nexthop, uint32_t *if_index, uint32_t *metric) {
    // TODO:
    for (int i = 0; i < top; ++i) {
      if (hasEntry[i]) {
        if ((addr == table[i].addr) && (len == table[i].len)) {
          return true;
        }
      }
    }
    return false;
}

bool if_exist2(uint32_t addr, uint32_t len, uint32_t *nexthop, uint32_t *if_index, uint32_t *metric) {
  if (map_table.count(Key(ntohl(addr), len)) > 0) {
    return true;
  }
  return false;
}