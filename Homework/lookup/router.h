#include <stdint.h>
#include <utility>
#include <map>

// 路由表的一项
typedef struct {
    uint32_t addr; // 地址
    uint32_t len; // 前缀长度
    uint32_t if_index; // 出端口编号
    uint32_t nexthop; // 下一条的地址，0 表示直连
    uint32_t metric;
    uint32_t timestemp;
    // 为了实现 RIP 协议，需要在这里添加额外的字段
} RoutingTableEntry;

typedef std::pair<uint32_t, uint32_t> Key;
typedef std::map<Key, RoutingTableEntry> MapTable;