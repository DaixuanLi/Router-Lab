#include <stdint.h>

// 路由表的一项
typedef struct {
    uint32_t addr;
    uint32_t len;
    uint32_t if_index;
    uint32_t nexthop;
    uint32_t metric;
} RoutingTableEntry;