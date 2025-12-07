#include "mem.h"

GPtrArray *mmio_ranges = NULL;
GPtrArray *ram_ranges = NULL;


bool range_contain_addr(GPtrArray *ranges, uint32_t addr) {
    for (guint i = 0; i < ranges->len; i++) {
        MemRange *r = g_ptr_array_index(ranges, i);
        if (addr >= r->start && addr < r->end) {
            return true; 
        }
    }
    return false;
}

