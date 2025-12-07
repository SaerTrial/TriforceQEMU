
#ifndef MMIO_MEM_H
#define MMIO_MEM_H
#include "qemu/osdep.h"


extern GPtrArray *mmio_ranges;
extern GPtrArray *ram_ranges;



typedef struct MemRange {
    uint32_t start;
    uint32_t end;   // end is exclusive: [start, end)
} MemRange;

bool range_contain_addr(GPtrArray *ranges, uint32_t addr);

#endif