

#pragma once
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

typedef struct {
    uint32_t regs[1024];
    unsigned reads, writes;
} NonUIAdbe0Timing;

static uint64_t nonui_adbe0_timing_read(void *opaque, uint64_t off,
                                        unsigned size) {
    NonUIAdbe0Timing *dev = opaque;
    if (size != 4 || off >= 4096 || (off & 3))
        return 0;
    uint32_t result = dev->regs[off / 4];
    if (dev->reads++ < 32)
        fprintf(stderr, "NonUI ADBE0 timing read +0x%llx -> 0x%x\n",
                (unsigned long long)off, result);
    return result;
}

static void nonui_adbe0_timing_write(void *opaque, uint64_t off, uint64_t value,
                                     unsigned size) {
    NonUIAdbe0Timing *dev = opaque;
    if (size != 4 || off >= 4096 || (off & 3))
        return;
    uint32_t result = (uint32_t)value;
    if (off == 4) {
        result = (result & ~0x8001u) | (result >> 31);
    }
    dev->regs[off / 4] = result;
    if (dev->writes++ < 48)
        fprintf(stderr, "NonUI ADBE0 timing write +0x%llx 0x%llx -> 0x%x\n",
                (unsigned long long)off, (unsigned long long)value, result);
}

#ifndef NONUI_ADBE0_TIMING_TEST
static void nonui_adbe0_timing_mmio_write(void *opaque, uint64_t off,
                                          uint64_t value, unsigned size) {
    nonui_adbe0_timing_write(opaque, off, value, size);
}

static const NonUIQemuMemoryRegionOps nonui_adbe0_timing_ops = {
    .read = nonui_adbe0_timing_read,
    .write = nonui_adbe0_timing_mmio_write,
    .endianness = 0,
    .valid = {.min_access_size = 4, .max_access_size = 4},
    .impl = {.min_access_size = 4, .max_access_size = 4},
};

static int install_nonui_adbe0_timing(const char *engine, void *anchor) {
    if (!getenv("NONUI_ADBE0_TIMING_ACK"))
        return 0;
    void *(*system_memory)(void) =
        local_qemu_symbol(engine, anchor, "_get_system_memory");
    void (*init_io)(void *, void *, const NonUIQemuMemoryRegionOps *, void *,
                    const char *, uint64_t) =
        local_qemu_symbol(engine, anchor, "_memory_region_init_io");
    void (*overlap)(void *, uint64_t, void *, int) = local_qemu_symbol(
        engine, anchor, "_memory_region_add_subregion_overlap");
    if (!system_memory || !init_io || !overlap)
        return 70;
    void *region = calloc(1, 4096);
    NonUIAdbe0Timing *dev = calloc(1, sizeof(*dev));
    if (!region || !dev)
        return 70;
    init_io(region, NULL, &nonui_adbe0_timing_ops, dev,
            "nonui-h6-adbe0-timing-ack-partial", 4096);
    overlap(system_memory(), 0x206300000ULL, region, 10);
    fputs("NonUI partial H6 ADBE0 timing handshake at 0x206300000\n", stderr);
    return 0;
}
#endif
