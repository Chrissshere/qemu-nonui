

#pragma once

#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

typedef struct {
    uint64_t (*read)(void *opaque, uint64_t offset, unsigned size);
    void (*write)(void *opaque, uint64_t offset, uint64_t value, unsigned size);
    void *read_with_attrs;
    void *write_with_attrs;
    int endianness;
    struct {
        unsigned min_access_size;
        unsigned max_access_size;
        bool unaligned;
        void *accepts;
    } valid;
    struct {
        unsigned min_access_size;
        unsigned max_access_size;
        bool unaligned;
    } impl;
} NonUIQemuMemoryRegionOps;

typedef struct {
    uint8_t register_bytes[4096];
    unsigned reads, writes, acknowledgments;
} NonUIPmgrAck;

static uint64_t nonui_pmgr_read(void *opaque, uint64_t off, unsigned size) {
    NonUIPmgrAck *pmgr = (NonUIPmgrAck *)opaque;
    if (size == 0 || size > 8 || off + size > sizeof(pmgr->register_bytes)) {
        return 0;
    }
    uint64_t value = 0;
    memcpy(&value, pmgr->register_bytes + off, size);
    if (pmgr->reads++ < 12) {
        fprintf(stderr, "NonUI PMGR diagnostic read: +0x%llx /%u -> 0x%llx\n",
                (unsigned long long)off, size, (unsigned long long)value);
    }
    return value;
}

static void nonui_pmgr_write(void *opaque, uint64_t off, uint64_t value,
                             unsigned size) {
    NonUIPmgrAck *pmgr = (NonUIPmgrAck *)opaque;
    if (size == 0 || size > 8 || off + size > sizeof(pmgr->register_bytes)) {
        return;
    }

    if (off < 0x400 && (off & 7) == 0 && size == 4) {
        uint32_t requested = (uint32_t)value;
        value = (requested & ~0xF0u) | ((requested & 0xFu) << 4);
        pmgr->acknowledgments++;
    }
    memcpy(pmgr->register_bytes + off, &value, size);
    if (pmgr->writes++ < 12) {
        fprintf(stderr, "NonUI PMGR diagnostic write: +0x%llx /%u -> 0x%llx\n",
                (unsigned long long)off, size, (unsigned long long)value);
    }
}

static const NonUIQemuMemoryRegionOps nonui_pmgr_ops = {
    .read = nonui_pmgr_read,
    .write = nonui_pmgr_write,
    .endianness = 0,
    .valid = {.min_access_size = 1, .max_access_size = 8, .unaligned = true},
    .impl = {.min_access_size = 1, .max_access_size = 8, .unaligned = true},
};

static int install_nonui_pmgr_ack(const char *engine, void *anchor) {
    if (!getenv("NONUI_PMGR_ACK")) {
        return 0;
    }
    void *(*get_system_memory)(void) =
        local_qemu_symbol(engine, anchor, "_get_system_memory");
    void (*init_io)(void *, void *, const NonUIQemuMemoryRegionOps *, void *,
                    const char *, uint64_t) =
        local_qemu_symbol(engine, anchor, "_memory_region_init_io");
    void (*add_overlap)(void *, uint64_t, void *, int) = local_qemu_symbol(
        engine, anchor, "_memory_region_add_subregion_overlap");
    if (!get_system_memory || !init_io || !add_overlap) {
        fputs("NonUI PMGR: QEMU MMIO callback API not available\n", stderr);
        return 70;
    }
    void *region = calloc(1, 4096);
    NonUIPmgrAck *device = calloc(1, sizeof(*device));
    if (!region || !device)
        return 70;
    init_io(region, NULL, &nonui_pmgr_ops, device,
            "nonui-pmgr-single-domain-ack-diagnostic", 0x1000);
    add_overlap(get_system_memory(), 0x20E020000ULL, region, 10);
    fputs("NonUI PMGR diagnostic register-ack bridge enabled at 0x20e020000\n",
          stderr);
    return 0;
}
