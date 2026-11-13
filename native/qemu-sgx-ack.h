

#pragma once
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

typedef struct {
    uint8_t state[4096];
    unsigned reads, writes, commands;
    uint64_t physical_base;
} NonUISgxCmdState;

static uint64_t nonui_sgx_cmd_read(void *opaque, uint64_t off, unsigned size) {
    NonUISgxCmdState *state = opaque;
    if (!size || size > 8 || off + size > sizeof(state->state))
        return 0;
    uint64_t result = 0;
    memcpy(&result, state->state + off, size);
    if (state->reads++ < 12)
        fprintf(stderr,
                "NonUI SGX diagnostic read: 0x%llx +0x%llx/%u -> 0x%llx\n",
                (unsigned long long)state->physical_base,
                (unsigned long long)off, size, (unsigned long long)result);
    return result;
}

static void nonui_sgx_cmd_write(void *opaque, uint64_t off, uint64_t value,
                                unsigned size) {
    NonUISgxCmdState *state = opaque;
    if (!size || size > 8 || off + size > sizeof(state->state))
        return;
    uint64_t result = value;
    if (off == 0 && size == 4 && (value & 0x10)) {
        result = value & ~0x10u;
        state->commands++;
    }
    memcpy(state->state + off, &result, size);
    if (state->writes++ < 12)
        fprintf(
            stderr,
            "NonUI SGX diagnostic write: 0x%llx +0x%llx/%u 0x%llx -> 0x%llx\n",
            (unsigned long long)state->physical_base, (unsigned long long)off,
            size, (unsigned long long)value, (unsigned long long)result);
}

static const NonUIQemuMemoryRegionOps nonui_sgx_ops = {
    .read = nonui_sgx_cmd_read,
    .write = nonui_sgx_cmd_write,
    .endianness = 0,
    .valid = {.min_access_size = 1, .max_access_size = 8, .unaligned = true},
    .impl = {.min_access_size = 1, .max_access_size = 8, .unaligned = true},
};

static int install_nonui_sgx_ack(const char *engine, void *anchor) {
    if (!getenv("NONUI_SGX_ACK"))
        return 0;
    void *(*get_system_memory)(void) =
        local_qemu_symbol(engine, anchor, "_get_system_memory");
    void (*init_io)(void *, void *, const NonUIQemuMemoryRegionOps *, void *,
                    const char *, uint64_t) =
        local_qemu_symbol(engine, anchor, "_memory_region_init_io");
    void (*add_overlap)(void *, uint64_t, void *, int) = local_qemu_symbol(
        engine, anchor, "_memory_region_add_subregion_overlap");
    if (!get_system_memory || !init_io || !add_overlap)
        return 70;

    const uint64_t bases[2] = {0x201001000ULL, 0x201E01000ULL};
    for (unsigned i = 0; i < 2; ++i) {
        void *region = calloc(1, 4096);
        NonUISgxCmdState *device = calloc(1, sizeof(*device));
        if (!region || !device)
            return 70;
        device->physical_base = bases[i];
        const char *name =
            i ? "nonui-sgx-secondary-cmd" : "nonui-sgx-primary-cmd";
        init_io(region, NULL, &nonui_sgx_ops, device, name, 0x1000);
        add_overlap(get_system_memory(), bases[i], region, 10);
        fprintf(stderr, "NonUI SGX diagnostic command register at 0x%llx\n",
                (unsigned long long)bases[i]);
    }
    if (getenv("NONUI_SGX_REVISION")) {

        NonUISgxCmdState *identity = calloc(1, sizeof(*identity));
        void *idregion = calloc(1, 4096);
        if (!identity || !idregion)
            return 70;
        identity->physical_base = 0x201000000ULL;
        const uint32_t original_accepted_id = 0x32010000u;
        memcpy(identity->state + 0x20, &original_accepted_id, 4);
        init_io(idregion, NULL, &nonui_sgx_ops, identity,
                "nonui-sgx-diagnostic-hardware-identity", 0x1000);
        add_overlap(get_system_memory(), 0x201000000ULL, idregion, 10);
        fprintf(stderr,
                "NonUI SGX diagnostic G3_B0 identity 0x%x at 0x201000020\n",
                original_accepted_id);
    }
    return 0;
}
