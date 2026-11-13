

#pragma once
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>

typedef struct {
    uint32_t configuration;
} NonUIButtonPad;

static uint64_t nonui_button_pad_read(void *opaque, uint64_t off,
                                      unsigned size) {
    if (off || size != 4)
        return 0;
    return ((NonUIButtonPad *)opaque)->configuration | 1u;
}

static void nonui_button_pad_write(void *opaque, uint64_t off, uint64_t value,
                                   unsigned size) {
    if (off || size != 4)
        return;
    ((NonUIButtonPad *)opaque)->configuration = (uint32_t)value & ~1u;
}

#ifndef NONUI_BUTTON_PAD_TEST
static const NonUIQemuMemoryRegionOps nonui_button_pad_ops = {
    .read = nonui_button_pad_read,
    .write = nonui_button_pad_write,
    .endianness = 0,
    .valid = {.min_access_size = 4, .max_access_size = 4},
    .impl = {.min_access_size = 4, .max_access_size = 4},
};

static int install_nonui_button_pads(const char *engine, void *anchor) {
    if (!getenv("NONUI_BUTTON_PAD_PULLUPS"))
        return 0;
    void *(*memory)(void) =
        local_qemu_symbol(engine, anchor, "_get_system_memory");
    void (*init)(void *, void *, const NonUIQemuMemoryRegionOps *, void *,
                 const char *, uint64_t) =
        local_qemu_symbol(engine, anchor, "_memory_region_init_io");
    void (*overlap)(void *, uint64_t, void *, int) = local_qemu_symbol(
        engine, anchor, "_memory_region_add_subregion_overlap");
    if (!memory || !init || !overlap)
        return 70;
    const unsigned pins[] = {2, 3, 4, 5, 16};
    for (unsigned i = 0; i < sizeof(pins) / sizeof(pins[0]); i++) {
        void *region = calloc(1, 4096);
        NonUIButtonPad *pad = calloc(1, sizeof(*pad));
        if (!region || !pad)
            return 70;
        init(region, NULL, &nonui_button_pad_ops, pad,
             "nonui-released-button-pad-partial", 4);
        overlap(memory(), 0x20E300000ULL + 4 * pins[i], region, 10);
    }
    fputs("NonUI partial GPIO inputs: released buttons on pins2,3,4,5,16; no "
          "IRQ/input transport\n",
          stderr);
    return 0;
}
#endif
