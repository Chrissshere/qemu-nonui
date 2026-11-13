

#pragma once
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

enum {

    NONUI_I2C_IDLE = 1u << 24,
    NONUI_I2C_COMPLETE = 1u << 27,
    NONUI_I2C_RX_READY = 1u << 20,
    NONUI_I2C_NACK = 1u << 21,
};

typedef struct {
    uint32_t regs[0x1000 / 4];
    uint32_t gpio[2];
    uint8_t chestnut[256], rx[256], register_pointer;
    unsigned rx_head, rx_count, reads, writes, transactions;
    unsigned slave_address;
    bool read_phase, need_register;
} NonUII2CChestnut;

static void nonui_i2c_initialize(NonUII2CChestnut *dev) {
    memset(dev, 0, sizeof(*dev));
    dev->regs[0x14 / 4] = NONUI_I2C_IDLE;
}

static uint64_t nonui_i2c_gpio_read(void *opaque, uint64_t off, unsigned size) {
    NonUII2CChestnut *dev = opaque;
    if (size != 4 || off >= 8 || (off & 3))
        return 0;

    return dev->gpio[off / 4] | 1;
}

static void nonui_i2c_gpio_write(void *opaque, uint64_t off, uint64_t data,
                                 unsigned size) {
    NonUII2CChestnut *dev = opaque;
    if (size != 4 || off >= 8 || (off & 3))
        return;
    dev->gpio[off / 4] = (uint32_t)data & ~1u;
}

static uint64_t nonui_i2c_read(void *opaque, uint64_t off, unsigned size) {
    NonUII2CChestnut *dev = opaque;
    if (size != 4 || off >= 0x1000 || (off & 3))
        return 0;
    uint32_t value = dev->regs[off / 4];
    if (off == 4) {
        value = 0x100;
        if (dev->rx_count) {
            value = dev->rx[dev->rx_head++ & 255];
            dev->rx_count--;
        }
    } else if (off == 8) {

        value = dev->rx_count << 8;
    } else if (off == 0x14) {
        value |= NONUI_I2C_IDLE;
    }
    if (dev->reads++ < 80)
        fprintf(stderr, "NonUI I2C0 partial read +0x%llx -> 0x%x\n",
                (unsigned long long)off, value);
    return value;
}

static void nonui_i2c_write(void *opaque, uint64_t off, uint64_t data,
                            unsigned size) {
    NonUII2CChestnut *dev = opaque;
    if (size != 4 || off >= 0x1000 || (off & 3))
        return;
    uint32_t value = (uint32_t)data;
    if (dev->writes++ < 100)
        fprintf(stderr, "NonUI I2C0 partial write +0x%llx <- 0x%x\n",
                (unsigned long long)off, value);
    if (off == 0x14) {

        dev->regs[off / 4] &= ~value;
        dev->regs[off / 4] |= NONUI_I2C_IDLE;
        return;
    }
    if (off != 0) {
        dev->regs[off / 4] = value;
        if (off == 0x10 && (value & 0x80000000u)) {
            dev->rx_count = dev->rx_head = 0;
            dev->regs[0x14 / 4] = NONUI_I2C_IDLE;
        }
        return;
    }
    if (value & 0x100) {
        dev->slave_address = (value & 0xFF) >> 1;
        dev->read_phase = (value & 1) != 0;
        dev->need_register = !dev->read_phase;
        dev->regs[0x14 / 4] &=
            ~(NONUI_I2C_COMPLETE | NONUI_I2C_NACK | NONUI_I2C_RX_READY);
        if (dev->slave_address != 0x27)
            dev->regs[0x14 / 4] |= NONUI_I2C_NACK;
    } else if (value & 0x400) {
        unsigned count = value & 0xFF;
        if (!count)
            count = 256;
        if (dev->slave_address == 0x27 && dev->read_phase &&
            count + dev->rx_count <= 256) {
            for (unsigned i = 0; i < count; i++) {
                dev->rx[(dev->rx_head + dev->rx_count++) & 255] =
                    dev->chestnut[dev->register_pointer++];
            }
            dev->regs[0x14 / 4] |= NONUI_I2C_RX_READY;
        } else {
            dev->regs[0x14 / 4] |= NONUI_I2C_NACK;
        }
    } else if (dev->slave_address == 0x27 && !dev->read_phase) {
        if (dev->need_register) {
            dev->register_pointer = (uint8_t)value;
            dev->need_register = false;
        } else {
            dev->chestnut[dev->register_pointer++] = (uint8_t)value;
        }
    }
    if (value & 0x200) {
        dev->regs[0x14 / 4] |= NONUI_I2C_COMPLETE;
        dev->transactions++;
    }
}

#ifndef NONUI_I2C_MODEL_TEST
static const NonUIQemuMemoryRegionOps nonui_i2c_ops = {
    .read = nonui_i2c_read,
    .write = nonui_i2c_write,
    .endianness = 0,
    .valid = {.min_access_size = 4, .max_access_size = 4},
    .impl = {.min_access_size = 4, .max_access_size = 4},
};
static const NonUIQemuMemoryRegionOps nonui_i2c_gpio_ops = {
    .read = nonui_i2c_gpio_read,
    .write = nonui_i2c_gpio_write,
    .endianness = 0,
    .valid = {.min_access_size = 4, .max_access_size = 4},
    .impl = {.min_access_size = 4, .max_access_size = 4},
};

static int install_nonui_i2c_chestnut(const char *engine, void *anchor) {
    if (!getenv("NONUI_I2C_CHESTNUT"))
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
    NonUII2CChestnut *dev = calloc(1, sizeof(*dev));
    if (!region || !dev)
        return 70;
    nonui_i2c_initialize(dev);
    init_io(region, NULL, &nonui_i2c_ops, dev, "nonui-i2c0-chestnut-partial",
            0x1000);
    overlap(system_memory(), 0x20A110000ULL, region, 10);
    void *gpio_region = calloc(1, 4096);
    if (!gpio_region)
        return 70;
    init_io(gpio_region, NULL, &nonui_i2c_gpio_ops, dev,
            "nonui-i2c0-line-pullups-partial", 8);
    overlap(system_memory(), 0x20E300140ULL, gpio_region, 10);
    fputs("NonUI partial I2C0/Chestnut model at 0x20a110000, slave 0x27\n",
          stderr);
    return 0;
}
#endif
