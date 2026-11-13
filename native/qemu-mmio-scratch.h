

#pragma once
#include <errno.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static int install_nonui_mmio_windows(const char *engine, void *anchor) {
    const char *value = getenv("NONUI_MMIO_WINDOWS");
    if (!value || !*value)
        return 0;

    void *(*get_system_memory)(void) =
        local_qemu_symbol(engine, anchor, "_get_system_memory");
    void (*init_ram)(void *, void *, const char *, uint64_t, void **) =
        local_qemu_symbol(engine, anchor, "_memory_region_init_ram_nomigrate");
    void (*add_region)(void *, uint64_t, void *) =
        local_qemu_symbol(engine, anchor, "_memory_region_add_subregion");
    if (!get_system_memory || !init_ram || !add_region) {
        fputs("NonUI: QEMU scratch MMIO APIs unavailable\n", stderr);
        return 70;
    }
    void *system = get_system_memory();
    if (!system)
        return 70;
    char *spec = strdup(value);
    if (!spec)
        return 70;
    int count = 0;
    for (char *entry = strtok(spec, ","); entry; entry = strtok(NULL, ",")) {
        if (++count > 48) {
            free(spec);
            return 70;
        }
        char *separator = strchr(entry, ':');
        if (!separator) {
            free(spec);
            return 70;
        }
        *separator = 0;
        errno = 0;
        char *endptr = NULL;
        uint64_t addr = strtoull(entry, &endptr, 16);
        if (errno || !endptr || *endptr) {
            free(spec);
            return 70;
        }
        errno = 0;
        uint64_t size = strtoull(separator + 1, &endptr, 16);
        if (errno || !endptr || *endptr || addr < 0x200000000ULL ||
            addr & 0xFFF || size < 0x1000 || size > 0x200000 || size & 0xFFF ||
            addr + size <= addr) {
            free(spec);
            return 70;
        }

        void *region = calloc(1, 4096);
        char *name = malloc(48);
        if (!region || !name) {
            free(spec);
            return 70;
        }
        snprintf(name, 48, "nonui-a7-mmio-%02d", count);
        void *error = NULL;
        init_ram(region, NULL, name, size, &error);
        if (error) {
            fprintf(stderr, "NonUI: could not install MMIO RAM %s\n", name);
            free(spec);
            return 70;
        }
        add_region(system, addr, region);
        fprintf(stderr,
                "NonUI diagnostic-only MMIO register store %s @0x%llx size "
                "0x%llx\n",
                name, (unsigned long long)addr, (unsigned long long)size);
    }
    free(spec);
    return count > 0 ? 0 : 70;
}
