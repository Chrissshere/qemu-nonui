

#include <fcntl.h>
#include <libkern/OSByteOrder.h>
#include <mach-o/fat.h>
#include <mach-o/loader.h>
#include <mach-o/nlist.h>
#include <stdint.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/stat.h>

static void *local_qemu_symbol(const char *path, void *anchor,
                               const char *name) {
    Dl_info info;
    if (!dladdr(anchor, &info))
        return NULL;
    int fd = open(path, O_RDONLY);
    if (fd < 0)
        return NULL;
    struct stat st;
    if (fstat(fd, &st) || st.st_size < (off_t)sizeof(struct mach_header_64)) {
        close(fd);
        return NULL;
    }
    size_t size = (size_t)st.st_size;
    const uint8_t *data = mmap(NULL, size, PROT_READ, MAP_PRIVATE, fd, 0);
    close(fd);
    if (data == MAP_FAILED)
        return NULL;
    const uint8_t *mapping = data;
    size_t mapping_size = size;
    void *result = NULL;
    const struct fat_header *fat = (const void *)data;
    if (fat->magic == FAT_CIGAM) {
        uint32_t count = OSSwapBigToHostInt32(fat->nfat_arch);
        if (count > (size - sizeof(*fat)) / sizeof(struct fat_arch))
            goto done;
        const struct fat_arch *arches = (const void *)(data + sizeof(*fat));
        int found = 0;
        for (uint32_t i = 0; i < count; i++) {
            if (OSSwapBigToHostInt32(arches[i].cputype) != CPU_TYPE_ARM64)
                continue;
            uint64_t begin = OSSwapBigToHostInt32(arches[i].offset);
            uint64_t length = OSSwapBigToHostInt32(arches[i].size);
            if (begin + length > size || length < sizeof(struct mach_header_64))
                goto done;
            data += begin;
            size = (size_t)length;
            found = 1;
            break;
        }
        if (!found)
            goto done;
    }
    const struct mach_header_64 *header = (const void *)data;
    const struct symtab_command *symtab = NULL;
    uint64_t text_address = UINT64_MAX;
    size_t offset = sizeof(*header);
    if (header->magic != MH_MAGIC_64)
        goto done;
    for (uint32_t i = 0; i < header->ncmds; i++) {
        if (offset + sizeof(struct load_command) > size)
            goto done;
        const struct load_command *cmd = (const void *)(data + offset);
        if (cmd->cmdsize < sizeof(*cmd) || cmd->cmdsize > size - offset)
            goto done;
        if (cmd->cmd == LC_SYMTAB && cmd->cmdsize >= sizeof(*symtab))
            symtab = (const void *)cmd;
        if (cmd->cmd == LC_SEGMENT_64 &&
            cmd->cmdsize >= sizeof(struct segment_command_64)) {
            const struct segment_command_64 *seg = (const void *)cmd;
            if (!strncmp(seg->segname, "__TEXT", 16))
                text_address = seg->vmaddr;
        }
        offset += cmd->cmdsize;
    }
    if (!symtab || text_address == UINT64_MAX ||
        (uint64_t)symtab->symoff +
                (uint64_t)symtab->nsyms * sizeof(struct nlist_64) >
            size ||
        (uint64_t)symtab->stroff + symtab->strsize > size)
        goto done;
    const struct nlist_64 *symbols = (const void *)(data + symtab->symoff);
    const char *strings = (const void *)(data + symtab->stroff);
    for (uint32_t i = 0; i < symtab->nsyms; i++) {
        uint32_t idx = symbols[i].n_un.n_strx;
        if (idx >= symtab->strsize || !symbols[i].n_value ||
            (symbols[i].n_type & N_TYPE) != N_SECT ||
            (symbols[i].n_type & N_STAB))
            continue;
        size_t remaining = symtab->strsize - idx;
        if (!memchr(strings + idx, 0, remaining))
            continue;
        if (!strcmp(strings + idx, name)) {
            result = (void *)((uintptr_t)info.dli_fbase + symbols[i].n_value -
                              text_address);
            break;
        }
    }
done:
    munmap((void *)mapping, mapping_size);
    return result;
}

static int wire_physical_timer_to_fiq(const char *engine, void *anchor) {
    void *(*get_cpu)(int) = local_qemu_symbol(engine, anchor, "_qemu_get_cpu");
    void *(*get_input)(void *, int) =
        local_qemu_symbol(engine, anchor, "_qdev_get_gpio_in");
    void *(*intercept)(void *, void *, const char *, int) =
        local_qemu_symbol(engine, anchor, "_qdev_intercept_gpio_out");
    if (!get_cpu || !get_input || !intercept)
        return 70;
    void *cpu = get_cpu(0);
    if (!cpu)
        return 70;

    void *fiq = get_input(cpu, 1);
    if (!fiq)
        return 70;
    const char *virtual_timer = getenv("NONUI_HVF_PHYSICAL_TIMER");
    int output = virtual_timer && !strcmp(virtual_timer, "1") ? 1 : 0;
    intercept(cpu, fiq, NULL, output);
    fprintf(
        stderr,
        "NonUI diagnostic: %s timer output %d connected to CPU0 FIQ input 1\n",
        output ? "virtual" : "physical", output);
    return 0;
}
