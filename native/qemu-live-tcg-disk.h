

#pragma once

enum {

    TCG_OPS_OFFSET = 0x148,
    CPU_SINGLE_STEP_OFFSET = 0xd4,
    CPU_WATCHPOINT_HIT_OFFSET = 0x278,

    ARM_XREGS_OFFSET = 0x2c60,
    ARM_PC_OFFSET = 0x2d60,
    ARM_PSTATE_OFFSET = 0x2d68,
    ARM_IS_AARCH64_OFFSET = 0x2d6c,
};

static const uint64_t bcopy_phys_pc = 0xffffff80002d9670ULL;
static const uint64_t live_disk_read_call = 0xffffff800063fe28ULL;
static const uint64_t live_disk_write_call = 0xffffff800063fee4ULL;
typedef struct {
    const void *before_debug[6];
    void (*debug_exception)(void *);
    const void *after_debug[12];
} LiveTCGOps;
_Static_assert(sizeof(LiveTCGOps) == 0x98, "Unexpected host TCGCPUOps layout");

static LiveTCGOps live_tcg_disk_ops;
static void *live_tcg_disk_cpu;
static void (*live_tcg_disk_original_debug)(void *);
static void (*live_tcg_disk_set_pc)(void *, uint64_t);
static void (*live_tcg_disk_resume)(void *);
static bool live_tcg_disk_installed;
static bool live_tcg_disk_call_sites;
static atomic_uint live_tcg_disk_directions;
static atomic_uint_fast64_t live_tcg_disk_reads, live_tcg_disk_writes,
    live_tcg_disk_bytes;

static bool handle_live_tcg_disk(void *cpu) {
    unsigned directions =
        atomic_load_explicit(&live_tcg_disk_directions, memory_order_acquire);
    if (!directions || cpu != live_tcg_disk_cpu)
        return false;
    const uint8_t *state = cpu;
    if (state[ARM_IS_AARCH64_OFFSET] != 1)
        return false;
    uint64_t pc, watchpoint;
    uint32_t step, pstate;
    memcpy(&pc, state + ARM_PC_OFFSET, sizeof(pc));
    if (live_tcg_disk_call_sites
            ? (pc != live_disk_read_call && pc != live_disk_write_call)
            : pc != bcopy_phys_pc)
        return false;
    memcpy(&step, state + CPU_SINGLE_STEP_OFFSET, sizeof(step));
    memcpy(&watchpoint, state + CPU_WATCHPOINT_HIT_OFFSET, sizeof(watchpoint));
    memcpy(&pstate, state + ARM_PSTATE_OFFSET, sizeof(pstate));
    unsigned mode = pstate & 15;
    if (step || watchpoint || (mode != 4 && mode != 5))
        return false;

    uint64_t arguments[3], link;
    memcpy(arguments, state + ARM_XREGS_OFFSET, sizeof(arguments));
    if (live_tcg_disk_call_sites) {
        link = pc + 4;
    } else {
        memcpy(&link, state + ARM_XREGS_OFFSET + 30 * sizeof(link),
               sizeof(link));
        if ((link & 3) || link < 0xffffff8000200000ULL ||
            link >= 0xffffff8001c42000ULL)
            return false;
    }
    unsigned direction =
        live_disk_direction(arguments[0], arguments[1], arguments[2]);
    if (!(directions & direction) || arguments[2] > 4096)
        return false;
    if (live_tcg_disk_call_sites &&
        direction !=
            (pc == live_disk_read_call ? LIVE_DISK_READ : LIVE_DISK_WRITE))
        return false;

    bool held = live_disk_bql_locked();
    if (!held)
        live_disk_bql_lock(__FILE__, __LINE__);
    bool copied = false;
    if (!atomic_load(&live_ram_done) && live_ram_running()) {
        static const uint32_t original_entry[] = {0xa9bf7bfd, 0x910003fd,
                                                  0xa9bf4ff4, 0xa9bf57f6};
        const uint8_t *entry = live_ram_at(0x402d9670, sizeof(original_entry));
        copied =
            entry && !memcmp(entry, original_entry, sizeof(original_entry));
        if (copied && live_tcg_disk_call_sites) {
            uint32_t expected =
                pc == live_disk_read_call ? 0x97f26612 : 0x97f265e3;
            const uint8_t *instruction =
                live_ram_at(pc - 0xffffff8000200000ULL + 0x40200000, 4);
            copied = instruction &&
                     !memcmp(instruction, &expected, sizeof(expected));
        }
        copied = copied && live_disk_transfer_ram(arguments[0], arguments[1],
                                                  arguments[2]);
        if (copied) {
            if (direction == LIVE_DISK_READ) {
                atomic_fetch_add_explicit(&live_tcg_disk_reads, 1,
                                          memory_order_relaxed);
            } else {
                atomic_fetch_add_explicit(&live_tcg_disk_writes, 1,
                                          memory_order_relaxed);
            }
            atomic_fetch_add_explicit(&live_tcg_disk_bytes, arguments[2],
                                      memory_order_relaxed);

            if (live_tcg_disk_call_sites)
                memcpy((uint8_t *)cpu + ARM_XREGS_OFFSET + 30 * sizeof(link),
                       &link, sizeof(link));
            live_tcg_disk_set_pc(cpu, link);
        }
    }
    if (!held)
        live_disk_bql_unlock();
    return copied;
}

static void live_tcg_disk_debug(void *cpu) {
    if (handle_live_tcg_disk(cpu)) {

        live_tcg_disk_resume(cpu);
        abort();
    }
    live_tcg_disk_original_debug(cpu);
}

static void install_live_tcg_disk(const char *engine, void *anchor) {
    const char *option = getenv("NONUI_LIVE_TCG_DISK");
    if (!live_disk_enabled || !option || strcmp(option, "1"))
        return;
    live_tcg_disk_call_sites = getenv("NONUI_LIVE_DISK_CALL_SITES") != NULL;
    void *(*get_cpu)(int) = local_qemu_symbol(engine, anchor, "_qemu_get_cpu");
    void *(*get_class)(void *) =
        local_qemu_symbol(engine, anchor, "_object_get_class");
    const LiveTCGOps *original_ops =
        local_qemu_symbol(engine, anchor, "_arm_tcg_ops");
    live_tcg_disk_original_debug =
        local_qemu_symbol(engine, anchor, "_arm_debug_excp_handler");
    live_tcg_disk_set_pc = local_qemu_symbol(engine, anchor, "_arm_cpu_set_pc");
    live_tcg_disk_resume =
        local_qemu_symbol(engine, anchor, "_cpu_loop_exit_noexc");
    if (!get_cpu || !get_class || !original_ops ||
        !live_tcg_disk_original_debug || !live_tcg_disk_set_pc ||
        !live_tcg_disk_resume ||
        original_ops->debug_exception != live_tcg_disk_original_debug) {
        fputs(
            "NonUI RAM-disk: using stopped copies because TCG callback ABI did "
            "not match\n",
            stderr);
        return;
    }
    live_tcg_disk_cpu = get_cpu(0);
    uint8_t *cpu_class =
        live_tcg_disk_cpu ? get_class(live_tcg_disk_cpu) : NULL;
    if (!cpu_class || get_cpu(1) || live_ram_running())
        return;
    const LiveTCGOps *class_ops;
    memcpy(&class_ops, cpu_class + TCG_OPS_OFFSET, sizeof(class_ops));
    if (class_ops != original_ops) {
        fputs("NonUI RAM-disk: using stopped copies because CPU class did not "
              "match\n",
              stderr);
        return;
    }
    live_tcg_disk_ops = *original_ops;
    live_tcg_disk_ops.debug_exception = live_tcg_disk_debug;
    class_ops = &live_tcg_disk_ops;
    memcpy(cpu_class + TCG_OPS_OFFSET, &class_ops, sizeof(class_ops));
    live_tcg_disk_installed = true;
    fputs("NonUI RAM-disk: vCPU callback installed, awaiting stopped copy "
          "readback\n",
          stderr);
}

static int arm_live_tcg_disk(uint64_t direction) {
    if (!live_tcg_disk_installed)
        return ENOTSUP;
    if (direction != LIVE_DISK_READ && direction != LIVE_DISK_WRITE)
        return EINVAL;
    live_disk_bql_lock(__FILE__, __LINE__);
    int status = EBUSY;
    if (!atomic_load(&live_ram_done) && !live_ram_running()) {
        const uint8_t *state = live_tcg_disk_cpu;
        uint64_t pc;
        memcpy(&pc, state + ARM_PC_OFFSET, sizeof(pc));
        status = ENOTSUP;

        uint64_t expected_pc =
            live_tcg_disk_call_sites
                ? (direction == LIVE_DISK_READ ? live_disk_read_call
                                               : live_disk_write_call)
                : bcopy_phys_pc;
        if (pc == expected_pc && state[ARM_IS_AARCH64_OFFSET] == 1 &&
            live_disk_direction(live_disk_last_stopped_copy[0],
                                live_disk_last_stopped_copy[1],
                                live_disk_last_stopped_copy[2]) == direction &&
            !memcmp(state + ARM_XREGS_OFFSET, live_disk_last_stopped_copy,
                    sizeof(live_disk_last_stopped_copy))) {
            atomic_fetch_or_explicit(&live_tcg_disk_directions,
                                     (unsigned)direction, memory_order_release);
            status = 0;
        }
    }
    live_disk_bql_unlock();
    return status;
}

static void log_live_tcg_disk(void) {
    if (live_tcg_disk_installed) {
        fprintf(stderr,
                "NonUI RAM-disk: direct reads=%llu writes=%llu bytes=%llu\n",
                (unsigned long long)atomic_load(&live_tcg_disk_reads),
                (unsigned long long)atomic_load(&live_tcg_disk_writes),
                (unsigned long long)atomic_load(&live_tcg_disk_bytes));
    }
}
