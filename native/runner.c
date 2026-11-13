#include <dlfcn.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/resource.h>
#include <unistd.h>

#include "qemu-timer-fiq.h"
#include "qemu-mmio-scratch.h"
#include "qemu-pmgr-ack.h"
#include "qemu-sgx-ack.h"
#include "qemu-i2c-chestnut.h"
#include "qemu-gpio-buttons.h"
#include "qemu-adbe0-timing.h"
#include "qemu-live-ram.h"

static void watchdog(int signal_number) {
    (void)signal_number;
    static const char message[] = "QEMU time limit reached\n";
    write(STDERR_FILENO, message, sizeof(message) - 1);
    _exit(124);
}

int main(int argc, char **argv, char **envp) {
    const char *engine = getenv("NONUI_QEMU_ENGINE");
    const char *duration = getenv("NONUI_WATCHDOG_SECONDS");
    char *end = NULL;
    unsigned long seconds = duration ? strtoul(duration, &end, 10) : 0;
    if (!engine || !*engine || !end || *end || seconds < 1 || seconds > 900) {
        return 64;
    }

    const struct rlimit core_limit = {0, 0};
    const struct rlimit file_limit = {8 * 1024 * 1024, 8 * 1024 * 1024};
    setrlimit(RLIMIT_CORE, &core_limit);
    setrlimit(RLIMIT_FSIZE, &file_limit);
    signal(SIGALRM, watchdog);
    alarm((unsigned)seconds);

    void *handle = dlopen(engine, RTLD_LOCAL | RTLD_LAZY | RTLD_FIRST);
    if (!handle) {
        fprintf(stderr, "%s\n", dlerror());
        return 70;
    }
    void (*initialize)(int, char **, char **) = dlsym(handle, "qemu_init");
    void (*main_loop)(void) = dlsym(handle, "qemu_main_loop");
    void (*cleanup)(void) = dlsym(handle, "qemu_cleanup");
    if (!initialize || !main_loop || !cleanup) {
        fputs("UTM QEMU API is incomplete\n", stderr);
        return 70;
    }

    initialize(argc, argv, envp);
    int (*const adapters[])(const char *, void *) = {
        install_nonui_mmio_windows, install_nonui_pmgr_ack,
        install_nonui_sgx_ack,      install_nonui_i2c_chestnut,
        install_nonui_button_pads,  install_nonui_adbe0_timing,
        wire_physical_timer_to_fiq, install_nonui_live_ram,
    };
    for (size_t index = 0; index < sizeof(adapters) / sizeof(*adapters);
         ++index) {
        int status = adapters[index](engine, (void *)initialize);
        if (status) {
            return status;
        }
    }
    main_loop();
    stop_nonui_live_ram();
    cleanup();
    return 0;
}
