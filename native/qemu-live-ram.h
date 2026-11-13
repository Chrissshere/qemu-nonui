

#pragma once
#include <errno.h>
#include <poll.h>
#include <pthread.h>
#include <stdatomic.h>
#include <stdbool.h>
#include <stdint.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/un.h>

static const uint64_t live_ram_base = 0x40000000ULL;
static uint64_t live_ram_size = 0x20000000ULL;
static void *live_ram_pointer;
static void *(*live_ram_map)(uint64_t, uint64_t *, bool);
static void (*live_ram_unmap)(void *, uint64_t, bool, uint64_t);
static bool (*live_ram_running)(void);
static int live_ram_listener = -1;
static pthread_t live_ram_thread;
static atomic_bool live_ram_done;
static char live_ram_socket_path[sizeof(((struct sockaddr_un *)0)->sun_path)];

static bool live_disk_enabled;
static void (*live_disk_bql_lock)(const char *, int);
static void (*live_disk_bql_unlock)(void);
static bool (*live_disk_bql_locked)(void);
static void (*live_disk_rcu_register)(void);
static void (*live_disk_rcu_unregister)(void);
static void *(*live_disk_region_from_host)(void *, uint64_t *);
static bool (*live_disk_is_io)(uint64_t);
static uint64_t live_disk_last_stopped_copy[3];

static bool live_disk_contains(uint64_t base, uint64_t size, uint64_t address,
                               uint64_t count) {
    return address >= base && count <= size && address - base <= size - count;
}

enum { LIVE_DISK_READ = 1, LIVE_DISK_WRITE = 2 };

static unsigned live_disk_direction(uint64_t source, uint64_t destination,
                                    uint64_t count) {
    if (!count || count > 0x8000)
        return 0;

    if (live_disk_contains(0x80000000, 0x50000000, source, count) &&
        live_disk_contains(0x40200000, 0x1fe00000, destination, count))
        return LIVE_DISK_READ;
    if (live_disk_contains(0x40200000, 0x1fe00000, source, count) &&
        live_disk_contains(0x80000000, 0x50000000, destination, count))
        return LIVE_DISK_WRITE;
    return 0;
}

static bool live_disk_transfer_ram(uint64_t source, uint64_t destination,
                                   uint64_t count) {
    if (live_disk_is_io(source) || live_disk_is_io(source + count - 1) ||
        live_disk_is_io(destination) ||
        live_disk_is_io(destination + count - 1))
        return false;
    uint64_t source_length = count, destination_length = count, offset;
    void *input = live_ram_map(source, &source_length, false);
    if (!input)
        return false;
    bool copied = false;
    if (source_length == count && live_disk_region_from_host(input, &offset)) {
        void *output = live_ram_map(destination, &destination_length, true);
        if (output && destination_length == count &&
            live_disk_region_from_host(output, &offset)) {
            memcpy(output, input, (size_t)count);
            copied = true;
        }

        if (output)
            live_ram_unmap(output, destination_length, copied,
                           copied ? count : 0);
    }
    live_ram_unmap(input, source_length, false, 0);
    return copied;
}

static int live_disk_copy(uint64_t source, uint64_t destination,
                          uint64_t count) {
    if (!live_disk_enabled)
        return ENOTSUP;
    if (!live_disk_direction(source, destination, count))
        return EINVAL;
    live_disk_bql_lock(__FILE__, __LINE__);
    int status = EBUSY;
    if (!atomic_load(&live_ram_done) && !live_ram_running()) {
        status =
            live_disk_transfer_ram(source, destination, count) ? 0 : EFAULT;
        if (!status) {
            live_disk_last_stopped_copy[0] = source;
            live_disk_last_stopped_copy[1] = destination;
            live_disk_last_stopped_copy[2] = count;
        }
    }
    live_disk_bql_unlock();
    return status;
}

static void install_nonui_live_disk(const char *engine, void *anchor) {
    const char *option = getenv("NONUI_LIVE_DISK_COPY");
    if (!option || strcmp(option, "1"))
        return;
    live_disk_bql_lock = local_qemu_symbol(engine, anchor, "_bql_lock_impl");
    live_disk_bql_unlock = local_qemu_symbol(engine, anchor, "_bql_unlock");
    live_disk_bql_locked = local_qemu_symbol(engine, anchor, "_bql_locked");
    live_disk_rcu_register =
        local_qemu_symbol(engine, anchor, "_rcu_register_thread");
    live_disk_rcu_unregister =
        local_qemu_symbol(engine, anchor, "_rcu_unregister_thread");
    live_disk_region_from_host =
        local_qemu_symbol(engine, anchor, "_memory_region_from_host");
    live_disk_is_io =
        local_qemu_symbol(engine, anchor, "_cpu_physical_memory_is_io");
    if (!live_disk_bql_lock || !live_disk_bql_unlock || !live_disk_bql_locked ||
        !live_disk_rcu_register || !live_disk_rcu_unregister ||
        !live_disk_region_from_host || !live_disk_is_io) {
        fputs("NonUI RAM-disk: native copy APIs unavailable; using debugger "
              "copies\n",
              stderr);
        return;
    }
    live_disk_enabled = true;
    fputs("NonUI native RAM-disk copies enabled for stopped guest\n", stderr);
}

static const uint8_t *live_ram_at(uint64_t address, uint64_t count) {
    if (!count || address < live_ram_base || count > live_ram_size ||
        address - live_ram_base > live_ram_size - count)
        return NULL;
    return (const uint8_t *)live_ram_pointer + (address - live_ram_base);
}

#include "qemu-live-tcg-disk.h"

static bool live_ram_copy_user(uint64_t ttbr, uint64_t address, uint64_t bits,
                               size_t length, uint8_t *output) {
    if (bits < 25 || bits > 48 || address < 0x1000 ||
        address >= (1ULL << bits) || length > (1ULL << bits) - address)
        return false;
    const uint64_t table_mask = 0x0000fffffffff000ULL;
    unsigned first = 3 - (unsigned)(bits - 13) / 9;
    while (length) {
        uint64_t table = ttbr & table_mask;
        for (unsigned level = first; level <= 3; level++) {
            unsigned shift = 12 + (3 - level) * 9;
            const uint8_t *entry =
                live_ram_at(table + ((address >> shift) & 511) * 8, 8);
            if (!entry)
                return false;
            uint64_t descriptor;
            memcpy(&descriptor, entry, sizeof(descriptor));
            unsigned kind = descriptor & 3;
            if (!(kind & 1) || (level == 3 && kind != 3))
                return false;
            if (kind == 1 || level == 3) {
                uint64_t offset_mask = (1ULL << shift) - 1;
                uint64_t physical = (descriptor & table_mask & ~offset_mask) |
                                    (address & offset_mask);
                size_t span = 0x1000 - (address & 0xfff);
                if (span > length)
                    span = length;
                const uint8_t *data = live_ram_at(physical, span);
                if (!data)
                    return false;
                memcpy(output, data, span);
                output += span;
                address += span;
                length -= span;
                break;
            }
            table = descriptor & table_mask;
        }
    }
    return true;
}

static bool live_ram_transfer(int fd, void *bytes, size_t length,
                              bool sending) {
    uint8_t *data = bytes;
    while (length && !atomic_load(&live_ram_done)) {
        ssize_t count =
            sending ? send(fd, data, length, 0) : recv(fd, data, length, 0);
        if (count < 0 && errno == EINTR)
            continue;
        if (!sending && count < 0 && (errno == EAGAIN || errno == EWOULDBLOCK))
            continue;
        if (count <= 0)
            return false;
        data += count;
        length -= (size_t)count;
    }
    return length == 0;
}

static void *live_ram_serve(void *unused) {
    (void)unused;
    if (live_disk_enabled)
        live_disk_rcu_register();
    uint8_t *virtual_bytes = malloc(0x400000);
    while (!atomic_load(&live_ram_done)) {
        struct pollfd ready = {live_ram_listener, POLLIN, 0};
        if (poll(&ready, 1, 200) <= 0)
            continue;
        int client = accept(live_ram_listener, NULL, NULL);
        if (client < 0)
            continue;
        int yes = 1;
        struct timeval timeout = {1, 0};
        setsockopt(client, SOL_SOCKET, SO_NOSIGPIPE, &yes, sizeof(yes));
        setsockopt(client, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout));
        setsockopt(client, SOL_SOCKET, SO_SNDTIMEO, &timeout, sizeof(timeout));
        uint64_t request[3];
        while (live_ram_transfer(client, request, sizeof(request), false)) {
            uint64_t address = request[1], count = request[2];
            bool disk = request[0] == 0x4e4f4e554944534bULL;
            bool user = request[0] == 0x4e4f4e5549564952ULL;
            uint64_t destination;
            if (disk && !live_ram_transfer(client, &destination,
                                           sizeof(destination), false))
                break;
            uint64_t translation[2];
            if (user && !live_ram_transfer(client, translation,
                                           sizeof(translation), false))
                break;
            uint64_t reply[2] = {0, count};
            const uint8_t *data = NULL;
            if (request[0] == 0x4e4f4e554941524dULL) {
                reply[0] = count ? EINVAL : arm_live_tcg_disk(address);
            } else if (disk)
                reply[0] = live_disk_copy(address, destination, count);
            else if ((!user && request[0] != 0x4e4f4e554952414dULL) || !count ||
                     count > 0x400000)
                reply[0] = EINVAL;
            else if (live_ram_running())
                reply[0] = EBUSY;
            else if (user) {
                if (!virtual_bytes)
                    reply[0] = ENOMEM;
                else if (!live_ram_copy_user(translation[0], address,
                                             translation[1], (size_t)count,
                                             virtual_bytes))
                    reply[0] = EFAULT;
                else
                    data = virtual_bytes;
            } else {
                data = live_ram_at(address, count);
                if (!data)
                    reply[0] = EINVAL;
            }
            if (reply[0])
                reply[1] = 0;
            if (!live_ram_transfer(client, reply, sizeof(reply), true))
                break;
            if (data &&
                !live_ram_transfer(client, (void *)data, (size_t)count, true))
                break;
        }
        close(client);
    }
    free(virtual_bytes);
    if (live_disk_enabled)
        live_disk_rcu_unregister();
    return NULL;
}

static int install_nonui_live_ram(const char *engine, void *anchor) {
    const char *path = getenv("NONUI_LIVE_RAM_SOCKET");
    if (!path || !*path)
        return 0;
    if (strlen(path) >= sizeof(live_ram_socket_path))
        return 64;
    live_ram_map =
        local_qemu_symbol(engine, anchor, "_cpu_physical_memory_map");
    live_ram_unmap =
        local_qemu_symbol(engine, anchor, "_cpu_physical_memory_unmap");
    live_ram_running =
        local_qemu_symbol(engine, anchor, "_runstate_is_running");
    if (!live_ram_map || !live_ram_unmap || !live_ram_running)
        return 70;
    install_nonui_live_disk(engine, anchor);
    uint64_t mapped = live_ram_size;
    live_ram_pointer = live_ram_map(live_ram_base, &mapped, false);
    if (!live_ram_pointer || mapped != live_ram_size) {
        if (live_ram_pointer)
            live_ram_unmap(live_ram_pointer, mapped, false, 0);
        live_ram_pointer = NULL;
        return 70;
    }
    struct sockaddr_un address = {0};
    address.sun_family = AF_UNIX;
    strlcpy(address.sun_path, path, sizeof(address.sun_path));
    live_ram_listener = socket(AF_UNIX, SOCK_STREAM, 0);
    mode_t mask = umask(077);
    int result = live_ram_listener < 0
                     ? -1
                     : bind(live_ram_listener, (struct sockaddr *)&address,
                            sizeof(address));
    umask(mask);
    if (result || listen(live_ram_listener, 1)) {
        perror("NonUI read-only RAM socket");
        if (live_ram_listener >= 0)
            close(live_ram_listener);
        live_ram_listener = -1;
        live_ram_unmap(live_ram_pointer, live_ram_size, false, 0);
        live_ram_pointer = NULL;
        return 70;
    }
    strlcpy(live_ram_socket_path, path, sizeof(live_ram_socket_path));
    install_live_tcg_disk(engine, anchor);
    atomic_store(&live_ram_done, false);
    if (pthread_create(&live_ram_thread, NULL, live_ram_serve, NULL)) {
        close(live_ram_listener);
        live_ram_listener = -1;
        unlink(live_ram_socket_path);
        live_ram_unmap(live_ram_pointer, live_ram_size, false, 0);
        live_ram_pointer = NULL;
        return 70;
    }
    fprintf(stderr,
            "NonUI main RAM reader ready; refuses reads while running\n");
    return 0;
}

static void stop_nonui_live_ram(void) {
    if (live_ram_listener < 0)
        return;
    atomic_store(&live_ram_done, true);
    atomic_store(&live_tcg_disk_directions, 0);

    bool locked = live_disk_enabled && live_disk_bql_locked();
    if (locked)
        live_disk_bql_unlock();
    pthread_join(live_ram_thread, NULL);
    if (locked)
        live_disk_bql_lock(__FILE__, __LINE__);
    log_live_tcg_disk();
    close(live_ram_listener);
    live_ram_listener = -1;
    unlink(live_ram_socket_path);
    live_ram_unmap(live_ram_pointer, live_ram_size, false, 0);
    live_ram_pointer = NULL;
}
