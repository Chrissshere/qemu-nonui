import hashlib
import json
import os
import pathlib
import resource
import re
import socket
import signal
import struct
import subprocess
import sys
import time
import traceback
import threading
from arm64_vm import (
    register_numbers,
    walk_4k,
    unix_syscall,
    save_guest_call_state,
    restore_guest_call_state,
)
from cache_trust import audit_cache, loaded_trust_node, embedded_cache_trust
from guest_graphics_inspect import (
    OriginalCache,
    read_user_memory,
    saved_user_state,
    user_backtrace,
    process_user_threads,
    matches_switchboard_menu_caller,
)
from guest_live_transport import LiveGuestBridge, LiveDisplayClosed, rgba_png
from live_frame_stream import LiveFrameStream
from live_ram_reader import LiveRAMReader
from device_tree import device_tree
from firmware import KERNEL_HASH

profile, RUN, IPC, runner, engine, working = map(pathlib.Path, sys.argv[1:7])
LIVE_BUDGET = int(sys.argv[7])
LIVE_FRAME_SOCKET = IPC / "frames.sock"
DISK_READ_CALL = 0xFFFFFF800063FE28
DISK_WRITE_CALL = 0xFFFFFF800063FEE4
ROOT_IMAGE = profile / "root.hfs"
graphics_cache = OriginalCache(profile / "dyld_shared_cache_arm64")
cache_audit = audit_cache(profile / "dyld_shared_cache_arm64")
kernel = (profile / "kernelcache.macho").read_bytes()
assert hashlib.sha256(kernel).hexdigest() == KERNEL_HASH
assert not embedded_cache_trust(kernel)
cache_audit["present_in_original_amfi_trust_list"] = False
assert struct.unpack_from("<II", kernel) == (0xFEEDFACF, 0x100000C)
segments = []
entry = None
offset = 32
for _ in range(struct.unpack_from("<I", kernel, 16)[0]):
    command, size = struct.unpack_from("<II", kernel, offset)
    assert size >= 8 and offset + size <= len(kernel)
    if command == 25:
        name = kernel[offset + 8 : offset + 24].split(b"\x00")[0].decode()
        va, vsize, fileoff, fsize = struct.unpack_from("<QQQQ", kernel, offset + 24)
        if vsize:
            assert fsize <= vsize and fileoff + fsize <= len(kernel)
            segments.append((name, va, vsize, fileoff, fsize))
    elif command == 5:
        entry = struct.unpack_from("<Q", kernel, offset + 0x110)[0]
    offset += size
assert entry is not None
PA = 0x40200000
VA = 0xFFFFFF8000200000
RAM_SIZE = 0x1FE00000
ARGS_PA = 0x43000000
DT_PA = 0x43010000
TABLES_PA = 0x44000000
RAMDISK_PA = 0x80000000
root_size = ROOT_IMAGE.stat().st_size
assert root_size == 0x50000000
ENTRY_PA = entry - VA + PA
end = max((va + size for _, va, size, _, _ in segments))
flat = bytearray(end - VA)
for name, va, vsize, fileoff, fsize in segments:
    start = va - VA
    assert start >= 0 and start + vsize <= len(flat)
    flat[start : start + fsize] = kernel[fileoff : fileoff + fsize]
entry_bytes = bytes(flat[ENTRY_PA - PA : ENTRY_PA - PA + 32])
assert entry_bytes[:4] == bytes.fromhex("f40300aa")
lowest_va = min((segment[1] for segment in segments))
LOAD_PA = PA + lowest_va - VA
(RUN / "kernel-flat.bin").write_bytes(flat[lowest_va - VA :])
args = bytearray(0x1000)
struct.pack_into("<HH", args, 0, 1, 1)
struct.pack_into("<QQQQ", args, 8, VA, PA, RAM_SIZE, TABLES_PA)
tree = json.loads((profile / "devicetree.json").read_text())
dt, MMIO_REGISTER_WINDOWS = device_tree(tree, PA, RAM_SIZE, RAMDISK_PA, root_size)
(RUN / "devicetree.bin").write_bytes(dt)
struct.pack_into("<Q", args, 96, VA + DT_PA - PA)
struct.pack_into("<I", args, 104, len(dt))
bootline = (
    b"debug=0x14e keepsyms=1 serial=3 cpus=1 jcon=1 rd=md0 no-effaceable-storage=1"
)
args[108 : 108 + len(bootline)] = bootline
FB_PA = 0x70000000
FB_WIDTH, FB_HEIGHT = (640, 1136)
FB_ROW_BYTES = FB_WIDTH * 4
FB_SIZE = FB_HEIGHT * FB_ROW_BYTES
assert PA + RAM_SIZE <= FB_PA
assert FB_PA + FB_SIZE <= RAMDISK_PA or FB_PA >= RAMDISK_PA + root_size
video_display = 1
struct.pack_into(
    "<6Q", args, 40, FB_PA, video_display, FB_ROW_BYTES, FB_WIDTH, FB_HEIGHT, 32
)
assert struct.unpack_from("<6Q", args, 40) == (
    FB_PA,
    video_display,
    FB_ROW_BYTES,
    FB_WIDTH,
    FB_HEIGHT,
    32,
)
(RUN / "bootargs.bin").write_bytes(args)
sockpath = IPC / "gdb.sock"
live_ram_path = IPC / "ram.sock"
live_ram = None
live_ram_verified_owners = set()
command = [
    str(runner),
    "-machine",
    "virt,secure=off,virtualization=off,gic-version=2",
    "-cpu",
    "cortex-a57",
    "-accel",
    "tcg,thread=single",
    "-m",
    "4G",
    "-smp",
    "1",
    "-display",
    "none",
    "-serial",
    "none",
    "-monitor",
    "none",
    "-nic",
    "none",
    "-audio",
    "driver=none",
    "-S",
    "-gdb",
    "unix:" + str(sockpath) + ",server=on,wait=off",
    "-no-reboot",
    "-device",
    "loader,file="
    + str(RUN / "kernel-flat.bin")
    + ",addr="
    + hex(LOAD_PA)
    + ",force-raw=on",
    "-device",
    "loader,file="
    + str(RUN / "bootargs.bin")
    + ",addr="
    + hex(ARGS_PA)
    + ",force-raw=on",
    "-device",
    "loader,file="
    + str(RUN / "devicetree.bin")
    + ",addr="
    + hex(DT_PA)
    + ",force-raw=on",
    "-device",
    "loader,file=" + str(ROOT_IMAGE) + ",addr=" + hex(RAMDISK_PA) + ",force-raw=on",
    "-d",
    "int,unimp,guest_errors",
    "-D",
    str(RUN / "qemu.log"),
]
report = {
    "build": "11A24580o",
    "kernel_sha256": KERNEL_HASH,
    "events": [],
    "syscall_histogram": {},
    "observed_processes": {},
    "service_events_count": 0,
    "mmio_windows": [
        {"base": hex(lo), "bytes": hi - lo} for lo, hi in MMIO_REGISTER_WINDOWS
    ],
    "native_ramdisk_copy": dict(
        direct_mode_requested=True,
        reads=0,
        writes=0,
        bytes=0,
        seconds=0.0,
        verified_directions={},
        direct_directions={},
        fallback_copies=0,
    ),
}
for output_name in ("service-events.jsonl", "userland-output.txt"):
    (RUN / output_name).write_bytes(b"")
guest_process_log = (RUN / "guest-processes.log").open("w", buffering=1)
console = (RUN / "console.log").open("wb")
child_environment = {
    name: value for name, value in os.environ.items() if not name.startswith("NONUI_")
}
child_environment.update(
    DYLD_FRAMEWORK_PATH=str(engine.parents[3]),
    NONUI_QEMU_ENGINE=str(engine),
    NONUI_BUTTON_PAD_PULLUPS="1",
    NONUI_ADBE0_TIMING_ACK="1",
    NONUI_I2C_CHESTNUT="1",
    NONUI_LIVE_RAM_SOCKET=str(live_ram_path),
    NONUI_LIVE_DISK_COPY="1",
    NONUI_LIVE_DISK_CALL_SITES="1",
    NONUI_LIVE_TCG_DISK="1",
    NONUI_SGX_REVISION="1",
    NONUI_SGX_ACK="1",
    NONUI_PMGR_ACK="1",
    NONUI_MMIO_WINDOWS=",".join(
        (f"{lo:x}:{hi - lo:x}" for lo, hi in MMIO_REGISTER_WINDOWS)
    ),
    NONUI_TIMER_FIQ="1",
    NONUI_WATCHDOG_SECONDS=str(LIVE_BUDGET + 20),
    NONUI_LIVE_SESSION="1",
)
for site, word in ((DISK_READ_CALL, 0x97F26612), (DISK_WRITE_CALL, 0x97F265E3)):
    assert struct.unpack_from("<I", flat, site - VA)[0] == word


def terminate_experiment(signum, frame):
    raise SystemExit(128 + signum)


signal.signal(signal.SIGTERM, terminate_experiment)
live_frame_stream = (
    LiveFrameStream(pathlib.Path(LIVE_FRAME_SOCKET)) if LIVE_FRAME_SOCKET else None
)
process = subprocess.Popen(
    command,
    stdout=console,
    stderr=subprocess.STDOUT,
    env=child_environment,
    cwd=working,
)
(IPC / "qemu.pid").write_text(str(process.pid) + "\n")
live_window_closed = threading.Event()
live_monitor_done = threading.Event()


def monitor_live_window():
    offset, partial = (0, b"")
    while not live_monitor_done.wait(0.2):
        try:
            with (IPC / "control.jsonl").open("rb") as source:
                source.seek(offset)
                data = source.read(0x10000)
                offset += len(data)
            lines = (partial + data).split(b"\n")
            partial = lines.pop()
            for line in lines:
                try:
                    closing = json.loads(line).get("type") == "shutdown"
                except (ValueError, AttributeError):
                    closing = False
                if closing:
                    live_window_closed.set()
                    if process.poll() is None:
                        process.terminate()
                    return
        except OSError:
            return


threading.Thread(target=monitor_live_window, daemon=True).start()
started_at = time.monotonic()
connection = None
received_bytes = bytearray()
guest_running = False


def receive_packet():
    while True:
        start = received_bytes.find(b"$")
        if start >= 0:
            del received_bytes[:start]
            end = received_bytes.find(b"#", 1)
            if end >= 0 and len(received_bytes) >= end + 3:
                data = bytes(received_bytes[1:end])
                checksum = bytes(received_bytes[end + 1 : end + 3])
                del received_bytes[: end + 3]
                break
        else:
            received_bytes.clear()
        chunk = connection.recv(0x4000)
        if not chunk:
            raise RuntimeError("GDB connection closed")
        received_bytes.extend(chunk)
    while True:
        assert int(checksum, 16) == sum(data) & 255
        connection.sendall(b"+")
        if data[:1] == b"O" and data != b"OK":
            report["events"].append(
                {
                    "monitor_output": bytes.fromhex(data[1:].decode()).decode(
                        errors="replace"
                    )
                }
            )
            return receive_packet()
        return data.decode()


def active_draw_profile():
    bridge = globals().get("live_bridge")
    if bridge and bridge.pending and (bridge.pending["operation"] == "render"):
        return bridge.pending.setdefault(
            "profile",
            dict(
                continue_wait_seconds=0.0, single_step_wait_seconds=0.0, stop_counts={}
            ),
        )
    return None


def packet(payload):
    global guest_running
    body = payload.encode()
    profile = active_draw_profile() if payload in ("c", "s") else None
    if profile is not None:
        before = time.monotonic()
    if payload in ("c", "s"):
        guest_running = True
    connection.sendall(b"$" + body + b"#" + f"{sum(body) & 255:02x}".encode())
    reply = receive_packet()
    if profile is not None:
        key = "continue_wait_seconds" if payload == "c" else "single_step_wait_seconds"
        profile[key] += time.monotonic() - before
    if reply[:1] in ("T", "S", "W", "X"):
        guest_running = False
    return reply


def regs():
    return bytearray.fromhex(packet("g"))


def write_regs(registers):
    assert packet("G" + registers.hex()) == "OK"


def pc(registers):
    return struct.unpack_from("<Q", registers, 32 * 8)[0]


def breakpoint(address, add=True):
    assert packet(("Z" if add else "z") + "0," + f"{address:x},4") == "OK"


def write_memory(address, data):
    for offset in range(0, len(data), 0x400):
        chunk = data[offset : offset + 0x400]
        assert packet(f"M{address + offset:x},{len(chunk):x}:" + chunk.hex()) == "OK"


def read_memory(address, count):
    result = bytearray()
    for offset in range(0, count, 0x800):
        length = min(0x800, count - offset)
        response = packet(f"m{address + offset:x},{length:x}")
        assert not response.startswith("E"), (
            f"Memory read failed at {address + offset:#x}: {response}"
        )
        chunk = bytes.fromhex(response)
        assert len(chunk) == length
        result += chunk
    return bytes(result)


def native_ramdisk_copy(source, destination, count, *, allow_direct=False):
    global live_ram
    if live_ram is None:
        live_ram = LiveRAMReader(live_ram_path)
    stats = report["native_ramdisk_copy"]
    direction = "reads" if RAMDISK_PA <= source < RAMDISK_PA + root_size else "writes"
    started = time.monotonic()
    prior = stats["verified_directions"].get(direction, {})
    verify = not prior.get("native_copy")
    copied = False if verify else live_ram.copy_disk(source, destination, count)
    if verify or not copied:
        assert packet("Qqemu.PhyMemMode:1") == "OK"
        try:
            expected = read_memory(source, count)
            if not prior and direction == "reads" and (stats["writes"] == 0):
                with ROOT_IMAGE.open("rb") as image:
                    image.seek(source - RAMDISK_PA)
                    assert image.read(count) == expected, (
                        "Loaded HFS bytes differ from the selected image"
                    )
            if verify:
                copied = live_ram.copy_disk(source, destination, count)
            if not copied:
                write_memory(destination, expected)
                stats["fallback_copies"] += 1
            assert read_memory(destination, count) == expected, (
                "RAM-disk copy differs from GDB readback"
            )
        finally:
            assert packet("Qqemu.PhyMemMode:0") == "OK"
        if verify:
            stats["verified_directions"][direction] = dict(
                bytes=count,
                sha256=hashlib.sha256(expected).hexdigest(),
                native_copy=copied,
            )
    stats[direction] += 1
    stats["bytes"] += count
    stats["seconds"] += time.monotonic() - started
    if (
        allow_direct
        and copied
        and stats.get("direct_mode_requested")
        and (direction not in stats["direct_directions"])
    ):
        stats["direct_directions"][direction] = live_ram.arm_direct_disk_copy(
            1 if direction == "reads" else 2
        )
    return not prior or (verify and copied)


def capture_console():
    pram = bytearray()
    assert packet("Qqemu.PhyMemMode:1") == "OK"
    try:
        pram = read_memory(PA + 0x2800000, 0x10000)
    finally:
        assert packet("Qqemu.PhyMemMode:0") == "OK"
    (RUN / "pram-console.bin").write_bytes(pram)
    import re

    console_runs = [
        x.decode(errors="replace")
        for x in re.findall(b"[\\x09\\x0a\\x0d\\x20-\\x7e]{12,}", pram)
    ]
    (RUN / "pram-console-text.txt").write_text("\n".join(console_runs) + "\n")
    report["console_ram_bytes_captured"] = len(pram)


def capture_framebuffer():
    assert packet("Qqemu.PhyMemMode:1") == "OK"
    try:
        raw = read_memory(FB_PA, FB_SIZE)
    finally:
        assert packet("Qqemu.PhyMemMode:0") == "OK"
    nonzero = sum((byte != 0 for byte in raw))
    report["video"] = {
        "base_pa": hex(FB_PA),
        "width": FB_WIDTH,
        "height": FB_HEIGHT,
        "row_bytes": FB_ROW_BYTES,
        "depth": 32,
        "nonzero_bytes": nonzero,
        "guest_framebuffer_written": nonzero > 0,
        "sha256": hashlib.sha256(raw).hexdigest(),
    }
    (RUN / "guest-framebuffer.bgra").write_bytes(raw)
    bmp_size = 54 + len(raw)
    bitmap_header = (
        b"BM"
        + struct.pack("<IHHI", bmp_size, 0, 0, 54)
        + struct.pack(
            "<IiiHHIIiiII",
            40,
            FB_WIDTH,
            -FB_HEIGHT,
            1,
            32,
            0,
            len(raw),
            2835,
            2835,
            0,
            0,
        )
    )
    (RUN / "guest-framebuffer.bmp").write_bytes(bitmap_header + raw)


def fetch_register_xml(name):
    result = ""
    while True:
        chunk = packet(f"qXfer:features:read:{name}:{len(result):x},fff")
        assert chunk[0] in "ml", chunk
        result += chunk[1:]
        if chunk[0] == "l":
            return result


guest_verified_thread_owners = {}


def capture_active_guest_process(from_user=False):
    result = {}
    physical_mode = False
    try:
        memory_read = read_memory
        if from_user:
            number, bits = system_registers["TPIDR_EL1"]
            assert bits == 64
            tpidr = int.from_bytes(bytes.fromhex(packet(f"p{number:x}")), "little")
            assert tpidr >= 0xFFFFFF0000000000
            result.update(tpidr_el1=hex(tpidr), thread=hex(tpidr))
            known = guest_verified_thread_owners.get(tpidr)
            if known:
                result.update(known)
                result["identity_source"] = "previously verified EL1 thread"
            else:
                result["context_note"] = "EL0 thread not yet identified at EL1"
            return result
        number, bits = system_registers["TPIDR_EL1"]
        assert bits == 64
        tpidr = int.from_bytes(bytes.fromhex(packet(f"p{number:x}")), "little")
        result["tpidr_el1"] = hex(tpidr)
        assert tpidr >= 0xFFFFFF0000000000
        thread = tpidr
        result["thread"] = hex(thread)
        assert thread >= 0xFFFFFF0000000000
        task = struct.unpack("<Q", memory_read(thread + 0x6A0, 8))[0]
        result["task"] = hex(task)
        assert task >= 0xFFFFFF0000000000
        proc = struct.unpack("<Q", memory_read(task + 0x2E0, 8))[0]
        result["proc"] = hex(proc)
        assert proc >= 0xFFFFFF0000000000
        pid = struct.unpack("<I", memory_read(proc + 16, 4))[0]
        ppid = struct.unpack("<I", memory_read(proc + 40, 4))[0]
        assert pid < 1000000 and ppid < 1000000
        name = (
            memory_read(proc + 0x2AC, 17).split(b"\x00", 1)[0].decode(errors="replace")
        )
        result.update(pid=pid, ppid=ppid, comm=name)
        guest_verified_thread_owners[tpidr] = {
            "pid": pid,
            "ppid": ppid,
            "comm": name,
            "proc": hex(proc),
            "task": hex(task),
        }
    except (
        AssertionError,
        KeyError,
        IndexError,
        ValueError,
        struct.error,
    ) as exception:
        result["context_error"] = str(exception)
    finally:
        if physical_mode:
            assert packet("Qqemu.PhyMemMode:0") == "OK"
    return result


def capture_guest_process_list():
    entries, visited = ([], set())
    try:
        ptr = struct.unpack("<Q", read_memory(0xFFFFFF8000822ED8, 8))[0]
        while ptr and len(entries) < 180:
            if ptr in visited:
                raise ValueError("process-list cycle")
            if ptr < 0xFFFFFF0000000000 or ptr % 8:
                raise ValueError("invalid kernel process pointer " + hex(ptr))
            visited.add(ptr)
            header = read_memory(ptr, 48)
            pid = struct.unpack_from("<I", header, 16)[0]
            ppid = struct.unpack_from("<I", header, 40)[0]
            name = (
                read_memory(ptr + 0x2AC, 17)
                .split(b"\x00", 1)[0]
                .decode(errors="replace")
            )
            if pid >= 1000000:
                raise ValueError("invalid PID")
            entries.append({"pid": pid, "ppid": ppid, "comm": name})
            if name == "SwitchBoard":
                for owner in guest_verified_thread_owners.values():
                    if owner["pid"] == pid and owner["proc"] == hex(ptr):
                        owner.update(comm=name, ppid=ppid)
            ptr = struct.unpack_from("<Q", header, 0)[0]
        return {"processes": entries, "truncated": bool(ptr)}
    except (AssertionError, IndexError, ValueError, struct.error) as exc:
        return {"processes": entries, "read_error": str(exc)}


def capture_graphics_thread_stacks():
    result = {"after_seconds": time.monotonic() - started_at, "processes": []}
    number, _ = system_registers["TCR_EL1"]
    tcr = int.from_bytes(bytes.fromhex(packet(f"p{number:x}")), "little")
    assert tcr >> 14 & 3 == 0
    bits = 64 - (tcr & 63)
    ptr = struct.unpack("<Q", read_memory(0xFFFFFF8000822ED8, 8))[0]
    visited = set()
    while ptr and ptr not in visited and (len(visited) < 180):
        visited.add(ptr)
        name = (
            read_memory(ptr + 0x2AC, 17).split(b"\x00", 1)[0].decode(errors="replace")
        )
        if name in (
            "SwitchBoard",
            "hidd.nonui",
            "notifyd",
            "sh",
            "sleep",
            "notifyutil",
        ) or (
            name in report.get("live_app_exec_names", [])
            or (live_bridge and name == live_bridge.process.get("comm"))
        ):
            item = {
                "comm": name,
                "pid": struct.unpack("<I", read_memory(ptr + 16, 4))[0],
            }
            try:
                item.update(process_user_threads(read_memory, ptr))
                if name not in (
                    "SwitchBoard",
                    "hidd.nonui",
                    "notifyd",
                    "sh",
                    "sleep",
                    "notifyutil",
                ):
                    entry = struct.unpack(
                        "<Q", read_memory(int(item["vm_map"], 16) + 24, 8)
                    )[0]
                    entries, seen_entries = ([], set())
                    while (
                        entry not in seen_entries
                        and entry >= 0xFFFFFF0000000000
                        and (len(seen_entries) < 150)
                    ):
                        seen_entries.add(entry)
                        nxt, prev, begin, end, flags = struct.unpack(
                            "<5Q", read_memory(entry, 40)
                        )
                        if 0x1000 <= begin < end <= 0x200000000:
                            entries.append(dict(begin=hex(begin), end=hex(end)))
                        if nxt == int(item["vm_map"], 16) + 24:
                            break
                        entry = nxt
                    item["low_vm_regions"] = entries
                assert packet("Qqemu.PhyMemMode:1") == "OK"
                try:
                    ttbr = int(item["ttbr0_physical"], 16)

                    def reader(address, size):
                        return read_user_memory(read_memory, ttbr, address, size, bits)

                    for region in item.get("low_vm_regions", []):
                        try:
                            header = reader(int(region["begin"], 16), 96)
                            if struct.unpack_from("<I", header)[0] == 0xFEEDFACF:
                                region["macho_header_bytes"] = header.hex()
                                if struct.unpack_from("<I", header, 12)[0] == 7:
                                    item["dyld_runtime_header"] = region["begin"]
                        except (ValueError, AssertionError, struct.error):
                            pass
                    for thread in item["threads"]:
                        if "user_pc" not in thread:
                            continue
                        thread["user_backtrace"] = user_backtrace(thread, reader, 16)
                        if graphics_cache and report.get(
                            "skank_verified_shared_cache_slide"
                        ):
                            slide = int(
                                report["skank_verified_shared_cache_slide"]["slide"], 16
                            )
                            for frame in thread["user_backtrace"]:
                                if "pc" in frame:
                                    description = graphics_cache.describe(
                                        int(frame["pc"], 16), slide
                                    )
                                    if description:
                                        frame.update(description)
                finally:
                    assert packet("Qqemu.PhyMemMode:0") == "OK"
            except (AssertionError, ValueError, struct.error) as exc:
                item["inspection_error"] = str(exc)
            result["processes"].append(item)
        ptr = struct.unpack("<Q", read_memory(ptr, 8))[0]
    report.setdefault("graphics_saved_thread_snapshots", []).append(result)
    with (RUN / "graphics-thread-stacks.jsonl").open("a") as output:
        output.write(json.dumps(result) + "\n")


def capture_user_translation(address):
    values = {}
    for name in ("TTBR0_EL1", "TCR_EL1"):
        number, bits = system_registers[name]
        value = bytes.fromhex(packet(f"p{number:x}"))
        assert len(value) * 8 == bits
        values[name] = int.from_bytes(value, "little")
    assert values["TCR_EL1"] >> 14 & 3 == 0, "Only 4 KiB tables supported"
    assert packet("Qqemu.PhyMemMode:1") == "OK"
    try:
        translation = walk_4k(
            read_memory, values["TTBR0_EL1"], address, 64 - (values["TCR_EL1"] & 63)
        )
        if translation["valid"]:
            translation["physical_bytes"] = read_memory(
                int(translation["physical"], 16), 32
            ).hex()
    finally:
        assert packet("Qqemu.PhyMemMode:0") == "OK"
    translation["registers"] = {key: hex(value) for key, value in values.items()}
    return translation


def capture_graphics_user_context(owner, trap):
    observation = {"trap": trap, "process": owner}
    try:
        thread = int(owner["thread"], 16)
        saved_ptr = struct.unpack("<Q", read_memory(thread + 0x660, 8))[0]
        observation["saved_ptr"] = hex(saved_ptr)
        assert saved_ptr >= 0xFFFFFF0000000000, "Invalid saved user state pointer"
        state = saved_user_state(read_memory(saved_ptr, 0x128))
        observation.update(state)
        values = {}
        for name in ("TTBR0_EL1", "TCR_EL1"):
            number, bits = system_registers[name]
            assert bits == 64
            values[name] = int.from_bytes(
                bytes.fromhex(packet(f"p{number:x}")), "little"
            )
        assert values["TCR_EL1"] >> 14 & 3 == 0, "Only 4 KiB tables supported"
        observation["translation_registers"] = {k: hex(v) for k, v in values.items()}
        assert packet("Qqemu.PhyMemMode:1") == "OK"
        try:

            def user_read(address, size):
                return read_user_memory(
                    read_memory,
                    values["TTBR0_EL1"],
                    address,
                    size,
                    64 - (values["TCR_EL1"] & 63),
                )

            observation["user_backtrace"] = user_backtrace(state, user_read)
            if graphics_cache and "skank_verified_shared_cache_slide" not in report:
                original_stubs = {
                    0x18ABCDCB8: "_mach_msg_trap",
                    0x18ABCDCC4: "_mach_msg_overwrite_trap",
                    0x18ABCDCF4: "_semaphore_wait_trap",
                }
                user_pc = int(state["user_pc"], 16)
                for original, name in original_stubs.items():
                    slide = user_pc - (original + 8)
                    if slide < 0 or slide > 0x20000000 or slide & 0xFFF:
                        continue
                    try:
                        actual = user_read(original + slide, 12)
                        expected = graphics_cache.read(original, 12)
                        header_va = graphics_cache.images[
                            "/usr/lib/system/libsystem_kernel.dylib"
                        ]
                        actual_header = user_read(header_va + slide, 32)
                        assert actual == expected, "Original trap instructions differ"
                        assert actual_header == graphics_cache.read(header_va, 32), (
                            "Original library header differs"
                        )
                        report["skank_verified_shared_cache_slide"] = {
                            "slide": hex(slide),
                            "user_pc": hex(user_pc),
                            "original_stub": name,
                            "original_stub_va": hex(original),
                            "runtime_stub_va": hex(original + slide),
                            "guest_stub_bytes": actual.hex(),
                            "runtime_macho_header_va": hex(header_va + slide),
                            "guest_macho_header_bytes": actual_header.hex(),
                            "evidence": "saved EL0 PC, TTBR0 physical page walk, original instructions and library header",
                        }
                    except (AssertionError, ValueError, struct.error) as exc:
                        observation.setdefault("slide_validation_errors", []).append(
                            str(exc)
                        )
            proof = report.get("skank_verified_shared_cache_slide")
            if proof and graphics_cache:
                slide = int(proof["slide"], 16)
                for frame in observation["user_backtrace"]:
                    if "pc" in frame:
                        description = graphics_cache.describe(
                            int(frame["pc"], 16), slide
                        )
                        if description:
                            frame.update(description)
        finally:
            assert packet("Qqemu.PhyMemMode:0") == "OK"
    except (AssertionError, KeyError, ValueError, struct.error) as exc:
        observation["inspection_error"] = str(exc)
    return observation


def read_current_user_bytes(address, size):
    values = {}
    for name in ("TTBR0_EL1", "TCR_EL1"):
        number, bits = system_registers[name]
        assert bits == 64
        values[name] = int.from_bytes(bytes.fromhex(packet(f"p{number:x}")), "little")
    assert values["TCR_EL1"] >> 14 & 3 == 0
    bits = 64 - (values["TCR_EL1"] & 63)
    if live_frame_stream and live_ram:
        try:
            return live_ram.read_user(values["TTBR0_EL1"], address, size, bits)
        except ValueError:
            pass
    assert packet("Qqemu.PhyMemMode:1") == "OK"
    try:
        return read_user_memory(read_memory, values["TTBR0_EL1"], address, size, bits)
    finally:
        assert packet("Qqemu.PhyMemMode:0") == "OK"


def capture_original_bitmap(
    pointer,
    bitmap,
    owner,
    read_bytes=None,
    origin="original CGBitmapContextCreate and CGBitmapContextGetData",
    verify_bytes=None,
    bulk=False,
):
    capture_started = time.monotonic()
    record = dict(bitmap, data_pointer=hex(pointer), process=owner, origin=origin)
    width, height, stride = (bitmap["width"], bitmap["height"], bitmap["row_bytes"])
    length = stride * height
    if not pointer or not (
        0 < width <= 0x1000 and 0 < height <= 0x1000 and (0 < length <= 0x400000)
    ):
        record["not_captured"] = "no verified bounded image layout"
        return record
    try:
        reader = read_bytes or read_current_user_bytes
        if bulk:
            pixels = reader(pointer, length)
        else:
            pixels = b"".join(
                (
                    reader(pointer + off, min(0x10000, length - off))
                    for off in range(0, length, 0x10000)
                )
            )
        record["read_pixels_seconds"] = time.monotonic() - capture_started
        if verify_bytes:
            verify_started = time.monotonic()
            expected = b"".join(
                (
                    verify_bytes(pointer + off, min(0x10000, length - off))
                    for off in range(0, length, 0x10000)
                )
            )
            assert pixels == expected, (
                "Native RAM pixels differ from stopped GDB capture"
            )
            record["native_ram_gdb_byte_equality"] = True
            record["native_ram_gdb_bytes_compared"] = length
            record["gdb_comparison_seconds"] = time.monotonic() - verify_started
        if (
            live_frame_stream
            and width == LiveFrameStream.width
            and (height == LiveFrameStream.height)
            and (stride == width * 4)
            and (bitmap["bits_per_component"] == 8)
            and (bitmap["bitmap_info"] & 0x701F == 1)
            and (
                bitmap.get("capture_reason")
                in (
                    "_CGBitmapContextCreateImage entry",
                    "completed original live render",
                )
            )
        ):
            frames = report.setdefault("live_guest_frames", [])
            sequence = len(frames)
            visible = any((pixels[channel::4].strip(b"\x00") for channel in range(3)))
            record["visible_rgb"] = visible
            if visible or frames:
                previous = live_frame_stream.latest
                changed = previous is None or previous[1] != pixels
                live_frame_stream.publish(sequence, pixels)
                published_at = time.monotonic()
                frame = dict(
                    sequence=sequence,
                    host_monotonic=published_at,
                    source=origin,
                    width=width,
                    height=height,
                    process=owner.get("comm"),
                    pid=owner.get("pid"),
                    visible_rgb=visible,
                    content_changed=changed,
                    read_pixels_seconds=record["read_pixels_seconds"],
                    capture_export_seconds=published_at - capture_started,
                )
                frames.append(frame)
                if (
                    sequence < 2
                    or verify_bytes
                    or (
                        report.get("live_save_input_frame")
                        and report.get("live_raw_samples", 0) < 64
                    )
                ):
                    name = f"original-guest-rgba-{sequence:05d}.bin"
                    (RUN / name).write_bytes(pixels)
                    record.update(
                        raw_file=name, sha256=hashlib.sha256(pixels).hexdigest()
                    )
                    frame.update(raw_file=name, raw_sha256=record["sha256"])
                    report["live_raw_samples"] = report.get("live_raw_samples", 0) + 1
                report["live_save_input_frame"] = False
                if (
                    sequence < 2
                    or owner.get("pid") != frames[-2]["pid"]
                    or sequence % 15 == 0
                ):
                    status = IPC / "live-status.json.tmp"
                    status.write_text(json.dumps(dict(state="running", frame=sequence)))
                    status.replace(IPC / "live-status.json")
                with (RUN / "live-frames.jsonl").open("a") as output:
                    output.write(json.dumps(frame) + "\n")
            return record
        record.update(
            nonzero_bytes=len(pixels) - pixels.count(0),
            sha256=hashlib.sha256(pixels).hexdigest(),
        )
        if record["nonzero_bytes"]:
            number = len(report.get("original_guest_bitmap_captures", []))
            name = f"original-guest-bitmap-{number:02d}"
            frame_index = len(report.get("live_guest_frames", []))
            retain_raw = (
                frame_index < 8
                or frame_index % 30 == 0
                or report.get("live_save_input_frame")
            ) and report.get("live_raw_samples", 0) < 64
            if retain_raw:
                (RUN / (name + ".bin")).write_bytes(pixels)
                record["raw_file"] = name + ".bin"
                report["live_raw_samples"] = report.get("live_raw_samples", 0) + 1
            info = bitmap["bitmap_info"]
            if (
                width == 640
                and height == 1136
                and (bitmap["bits_per_component"] == 8)
                and (info & 0x701F == 1)
                and (
                    bitmap.get("capture_reason")
                    in (
                        "_CGBitmapContextCreateImage entry",
                        "completed original live render",
                    )
                )
            ):
                rgba = b"".join(
                    (pixels[y * stride : y * stride + width * 4] for y in range(height))
                )
                rgb_mask = 0xFFFFFF if sys.byteorder == "little" else 0xFFFFFF00
                rgb_count = sum(
                    (word & rgb_mask != 0 for word in memoryview(rgba).cast("I"))
                )
                record["rgb_nonzero_pixels"] = rgb_count
                png = rgba_png(pixels, width, height, stride)
                (RUN / (name + ".png")).write_bytes(png)
                temporary = RUN / "live-frame.png.tmp"
                temporary.write_bytes(png)
                temporary.replace(RUN / "live-frame.png")
                frames = report.setdefault("live_guest_frames", [])
                frame = dict(
                    sequence=len(frames),
                    host_monotonic=time.monotonic(),
                    raw_sha256=record["sha256"],
                    png_sha256=hashlib.sha256(png).hexdigest(),
                    source=record["origin"],
                    width=width,
                    height=height,
                    rgb_nonzero_pixels=rgb_count,
                    png_file=name + ".png",
                    read_pixels_seconds=record["read_pixels_seconds"],
                    capture_export_seconds=time.monotonic() - capture_started,
                )
                frames.append(frame)
                report["live_save_input_frame"] = False
                status = IPC / "live-status.json.tmp"
                status.write_text(
                    json.dumps(dict(state="running", frame=frame["sequence"]))
                )
                status.replace(IPC / "live-status.json")
                with (RUN / "live-frames.jsonl").open("a") as output:
                    output.write(json.dumps(frame) + "\n")
            if (
                bitmap["bits_per_component"] == 8
                and info & 0x7000 == 0x2000
                and (info & 31 in (2, 4, 6))
                and (stride >= width * 4)
            ):
                bgra = b"".join(
                    (pixels[y * stride : y * stride + width * 4] for y in range(height))
                )
                record["rgb_nonzero_pixels"] = sum(
                    (any(bgra[i : i + 3]) for i in range(0, len(bgra), 4))
                )
                header = b"BM" + struct.pack("<IHHI", 54 + len(bgra), 0, 0, 54)
                header += struct.pack(
                    "<IiiHHIIiiII",
                    40,
                    width,
                    -height,
                    1,
                    32,
                    0,
                    len(bgra),
                    2835,
                    2835,
                    0,
                    0,
                )
                (RUN / (name + ".bmp")).write_bytes(header + bgra)
                record["displayable_bgra_file"] = name + ".bmp"
        return record
    except (AssertionError, ValueError, struct.error) as exc:
        record["read_error"] = str(exc)
        return record


def capture_registered_guest_bitmap(bitmap, reason):
    global live_ram
    record = dict(bitmap, capture_reason=reason)
    try:
        ttbr = int(bitmap["ttbr0_el1"], 16)
        bits = bitmap["user_address_bits"]
        assert packet("Qqemu.PhyMemMode:1") == "OK"
        try:
            if child_environment.get("NONUI_LIVE_RAM_SOCKET") and live_ram is None:
                live_ram = LiveRAMReader(live_ram_path)
            descriptors = {}

            def read_capture_physical(address, size):
                physical_reader = (
                    live_ram.read
                    if live_ram and live_ram.covers(address, size)
                    else read_memory
                )
                if size == 8:
                    if address not in descriptors:
                        descriptors[address] = physical_reader(address, size)
                    return descriptors[address]
                return physical_reader(address, size)

            def reader(address, size):
                return read_user_memory(
                    read_capture_physical, ttbr, address, size, bits
                )

            if live_frame_stream and live_ram:
                paged_reader = reader

                def reader(address, size):
                    try:
                        return live_ram.read_user(ttbr, address, size, bits)
                    except ValueError:
                        return b"".join(
                            (
                                paged_reader(address + off, min(0x10000, size - off))
                                for off in range(0, size, 0x10000)
                            )
                        )

            context = reader(int(bitmap["context"], 16), 40)
            assert struct.unpack_from("<I", context, 16)[0] == 0x43545854, (
                "context no longer CTXT"
            )
            assert struct.unpack_from("<I", context, 24)[0] == 4, (
                "context no longer bitmap type4"
            )
            info = reader(struct.unpack_from("<Q", context, 32)[0], 96)
            record["inspected_info_bytes"] = info.hex()
            record["inspected_dimensions"] = struct.unpack_from("<QQ", info, 8)
            record["original_creation_layout"] = {
                k: bitmap[k]
                for k in (
                    "width",
                    "height",
                    "row_bytes",
                    "bitmap_info",
                    "bits_per_component",
                )
            }
            record["metadata_changed_since_original_create"] = record[
                "inspected_dimensions"
            ] != (bitmap["width"], bitmap["height"])
            record["width"], record["height"] = record["inspected_dimensions"]
            record["bitmap_info"] = struct.unpack_from("<I", info, 40)[0]
            (
                record["bits_per_pixel"],
                record["bits_per_component"],
                record["row_bytes"],
            ) = struct.unpack_from("<QQQ", info, 72)
            assert (
                record["bits_per_pixel"] == 32 and record["bits_per_component"] == 8
            ), "unsupported live bitmap pixel format"
            assert record["row_bytes"] >= record["width"] * 4, (
                "invalid live bitmap stride"
            )
            pointer = struct.unpack_from("<Q", info, 64)[0]
            owner_key = (ttbr, bitmap["process_at_creation"].get("pid"))
            verify = (
                live_ram
                and owner_key not in live_ram_verified_owners
                and (reason == "completed original live render")
            )
            gdb_descriptors = {}

            def gdb_physical(address, size):
                if size != 8:
                    return read_memory(address, size)
                if address not in gdb_descriptors:
                    gdb_descriptors[address] = read_memory(address, size)
                return gdb_descriptors[address]

            def gdb_reader(address, size):
                return read_user_memory(gdb_physical, ttbr, address, size, bits)

            record = capture_original_bitmap(
                pointer,
                record,
                bitmap["process_at_creation"],
                reader,
                "original guest CGBitmapContextCreate; original pure GetData layout; read-only TTBR0 walk",
                gdb_reader if verify else None,
                bulk=bool(live_frame_stream and live_ram),
            )
            if record.get("native_ram_gdb_byte_equality"):
                live_ram_verified_owners.add(owner_key)
                report.setdefault("native_ram_frame_verifications", []).append(
                    dict(
                        ttbr0=hex(ttbr),
                        pid=owner_key[1],
                        bytes_compared=record["native_ram_gdb_bytes_compared"],
                        sha256=record["sha256"],
                        byte_identical=True,
                    )
                )
        finally:
            assert packet("Qqemu.PhyMemMode:0") == "OK"
    except (AssertionError, KeyError, ValueError, struct.error) as exc:
        record["inspection_error"] = str(exc)
    report.setdefault("original_guest_bitmap_captures", []).append(record)
    with (RUN / "bitmap-captures.jsonl").open("a") as output:
        output.write(json.dumps(record) + "\n")


def capture_backtrace():
    import bisect

    image = (profile / "kernel-development.macho").read_bytes()
    position = 32
    symbols = []
    for _ in range(struct.unpack_from("<I", image, 16)[0]):
        kind, size = struct.unpack_from("<II", image, position)
        if kind == 2:
            symoff, count, stroff, strsize = struct.unpack_from(
                "<IIII", image, position + 8
            )
            strings = image[stroff : stroff + strsize]
            for index in range(count):
                string_index, symbol_type, _, _, value = struct.unpack_from(
                    "<IBBHQ", image, symoff + 16 * index
                )
                if value and symbol_type & 14 == 14 and (string_index < len(strings)):
                    name = (
                        strings[string_index:]
                        .split(b"\x00", 1)[0]
                        .decode(errors="replace")
                    )
                    symbols.append((value, name))
        position += size
    symbols.sort()
    addresses = [value for value, _ in symbols]

    def describe(address):
        index = bisect.bisect_right(addresses, address) - 1
        if index < 0:
            return hex(address)
        value, name = symbols[index]
        return f"{name}+0x{address - value:x}"

    registers = regs()
    current_pc = pc(registers)
    fp = struct.unpack_from("<Q", registers, 29 * 8)[0]
    frames = [{"pc": hex(current_pc), "symbol": describe(current_pc)}]
    seen = set()
    for _ in range(24):
        if fp in seen or fp < 0xFFFFFF0000000000 or fp & 7:
            break
        seen.add(fp)
        response = packet(f"m{fp:x},10")
        if response.startswith("E"):
            break
        parent, returned = struct.unpack("<QQ", bytes.fromhex(response))
        frames.append(
            {
                "pc": hex(returned),
                "symbol": describe(returned),
                "frame_pointer": hex(fp),
            }
        )
        fp = parent
    report["backtrace"] = frames


try:
    for _ in range(750):
        if sockpath.exists():
            break
        if process.poll() is not None:
            raise RuntimeError("QEMU exited before debugger startup")
        time.sleep(0.02)
    connection = socket.socket(socket.AF_UNIX)
    connection.settimeout(30)
    connection.connect(str(sockpath))
    packet("qSupported:multiprocess+;qXfer:features:read+")
    assert "aarch64" in packet("qXfer:features:read:target.xml:0,fff")
    system_registers = register_numbers(fetch_register_xml)
    primary_registers = register_numbers(fetch_register_xml, preserve_first=True)
    (RUN / "gdb-registers.json").write_text(json.dumps(system_registers, indent=2))
    assert all((name in system_registers for name in ("TTBR0_EL1", "TCR_EL1")))
    current = regs()
    struct.pack_into("<Q", current, 0, ARGS_PA)
    struct.pack_into("<Q", current, 31 * 8, 0x4FF00000)
    struct.pack_into("<Q", current, 32 * 8, ENTRY_PA)
    struct.pack_into("<I", current, 33 * 8, 0x3C5)
    write_regs(current)
    verified = regs()
    assert verified[:8] == struct.pack("<Q", ARGS_PA)
    assert pc(verified) == ENTRY_PA
    assert bytes.fromhex(packet(f"m{ENTRY_PA:x},20")) == entry_bytes
    assert bytes.fromhex(packet(f"m{ARGS_PA + 8:x},20")) == args[8:40]
    report["setup_verified"] = True
    report["events"].append(
        {"stage": "verified Mach-O mapping, boot-argument memory, X0, PC and EL1 state"}
    )
    first_hid = ENTRY_PA + (0x4240 - 0x4058)
    breakpoint(first_hid)
    stopped = packet("c")
    current = regs()
    report["events"].append(
        {
            "stage": "ran kernel to first Apple HID access",
            "stop": stopped,
            "pc": hex(pc(current)),
        }
    )
    assert pc(current) == first_hid
    breakpoint(first_hid, False)
    high_word = packet("mffffff80002e4240,4")
    assert high_word == "0cf038d5"
    report["kernel_mmu_mapping_verified"] = True
    sites = [
        0x4240,
        0x4248,
        0x424C,
        0x4258,
        0x425C,
        0x4264,
        0x4268,
        0x4274,
        0x4278,
        0x4284,
    ]
    for site in sites[1:]:
        breakpoint(ENTRY_PA + site - 0x4058)
    handoff = 0xFFFFFF80002D85AC
    breakpoint(handoff)
    apple_sysreg_values = {}
    for _ in range(16):
        current = regs()
        address = pc(current)
        if address == handoff:
            report["reached_high_virtual_handoff"] = True
            report["events"].append(
                {
                    "stage": "reached high virtual C initialization handoff",
                    "pc": hex(address),
                }
            )
            break
        if address != first_hid:
            breakpoint(address, False)
        word = int.from_bytes(bytes.fromhex(packet(f"m{address:x},4")), "little")
        assert word & 0xFFC00000 == 0xD5000000, (
            "HID shim did not read an original MRS/MSR"
        )
        register = word & 31
        sysreg = word >> 5 & 0x7FFF
        read = bool(word & 1 << 21)
        if read:
            value = apple_sysreg_values.get(sysreg, 0)
            struct.pack_into("<Q", current, register * 8, value)
        else:
            value = struct.unpack_from("<Q", current, register * 8)[0]
            apple_sysreg_values[sysreg] = value
        report["events"].append(
            {
                "stage": "HID register access shim",
                "pc": hex(address),
                "read": read,
                "system_register": hex(sysreg),
                "value": hex(value),
            }
        )
        struct.pack_into("<Q", current, 32 * 8, address + 4)
        write_regs(current)
        packet("c")
    else:
        raise RuntimeError("HID shim diagnostic exceeded bounded stop count")
    if report.get("reached_high_virtual_handoff"):
        breakpoint(handoff, False)
        milestones = {
            0xFFFFFF80005CEA74: "PE_init_platform",
            0xFFFFFF80002D872C: "PE_init_platform returned",
            0xFFFFFF80002D6E84: "cpu_init",
            0xFFFFFF80002D8CC4: "arm_vm_init",
            0xFFFFFF80002E465C: "machine_startup",
            0xFFFFFF8000232908: "panic",
            0xFFFFFF80002DE000: "EL1 synchronous exception (SP0)",
            0xFFFFFF80002DE200: "EL1 synchronous exception (SP1)",
        }
        milestones[0xFFFFFF80002F1C04] = "L4_Aux secure monitor call"
        milestones.update(
            {
                0xFFFFFF800024A43C: "kernel_bootstrap",
                0xFFFFFF80002E47D4: "machine_init",
                0xFFFFFF80002E8894: "rtclock_init",
                0xFFFFFF80005CE848: "PE_init_iokit",
                0xFFFFFF80004BF5C8: "bsd_init",
            }
        )
        milestones.update(
            {
                0xFFFFFF80005BCC2C: "IOFindBSDRoot",
                0xFFFFFF800038E6C4: "mdevadd",
                0xFFFFFF800039D8A0: "vfs_mountroot",
                0xFFFFFF800049D424: "hfs_mountroot",
                0xFFFFFF80004C20B4: "vfs_mountroot returned",
                0xFFFFFF80004D9C64: "load_init_program",
                0xFFFFFF800052EDD4: "unix_syscall from userland",
            }
        )
        skank_methods = {
            0x187594D7C: "SKUIApplication::init",
            0x187594CE0: "SKUIApplication::_setupGraphics",
            0x187595774: "SKUIApplication::buildWindow",
            0x1875959D0: "SKUIApplication::showWindow",
            0x187595290: "SKUIApplication::addLayer",
            0x1875955E0: "SKUIApplication::mainLayer",
            0x187595AF4: "SKUIApplication::showModule",
            0x1875973C4: "SKUIApplication::run",
            0x187580964: "SKLayer::setContext",
            0x187580A10: "SKLayer::context",
        }
        for at, name in skank_methods.items():
            pass
        report["original_skank_method_symbols"] = {
            hex(at): name for at, name in skank_methods.items()
        }
        report["original_skank_method_hits"] = []
        report["original_skank_method_total"] = 0
        report["skank_guest_user_execution_samples"] = []
        context_methods = graphics_cache.methods(
            "/QuartzCore", {"CAContext", "CAContextImpl", "CAWindowServer"}
        )
        wanted = (
            "context]",
            "contextWithOptions:",
            "server]",
            "_init]",
            "localContext",
            "remoteContext",
            "setClientPort:",
            "setLayer:",
            "initWithOptions:",
            "initRemoteWithOptions:",
            "setLevel:",
            "orderAbove:",
        )
        context_methods = {
            at: name
            for at, name in context_methods.items()
            if any((part in name for part in wanted))
        }
        for at, name, image in graphics_cache.symbols:
            if name in (
                "_CARenderServerStart",
                "_CARenderServerRegister",
                "_IOSurfaceCreate",
                "_IOMobileFramebufferGetMainDisplay",
                "_IOMobileFramebufferGetDisplaySize",
            ) or name.endswith("MGServerCopyAnswerWithError"):
                context_methods[at] = name
            if name in (
                "_CGBitmapContextCreate",
                "_CGBitmapContextCreateWithData",
                "_CGBitmapContextGetData",
            ):
                context_methods[at] = name
            if name in (
                "_CGBitmapContextCreateImage",
                "_CGContextRelease",
                "_CGContextFlush",
                "_CGIOSurfaceContextCreate",
                "_IOSurfaceGetBaseAddress",
                "_IOSurfaceUnlock",
            ):
                context_methods[at] = name
            if name in (
                "_FigSharedPlayerCreate",
                "_FigSharedPlayerGetDefaultEngineTopology",
                "_FigPlayerCMSessionOneTimeInitialization",
                "_FigMediaServerStart",
                "_FigMovieStartServing",
                "_FigSandboxReacquireServer",
            ):
                context_methods[at] = name
        context_methods.update(
            {
                0x187594E44: "Skank init screen setup returned",
                0x184816FC8: "Celestial AVController::init",
                0x187594E68: "Skank init AVController returned",
            }
        )
        milestones[0xFFFFFF80004D9EF4] = "original graphics process exit"
        report["original_guest_bitmap_contexts"] = {}
        report["original_guest_bitmap_captures"] = []
        context_methods.update(
            {
                0x187594CA8: "Skank capture: original Darwin notification callback",
                0x18759750C: "Skank capture: original doScreenCapture",
                0x18759AA34: "Skank capture: original writeLayerToPath",
                0x1838A7160: "Skank capture: original CALayer renderInContext",
            }
        )
        context_methods.pop(0x1838A7160, None)
        context_methods.update(
            {
                0x1875964C0: "Live input: original SKUIApplication handleEvent",
                0x187595D6C: "Live input: original SKUIApplication handleMouseEvent",
                0x1858C7AB0: "Live input: original GSSendSystemAppEvent",
                0x187585350: "Live control: original SKButton handleEvent inLayer",
                0x187587394: "Live control: original SKControl handleEvent inLayer",
                0x1875931E0: "Live control: original SKLayerModule handleEvent inLayer",
                0x187596700: "Live launch: original loadLaunchD",
                0x187596730: "Live launch: original launch plist path",
                0x1875967A8: "Live launch: original parsed job dictionary",
                0x1875968A4: "Live launch: original SMJobSubmit call",
                0x1875968A8: "Live launch: original SMJobSubmit returned",
                0x1875968CC: "Live launch: original submit error description",
                0x1858C7788: "Live foreground: original GSEventRunModal",
            }
        )
        context_methods.update(
            {
                0x184817040: "AV startup: initWithQueue:fmpType:error:",
                0x184817100: "AV startup: superclass initWithError returned",
                0x184817124: "AV startup: FigSharedPlayerCreate returned",
                0x1848174D8: "AV startup: final controller object",
                0x1826434D0: "AV startup: first remote player RPC returned",
                0x182643580: "AV startup: retry remote player RPC returned",
                0x181AA2664: "AV startup: original sandbox timeout preference read",
                0x181A6847C: "AV startup: original media-server timeout preference read",
            }
        )
        context_methods.update(
            {
                0x187597B18: "HID startup: original SKHIDController init",
                0x187597E1C: "HID startup: original event pump",
                0x187597F9C: "HID startup: original built-in event table",
                0x187598054: "HID startup: CopyServices returned",
                0x18207D1D4: "HID startup: original service dictionary count",
            }
        )
        for site, name in {
            0xFFFFFF8001781218: "AppleM68Buttons handleStart entry",
            0xFFFFFF8001781314: "M68 superclass handleStart returned",
            0xFFFFFF80017813CC: "M68 original GPIO callback returned",
            0xFFFFFF8001781418: "M68 optional wake callback returned",
            0xFFFFFF8001781434: "M68 interrupt event source returned",
            0xFFFFFF80017814C8: "M68 timer enabled",
            0xFFFFFF8001781524: "M68 handleStart final boolean",
            0xFFFFFF8001781AC4: "M68 original first button state",
            0xFFFFFF80002E7364: "original DebuggerWithContext entry",
        }.items():
            milestones[site] = "original HID hardware: " + name
        context_methods[0x189B1FD3C] = (
            "MobileGestalt::screenGeometryFramebufferProducer"
        )
        milestones[0xFFFFFF80002332F4] = "original guest exception triage"
        report["mgfb_branch_trace"] = []
        report["mgfb_branch_count"] = 0
        graphics_user_returns = {}
        capture_menu_returns = {}
        capture_call_state = None
        live_bridge = None
        live_app_candidates = {}
        report["original_guest_graphics_method_symbols"] = {
            hex(at): name for at, name in context_methods.items()
        }
        report["original_guest_graphics_method_hits"] = []
        report["original_guest_graphics_method_counts"] = {}
        report["original_guest_graphics_function_returns"] = []
        milestones[0xFFFFFF8000AD5D78] = (
            "AppleARMPerformanceController update DVD parameters entry"
        )
        report["uninitialized_performance_table_noops"] = []
        report["pinot_panel_stages"] = []
        original_lcd_sites = {
            0xFFFFFF800157E44C: "AppleSamsungMIPIDSIController::start",
            0xFFFFFF800157E478: "MIPI first platform readiness returned",
            0xFFFFFF800157E4A0: "MIPI provider property returned",
            0xFFFFFF800157E4C8: "MIPI provider function returned",
            0xFFFFFF800157E514: "MIPI first resources initialized",
            0xFFFFFF800157E5C4: "MIPI clocks and resources initialized",
            0xFFFFFF800157E5D8: "MIPI controller MMIO setup returned",
            0xFFFFFF8000ADD560: "AppleARMMIPIDSIDevice::initWithRegistryEntry",
            0xFFFFFF80016D5418: "ApplePinotLCD::start",
            0xFFFFFF8000ACAE9C: "AppleARMFunction::registerFunctionParent",
            0xFFFFFF800157E5F4: "MIPI initial MMIO setup completed",
            0xFFFFFF800157E618: "MIPI allocation helper returned",
            0xFFFFFF800157E630: "MIPI allocated object initialized",
            0xFFFFFF800157E650: "MIPI provider virtual clock call returned",
            0xFFFFFF800157E66C: "MIPI provider virtual power call returned",
            0xFFFFFF800157E690: "MIPI 0x80 MMIO snapshot complete",
            0xFFFFFF800157E6DC: "MIPI initial status bit branch complete",
            0xFFFFFF800157E714: "MIPI panel configuration helper entry",
            0xFFFFFF800157E730: "MIPI panel configuration helper returned",
            0xFFFFFF800157E734: "MIPI panel config stack flag branch",
            0xFFFFFF800157E738: "MIPI controller x19+0x1b4 status check",
            0xFFFFFF800157E740: "MIPI provider method after status",
            0xFFFFFF800157E758: "MIPI next platform helper",
            0xFFFFFF800157E760: "MIPI next platform helper returned",
            0xFFFFFF800157E764: "MIPI next platform helper null check",
            0xFFFFFF800157E778: "MIPI platform object length returned",
            0xFFFFFF800157E7C8: "MIPI SAC frequency list generate",
            0xFFFFFF800157E7E4: "MIPI SAC frequency list completed",
            0xFFFFFF800157E800: "MIPI SAC allocation call",
            0xFFFFFF8001580A58: "MIPI SAC allocation import trampoline",
            0xFFFFFF8001580A60: "MIPI SAC allocation import branch",
            0xFFFFFF8000AE6DE4: "SAC AppleARMFunction withProvider returned",
            0xFFFFFF8000AE6E00: "SAC child lookup returned",
            0xFFFFFF8000AE6E28: "SAC child virtual initializer dispatch",
            0xFFFFFF8000AE6E2C: "SAC child virtual initializer returned",
            0xFFFFFF8000AE6E30: "SAC parent release branch",
            0xFFFFFF8000AE6E44: "SAC wrapper final return value",
            0xFFFFFF800157E804: "MIPI platform SAC object allocated",
            0xFFFFFF800157E818: "MIPI platform SAC registers initialized",
            0xFFFFFF800157E8E8: "MIPI setup stage complete",
            0xFFFFFF800157E904: "MIPI enable panel check",
            0xFFFFFF800157E930: "MIPI panel initialization later branch",
            0xFFFFFF800157E9E0: "MIPI failure cleanup branch",
            0xFFFFFF800157EA1C: "MIPI failed early branch",
        }
        original_lcd_sites = {
            0xFFFFFF800157E44C: "AppleSamsungMIPIDSIController::start",
            0xFFFFFF800157EA1C: "MIPI controller final return value",
            0xFFFFFF80016D5418: "ApplePinotLCD::start",
            0xFFFFFF80016D5440: "Pinot superclass start returned",
            0xFFFFFF80016D5460: "Pinot MIPI provider cast returned",
            0xFFFFFF80016D5488: "Pinot lcd-panel-id property returned",
            0xFFFFFF80016D54BC: "Pinot lcd-panel-id loaded",
            0xFFFFFF80016D54C8: "Pinot function-lcd_ldo lookup call",
            0xFFFFFF80016D54CC: "Pinot function-lcd_ldo lookup returned",
            0xFFFFFF80016D54E8: "Pinot function-reset lookup call",
            0xFFFFFF80016D54EC: "Pinot function-reset lookup returned",
            0xFFFFFF80016D550C: "Pinot optional function-gpio lookup returned",
            0xFFFFFF80016D5534: "Pinot nonzero panel-id check",
            0xFFFFFF80016D557C: "Pinot interrupt registration returned",
            0xFFFFFF80016D55CC: "Pinot function-parent registration call",
            0xFFFFFF80016D55D8: "Pinot function-parent registration returned",
            0xFFFFFF80016D55EC: "Pinot registerService returned",
            0xFFFFFF80016D5604: "Pinot start final boolean",
        }
        original_lcd_sites.update(
            {
                0xFFFFFF80015EA238: "GPIO controller start entry",
                0xFFFFFF80015EA604: "GPIO controller start final boolean",
                0xFFFFFF80014808A0: "I2C controller start entry",
                0xFFFFFF80014808C8: "I2C superclass start returned",
                0xFFFFFF8001480910: "I2C register mapping returned",
                0xFFFFFF80014809A4: "I2C device-reset function returned",
                0xFFFFFF80014809BC: "I2C SDA function returned",
                0xFFFFFF80014809D0: "I2C SCL function returned",
                0xFFFFFF80014809FC: "I2C original peripheral clock returned",
                0xFFFFFF8001480A84: "I2C child publication returned",
                0xFFFFFF8001480AB4: "I2C controller start final boolean",
                0xFFFFFF800148B22C: "Chestnut display PMU start entry",
                0xFFFFFF800148B988: "Chestnut handleStart entry",
                0xFFFFFF800148BA14: "Chestnut initial I2C read call",
                0xFFFFFF800148BA18: "Chestnut initial I2C read returned",
                0xFFFFFF800148BA8C: "Chestnut handleStart final IOReturn",
                0xFFFFFF800148B2BC: "Chestnut handleStart returned",
                0xFFFFFF800148B2EC: "Chestnut display PMU start final boolean",
                0xFFFFFF8000ACCB04: "I2C child initWithRegistryEntry entry",
                0xFFFFFF8000ACCC0C: "I2C child init final boolean",
                0xFFFFFF8001480D64: "I2C valid bus configuration check",
                0xFFFFFF8001480D74: "I2C valid bus configuration result",
                0xFFFFFF8001480DFC: "I2C hardware transaction entry",
                0xFFFFFF80014813C4: "I2C hardware polling loop entry",
                0xFFFFFF8001481010: "I2C hardware transaction final IOReturn",
            }
        )
        for at, stage in original_lcd_sites.items():
            assert at not in milestones
            milestones[at] = "PINOT original: " + stage
        report["adbe0_startup_trace"] = []
        report["armfunction_primary_trace"] = []
        adbe0_stages = {
            0xFFFFFF80016B0D60: "AppleMobileADBE0::start_hardware entry",
            0xFFFFFF80016B0E1C: "ADBE0Driver::getADBE0Driver return",
            0xFFFFFF80016B0E20: "ADBE0Driver returned provider check",
            0xFFFFFF80016B0EAC: "AppleMobileADBE0::startWithIBoot call",
            0xFFFFFF80016B0EB0: "AppleMobileADBE0::startWithIBoot return",
            0xFFFFFF80016B0F3C: "AppleMobileADBE0::start_hardware final result",
        }
        adbe0_stages.update(
            {
                0xFFFFFF80016B19CC: "ADBE0 startWithIBoot entry",
                0xFFFFFF80016B1A74: "ADBE0 original lcd_enable resolved",
                0xFFFFFF80016B1AEC: "ADBE0 original iBoot state initialized",
                0xFFFFFF80016B1CF8: "ADBE0 startWithIBoot near return",
                0xFFFFFF80016B1BEC: "ADBE0 EDT timing lookup returned",
                0xFFFFFF80016B1C70: "ADBE0 timing size programmed",
                0xFFFFFF80016B1CA4: "ADBE0 timing porches programmed",
                0xFFFFFF80016B1CEC: "ADBE0 timings enabled",
                0xFFFFFF80016B1D34: "ADBE0 original missing timing failure",
            }
        )
        for at, stage in adbe0_stages.items():
            milestones[at] = "ADBE0 original startup: " + stage
        milestones[0xFFFFFF800157EC20] = "MIPI SAC register frequency read"
        milestones[0xFFFFFF800157EC58] = "MIPI SAC source clock provider function"
        milestones[0xFFFFFF800157EC5C] = "MIPI SAC source clock returned"
        milestones[0xFFFFFF800157EC60] = "MIPI SAC source clock cached"
        milestones[0xFFFFFF800157EE4C] = "MIPI SAC frequency list source check"
        milestones[0xFFFFFF800157F33C] = "MIPI SAC frequency source empty"
        report["mipi_sac_frequency_trace"] = []
        milestones.update(
            {
                0xFFFFFF80015EFDDC: "A7 cache-error register read",
                0xFFFFFF80015EFDE8: "A7 cache-error register write",
            }
        )
        aic_registers = {4: 896, 0x2000: 0, 0x2004: 0}
        milestones.update(
            {
                0xFFFFFF80019A8C00: "AIC register read",
                0xFFFFFF80019A8C0C: "AIC register write",
            }
        )
        milestones[0xFFFFFF8000563708] = "IOKitInitializeTime"
        milestones[0xFFFFFF8000563734] = "RTC service wait timeout"
        disk_sites = (DISK_READ_CALL, DISK_WRITE_CALL)
        for site in disk_sites:
            milestones[site] = "physical RAM-disk copy"
        milestones[0xFFFFFF80004EC008] = "raw RAM-disk uiomove64"
        milestones[0xFFFFFF800063F9D0] = "raw RAM-disk mdevrw"
        milestones[0xFFFFFF80005BD970] = "IOSecureBSDRoot"
        milestones[0xFFFFFF80004C21B4] = "IOSecureBSDRoot returned"
        milestones[0xFFFFFF80002DE400] = "EL0 synchronous exception"
        surface_symbols = {
            0xFFFFFF80012315FC: "IOMobileFramebuffer::start",
            0xFFFFFF800123397C: "IOMobileFramebuffer::swap_submit",
            0xFFFFFF8001233F5C: "IOMobileFramebuffer::swap_queue",
            0xFFFFFF80015C7A98: "AppleDisplayPipe::start_hardware",
            0xFFFFFF80015CEC90: "AppleDisplayPipe::swap_begin",
        }
        surface_symbols.update(
            {
                0xFFFFFF800122F3D0: "IOMobileFramebufferUserClient::start",
                0xFFFFFF8001230E88: "IOMobileFramebufferUserClient::externalMethod",
                0xFFFFFF8001AAC110: "AGXAccelerator::start",
                0xFFFFFF800120C31C: "IOSurfaceRoot::start",
                0xFFFFFF800120ECA4: "IOSurfaceRootUserClient::start",
            }
        )
        surface_symbols.update(
            {
                0xFFFFFF8001AC16E0: "AGXAcceleratorG3_B0::probe",
                0xFFFFFF8001AC1410: "AGXAcceleratorG3_B0::start",
            }
        )
        for at, symbol_name in surface_symbols.items():
            milestones[at] = "original graphics: " + symbol_name
        report["graphics_symbol_addresses"] = {
            hex(at): name for at, name in surface_symbols.items()
        }
        report["graphics_call_counts"] = {}
        surface_returns = {}
        framebuffer_method_returns = {}
        report["switchboard_mach_ipc_events"] = []
        report["switchboard_mach_ipc_total_stops"] = 0
        phases = {
            0xFFFFFF80015C7B5C: "IOService provider resolution",
            0xFFFFFF80015C7BA8: "provider platform method",
            0xFFFFFF80015C7BFC: "initARMFunctions enter",
            0xFFFFFF80015C7C00: "initARMFunctions returned",
            0xFFFFFF80015C7C04: "ARM function missing",
            0xFFFFFF80015C7C34: "ARM function available",
            0xFFFFFF80015C7CA4: "buffer allocation failed",
            0xFFFFFF80015C7CBC: "start_hardware return epilogue",
            0xFFFFFF80015C7CE8: "start_hardware buffer allocation complete",
            0xFFFFFF80015C7D00: "provider memory map installed",
            0xFFFFFF80015C7D70: "IOKit callback registered",
            0xFFFFFF80015C7DAC: "provider mapping failure",
        }
        phases.update(
            {
                0xFFFFFF80015C7D04: "memory map nonzero?",
                0xFFFFFF80015C7D08: "first virtual memory-map getter",
                0xFFFFFF80015C7D14: "first map getter returned",
                0xFFFFFF80015C7D18: "second provider virtual call",
                0xFFFFFF80015C7D28: "second provider virtual dispatch",
                0xFFFFFF80015C7D2C: "second provider returned",
                0xFFFFFF80015C7D38: "map offset info reader",
                0xFFFFFF80015C7D3C: "map offset info returned",
                0xFFFFFF80015C7D50: "callback setup begin",
                0xFFFFFF80015C7D6C: "callback setup call",
                0xFFFFFF80015C7D70: "IOKit callback registered",
                0xFFFFFF80015C7D74: "IOKit callback valid?",
                0xFFFFFF80015C7D84: "dispatching next display operation",
                0xFFFFFF80015C7D98: "dispatch result checked",
            }
        )
        for at, phase in phases.items():
            milestones[at] = "display start phase: " + phase
        irq_phases = {
            0xFFFFFF8000593948: "IOFilterInterruptEventSource allocation",
            0xFFFFFF8000593978: "interrupt event source atomic accounting",
            0xFFFFFF8000593988: "interrupt event source object allocated",
            0xFFFFFF80005939AC: "interrupt event source init dispatch",
            0xFFFFFF80005939B0: "interrupt event source init returned",
            0xFFFFFF80005939C8: "interrupt event source return epilogue",
        }
        irq_phases.update(
            {
                0xFFFFFF80005938B8: "IOFilterInterruptEventSource::init entered",
                0xFFFFFF80005938D4: "IOInterruptEventSource::init called",
                0xFFFFFF80005938D8: "IOInterruptEventSource::init returned",
                0xFFFFFF80005911BC: "IOInterruptEventSource::init entered",
                0xFFFFFF80005911DC: "IOEventSource::init called",
                0xFFFFFF80005911E0: "IOEventSource::init returned",
                0xFFFFFF8000591224: "getInterruptType virtual invoked",
                0xFFFFFF8000591228: "getInterruptType returned",
                0xFFFFFF8000591270: "registerInterrupt virtual invoked",
                0xFFFFFF8000591274: "registerInterrupt returned",
                0xFFFFFF8000591288: "IOInterruptEventSource::init epilogue",
            }
        )
        irq_phases.update(
            {
                0xFFFFFF8000575F8C: "IOService::getInterruptType entry",
                0xFFFFFF8000575FB8: "IOService::resolveInterrupt called",
                0xFFFFFF8000575FBC: "IOService::resolveInterrupt returned",
                0xFFFFFF8000575AD4: "IOService::resolveInterrupt entered",
                0xFFFFFF8000575B08: "interrupt-controller property lookup returned",
                0xFFFFFF8000575B50: "interrupt-controller property valid",
                0xFFFFFF8000575BC0: "interrupt-controller lookup direct",
                0xFFFFFF8000575D48: "interrupt resolution exit",
                0xFFFFFF8000576008: "getInterruptType error return",
                0xFFFFFF8000576024: "getInterruptType controller dispatch",
            }
        )
        irq_phases.update(
            {
                0xFFFFFF8000575FC0: "getInterruptType controller array",
                0xFFFFFF8000575FDC: "getInterruptType index checked",
                0xFFFFFF8000575FE0: "getInterruptType index accepted",
                0xFFFFFF8000575FF0: "getInterruptType controller entry",
                0xFFFFFF8000575FF4: "getInterruptType controller entry loaded",
                0xFFFFFF8000575FF8: "getInterruptType controller missing; resolve again",
                0xFFFFFF8000576004: "getInterruptType second resolution returned",
                0xFFFFFF8000576008: "getInterruptType error result",
                0xFFFFFF8000576024: "getInterruptType controller method",
                0xFFFFFF8000576038: "getInterruptType dispatch tail",
                0xFFFFFF8000591228: "IRQ getInterruptType result",
            }
        )
        aic_sites = {
            0xFFFFFF80019A7DD8: "AppleInterruptController::start",
            0xFFFFFF80019A8298: "AIC registering interrupt controller",
            0xFFFFFF80019A82A0: "AIC startup returned success",
            0xFFFFFF80005A32A4: "IOPlatformExpert::registerInterruptController",
            0xFFFFFF80005A3314: "IOPlatformExpert::lookUpInterruptController",
            0xFFFFFF80005A3360: "IOPlatformExpert interrupt lookup registry result",
        }
        aic_sites.update(
            {
                0xFFFFFF80019A7F3C: "AIC device properties verified",
                0xFFFFFF80019A8070: "AIC allocate interrupt vectors",
                0xFFFFFF80019A80AC: "AIC vector allocation returned",
                0xFFFFFF80019A80EC: "AIC vector setup complete",
                0xFFFFFF80019A8150: "AIC IRQ configuration begins",
                0xFFFFFF80019A818C: "AIC IRQ config second section",
                0xFFFFFF80019A81C8: "AIC IRQ mask configuration",
                0xFFFFFF80019A8204: "AIC ARM platform registration setup",
                0xFFFFFF80019A8210: "AIC provider call returned",
                0xFFFFFF80019A8234: "AIC additional IRQ registration",
                0xFFFFFF80019A8288: "AIC register interrupt controller with platform",
                0xFFFFFF80019A829C: "AIC register controller virtual call",
                0xFFFFFF80019A82A4: "AIC exit with return code",
            }
        )
        aic_sites.update(
            {
                0xFFFFFF80019A8240: "AIC per-IPI registration begins",
                0xFFFFFF80019A824C: "AIC interrupt registration provider",
                0xFFFFFF80019A8260: "AIC IOService registerInterrupt called",
                0xFFFFFF80019A8264: "AIC IOService registerInterrupt returned",
                0xFFFFFF80019A8274: "AIC interrupt enabled",
                0xFFFFFF80019A8278: "AIC interrupt enable returned",
                0xFFFFFF80019A8288: "AIC IPI setup completed",
            }
        )
        for aic_pc, aic_label in aic_sites.items():
            milestones.setdefault(aic_pc, "AIC registry: " + aic_label)
        report["aic_probe_addresses"] = {hex(p): v for p, v in aic_sites.items()}
        for irq_at, irq_phase in irq_phases.items():
            milestones[irq_at] = "IRQ factory phase: " + irq_phase
        report["irq_factory_breakpoints"] = {hex(x): v for x, v in irq_phases.items()}
        report["display_phase_breakpoints"] = {hex(x): v for x, v in phases.items()}
        user_faults = {}
        pending_user_reads = {}
        vm_fault_returns = set()
        fault_target = None
        for address in milestones:
            breakpoint(address)
        for _ in range(300000):
            if len(report["events"]) > 5000:
                report["events"] = report["events"][:300] + report["events"][-2700:]
                report["compacted_diagnostic_events"] = (
                    report.get("compacted_diagnostic_events", 0) + 2000
                )
            remaining = LIVE_BUDGET - (time.monotonic() - started_at)
            if remaining <= 0:
                raise TimeoutError("Total diagnostic budget reached")
            connection.settimeout(min(60, remaining))
            stop = packet("c")
            current = regs()
            address = pc(current)
            label = milestones.get(address, "unclassified debugger stop")
            draw_profile = active_draw_profile()
            if draw_profile is not None:
                counts = draw_profile["stop_counts"]
                counts[label] = counts.get(label, 0) + 1
            event = {"stage": label, "pc": hex(address), "stop": stop}
            if label.startswith("selected original loader:"):
                None.handle(
                    address,
                    current,
                    packet,
                    system_registers,
                    read_current_user_bytes,
                    breakpoint,
                    milestones,
                )
                continue
            if label in (
                "live guest bridge safe point",
                "live guest bridge return point",
            ):
                live_bridge.handle(current)
                continue
            if label == "panic":
                report["original_guest_panic_observed"] = True
                try:
                    message_ptr = struct.unpack_from("<Q", current)[0]
                    report["original_guest_panic_format"] = (
                        read_memory(message_ptr, 0x100)
                        .split(b"\x00", 1)[0]
                        .decode(errors="replace")
                    )
                except (ValueError, AssertionError, struct.error) as exc:
                    report["panic_format_read_error"] = str(exc)
            if label == "original graphics process exit":
                owner = capture_active_guest_process()
                if live_bridge:
                    live_bridge.process_exited(owner)
                live_snapshot_request = (RUN / "request-thread-snapshot").exists()
                live_stalled = (
                    report.get("live_last_input_host")
                    and time.monotonic()
                    - max(
                        report["live_last_input_host"],
                        report.get("live_guest_frames", [{}])[-1].get(
                            "host_monotonic", 0
                        ),
                    )
                    > 12
                )
                if (
                    (live_snapshot_request or live_stalled)
                    and len(report.get("graphics_saved_thread_snapshots", [])) < 6
                    and (
                        not report.get("graphics_saved_thread_snapshots")
                        or time.monotonic()
                        - started_at
                        - report["graphics_saved_thread_snapshots"][-1]["after_seconds"]
                        >= 15
                    )
                ):
                    try:
                        capture_graphics_thread_stacks()
                        (RUN / "request-thread-snapshot").unlink(missing_ok=True)
                    except (AssertionError, ValueError, struct.error) as exc:
                        report.setdefault("thread_snapshot_errors", []).append(str(exc))
                if (
                    owner.get("comm") in ("SwitchBoard", "hidd.nonui", "mediaserverd")
                    or owner.get("comm", "").startswith("MobileGestalt")
                    or owner.get("comm") in report.get("live_app_exec_names", [])
                ):
                    sample = capture_graphics_user_context(owner, label)
                    sample["exit_args"] = [
                        hex(x) for x in struct.unpack_from("<4Q", current)
                    ]
                    report.setdefault("original_graphics_process_exits", []).append(
                        sample
                    )
                    with (RUN / "graphics-exits.jsonl").open("a") as output:
                        output.write(json.dumps(sample) + "\n")
                breakpoint(address, False)
                packet("s")
                breakpoint(address)
                continue
            if label.startswith("original HID hardware: "):
                values = struct.unpack_from("<33Q", current)
                owner = capture_active_guest_process()
                sample = {
                    "stage": label,
                    "pc": hex(address),
                    "owner": owner,
                    "x0_x3": [hex(v) for v in values[:4]],
                    "x19_x26": [hex(v) for v in values[19:27]],
                }
                if address == 0xFFFFFF8001781218:
                    report["original_m68_start_thread"] = owner.get("thread")
                if address == 0xFFFFFF8001781524:
                    sample["entry_thread_verified"] = owner.get("thread") == report.get(
                        "original_m68_start_thread"
                    )
                    sample["original_return_boolean"] = bool(values[22] & 0xFFFFFFFF)
                if address == 0xFFFFFF80002E7364:
                    try:
                        sample["debugger_reason"] = (
                            read_memory(values[0], 160)
                            .split(b"\x00", 1)[0]
                            .decode(errors="replace")
                        )
                    except (AssertionError, ValueError, struct.error) as exc:
                        sample["debugger_reason_read_error"] = str(exc)
                report.setdefault("original_hid_hardware_stages", []).append(sample)
                with (RUN / "hid-hardware.jsonl").open("a") as output:
                    output.write(json.dumps(sample) + "\n")
                breakpoint(address, False)
                del milestones[address]
                continue
            if label == "original guest exception triage":
                owner = capture_active_guest_process()
                if (
                    owner.get("comm") in ("SwitchBoard", "hidd.nonui")
                    or owner.get("comm", "").startswith("MobileGestalt")
                    or owner.get("comm") in report.get("live_app_exec_names", [])
                ):
                    sample = capture_graphics_user_context(owner, label)
                    sample["exception_type"] = struct.unpack_from("<Q", current)[0]
                    code_ptr, count = struct.unpack_from("<QQ", current, 8)
                    try:
                        sample["exception_codes"] = [
                            hex(v)
                            for v in struct.unpack(
                                "<" + "Q" * min(count, 2),
                                read_memory(code_ptr, 8 * min(count, 2)),
                            )
                        ]
                    except (AssertionError, ValueError, struct.error) as exc:
                        sample["code_read_error"] = str(exc)
                    report.setdefault(
                        "original_graphics_process_exceptions", []
                    ).append(sample)
                    with (RUN / "graphics-contexts.jsonl").open("a") as output:
                        output.write(json.dumps(sample) + "\n")
                breakpoint(address, False)
                packet("s")
                breakpoint(address)
                continue
            if label.startswith("MGFB original branch: "):
                report["mgfb_branch_count"] += 1
                values = struct.unpack_from("<33Q", current)
                sample = {
                    "point": label.removeprefix("MGFB original branch: "),
                    "pc": hex(address),
                    "return_w0": hex(values[0] & 0xFFFFFFFF),
                    "x20_out_pointer": hex(values[20]),
                    "x19_reference_service": hex(values[19]),
                    "x21_requested_type": hex(values[21]),
                    "x8_low32": hex(values[8] & 0xFFFFFFFF),
                    "x22_error": hex(values[22] & 0xFFFFFFFF),
                    "x23_iterator": hex(values[23]),
                    "owner": capture_active_guest_process(from_user=True),
                }
                if sample["owner"].get("comm", "").startswith("MobileGestalt"):
                    try:
                        sample["out_pointer_contents"] = read_current_user_bytes(
                            values[20], 8
                        ).hex()
                    except (AssertionError, ValueError, struct.error) as exc:
                        sample["output_read_error"] = str(exc)
                report["mgfb_branch_trace"].append(sample)
                breakpoint(address, False)
                packet("s")
                if report["mgfb_branch_count"] < 32:
                    breakpoint(address)
                else:
                    del milestones[address]
                continue
            if label == "original SwitchBoard menu construction returned":
                expected = capture_menu_returns[address]
                active = capture_active_guest_process(from_user=True)
                sp = struct.unpack_from("<Q", current, 31 * 8)[0]
                if active.get("thread") == expected["thread"] and sp == expected["sp"]:
                    slide = int(
                        report["skank_verified_shared_cache_slide"]["slide"], 16
                    )
                    selector = struct.unpack(
                        "<Q", read_current_user_bytes(0x18C628D00 + slide, 8)
                    )[0]
                    assert (
                        read_current_user_bytes(selector, 16) == b"doScreenCapture\x00"
                    )
                    objc_send = next(
                        (
                            a
                            for a, n, _ in graphics_cache.symbols
                            if n == "_objc_msgSend"
                        )
                    )
                    assert read_current_user_bytes(
                        objc_send + slide, 12
                    ) == graphics_cache.read(objc_send, 12)
                    complete_state = save_guest_call_state(
                        packet, primary_registers, current
                    )
                    capture_call_state = {
                        "registers": bytes(current),
                        "complete_state": complete_state,
                        "thread": expected["thread"],
                        "sp": sp,
                    }
                    (RUN / "before-original-capture-complete-state.json").write_text(
                        json.dumps(complete_state, indent=2)
                    )
                    report["original_capture_call_started"] = {
                        "diagnostic_only": True,
                        "guest_process": active,
                        "original_menu_return_pc": hex(address),
                        "original_menu_construction_returned": True,
                        "app_object": hex(expected["app"]),
                        "selector": hex(selector),
                        "objc_msgSend": hex(objc_send + slide),
                        "saved_register_packet_sha256": hashlib.sha256(
                            current
                        ).hexdigest(),
                        "purpose": "Operator capture request through original guest ObjC dispatch; no renderer/pixel/instruction replacement",
                    }
                    (RUN / "before-original-capture-registers.bin").write_bytes(current)
                    breakpoint(address, False)
                    milestones[address] = "diagnostic original screen capture returned"
                    breakpoint(address)
                    struct.pack_into("<Q", current, 0, expected["app"])
                    struct.pack_into("<Q", current, 8, selector)
                    struct.pack_into("<Q", current, 30 * 8, address)
                    struct.pack_into("<Q", current, 32 * 8, objc_send + slide)
                    write_regs(current)
                    continue
                breakpoint(address, False)
                packet("s")
                breakpoint(address)
                continue
            if label == "diagnostic original screen capture returned":
                active = capture_active_guest_process(from_user=True)
                sp = struct.unpack_from("<Q", current, 31 * 8)[0]
                if (
                    active.get("thread") == capture_call_state["thread"]
                    and sp == capture_call_state["sp"]
                ):
                    report["original_capture_call_returned"] = True
                    breakpoint(address, False)
                    del milestones[address]
                    restore_guest_call_state(
                        packet, capture_call_state["complete_state"]
                    )
                    report["original_capture_call_registers_restored_exactly"] = True
                    report[
                        "original_capture_call_simd_fp_state_restored_and_verified"
                    ] = True
                    capture_call_state = None
                    request = report["original_capture_call_started"]
                    live_bridge = LiveGuestBridge(
                        packet=packet,
                        regs=regs,
                        write_regs=write_regs,
                        breakpoint=breakpoint,
                        read_user=read_current_user_bytes,
                        write_user=write_memory,
                        register_map=primary_registers,
                        system_map=system_registers,
                        cache=graphics_cache,
                        milestones=milestones,
                        report=report,
                        run=RUN,
                        ipc=IPC,
                        slide=int(
                            report["skank_verified_shared_cache_slide"]["slide"], 16
                        ),
                        thread=request["guest_process"]["thread"],
                        app=int(request["app_object"], 16),
                        process=request["guest_process"],
                        fast_frames=bool(live_frame_stream),
                        scanout_active=lambda: (
                            time.monotonic()
                            - report.get("native_scanout_last_frame", -10)
                            < 1
                        ),
                        on_frame=lambda context: capture_registered_guest_bitmap(
                            report["original_guest_bitmap_contexts"][hex(context)],
                            "completed original live render",
                        ),
                    )
                    if live_frame_stream:
                        keep_methods = {
                            "_CGBitmapContextCreate",
                            "_CGBitmapContextCreateWithData",
                            "Live foreground: original GSEventRunModal",
                        }
                        removed = []
                        for probe, probe_name in tuple(milestones.items()):
                            name = probe_name.removeprefix(
                                "original guest graphics method: "
                            )
                            if (
                                name != probe_name
                                and name not in keep_methods
                                and (
                                    not name.startswith(("Live input:", "Live launch:"))
                                )
                            ):
                                breakpoint(probe, False)
                                del milestones[probe]
                                removed.append(name)
                        report["retired_live_graphics_observers"] = removed
                    continue
                breakpoint(address, False)
                packet("s")
                breakpoint(address)
                continue
            if label == "original graphics user return":
                active = capture_active_guest_process(from_user=True)
                sp = struct.unpack_from("<Q", current, 31 * 8)[0]
                entries = graphics_user_returns.get(address, [])
                match = next(
                    (
                        v
                        for v in entries
                        if v["thread"] == active.get("thread") and v["sp"] == sp
                    ),
                    None,
                )
                if match:
                    entries.remove(match)
                    value = struct.unpack_from("<Q", current)[0]
                    record = {
                        "function": match["function"],
                        "process": active,
                        "returned_x0": hex(value),
                        "entry_arguments": match["arguments"],
                    }
                    if match["function"].startswith("_CGBitmapContextCreate") and value:
                        a = [int(v, 16) for v in match["arguments"]]
                        report["original_guest_bitmap_contexts"][hex(value)] = {
                            "context": hex(value),
                            "width": a[1],
                            "height": a[2],
                            "bits_per_component": a[3],
                            "row_bytes": a[4],
                            "bitmap_info": a[6],
                            "process_at_creation": active,
                        }
                        bitmap = report["original_guest_bitmap_contexts"][hex(value)]
                        number, _ = system_registers["TTBR0_EL1"]
                        bitmap["ttbr0_el1"] = hex(
                            int.from_bytes(
                                bytes.fromhex(packet(f"p{number:x}")), "little"
                            )
                        )
                        number, _ = system_registers["TCR_EL1"]
                        tcr = int.from_bytes(
                            bytes.fromhex(packet(f"p{number:x}")), "little"
                        )
                        assert tcr >> 14 & 3 == 0
                        bitmap["user_address_bits"] = 64 - (tcr & 63)
                    if match["function"] == "_CGBitmapContextGetData" and value:
                        context = match["arguments"][0]
                        bitmap = report["original_guest_bitmap_contexts"].get(context)
                        if bitmap and len(report["original_guest_bitmap_captures"]) < 8:
                            capture = capture_original_bitmap(value, bitmap, active)
                            report["original_guest_bitmap_captures"].append(capture)
                    if match["function"] in (
                        "_FigSharedPlayerCreate",
                        "_FigSharedPlayerGetDefaultEngineTopology",
                    ):
                        args = [int(x, 16) for x in match["arguments"]]
                        pointer, length = (
                            (args[2], 8)
                            if match["function"] == "_FigSharedPlayerCreate"
                            else (args[0], 4)
                        )
                        record["returned_status_signed32"] = struct.unpack(
                            "<i", struct.pack("<I", value & 0xFFFFFFFF)
                        )[0]
                        try:
                            record["output_bytes"] = read_current_user_bytes(
                                pointer, length
                            ).hex()
                        except (AssertionError, ValueError, struct.error) as exc:
                            record["output_read_error"] = str(exc)
                    if (
                        value & 0xFFFFFFFF == 0
                        and "IOMobileFramebuffer" in match["function"]
                    ):
                        index, size = (
                            (1, 16)
                            if match["function"].endswith("GetDisplaySize")
                            else (0, 8)
                        )
                        try:
                            raw = read_current_user_bytes(
                                int(match["arguments"][index], 16), size
                            )
                            record["output_bytes"] = raw.hex()
                            if size == 16:
                                record["display_size_doubles"] = struct.unpack(
                                    "<dd", raw
                                )
                            else:
                                record["framebuffer_ref"] = hex(
                                    struct.unpack("<Q", raw)[0]
                                )
                        except (AssertionError, ValueError, struct.error) as exc:
                            record["output_read_error"] = str(exc)
                    report["original_guest_graphics_function_returns"].append(record)
                breakpoint(address, False)
                packet("s")
                if entries:
                    breakpoint(address)
                else:
                    del milestones[address]
                continue
            if label.startswith("original guest graphics method: "):
                name = label.removeprefix("original guest graphics method: ")
                counts = report["original_guest_graphics_method_counts"]
                counts[name] = counts.get(name, 0) + 1
                active = capture_active_guest_process(from_user=True)
                arguments = [hex(x) for x in struct.unpack_from("<8Q", current)]
                report["original_guest_graphics_method_hits"].append(
                    {
                        "method": name,
                        "pc": hex(address),
                        "after_seconds": time.monotonic() - started_at,
                        "process": active,
                        "user_lr": hex(struct.unpack_from("<Q", current, 30 * 8)[0]),
                        "user_sp": hex(struct.unpack_from("<Q", current, 31 * 8)[0]),
                        "x0_x3": arguments,
                    }
                )
                if live_bridge and name == "Live foreground: original GSEventRunModal":
                    candidate = live_app_candidates.pop(active.get("thread"), None)
                    if candidate and candidate["process"].get("pid") == active.get(
                        "pid"
                    ):
                        live_bridge.note(
                            foreground_event_loop_verified=dict(
                                thread=active["thread"],
                                app=hex(candidate["app"]),
                                process=active,
                            )
                        )
                        live_bridge.observe_app(
                            active["thread"], candidate["app"], active
                        )
                if name in (
                    "Live input: original SKUIApplication handleEvent",
                    "Live input: original SKUIApplication handleMouseEvent",
                ):
                    try:
                        original_event = read_current_user_bytes(
                            int(arguments[2], 16), 144
                        )
                        report["original_guest_graphics_method_hits"][-1][
                            "original_event"
                        ] = dict(
                            raw_type=struct.unpack_from("<I", original_event, 16)[0],
                            position=struct.unpack_from("<dd", original_event, 40),
                            hand=struct.unpack_from("<IHH", original_event, 104),
                        )
                    except (AssertionError, ValueError, struct.error) as exc:
                        report["original_guest_graphics_method_hits"][-1][
                            "event_inspection_error"
                        ] = str(exc)
                if name.startswith("Live launch:"):
                    launch_record = report["original_guest_graphics_method_hits"][-1]
                    try:
                        if name.endswith("launch plist path"):
                            launch_record["plist_path"] = (
                                read_current_user_bytes(int(arguments[0], 16), 512)
                                .split(b"\x00", 1)[0]
                                .decode(errors="replace")
                            )
                        elif name.endswith("SMJobSubmit returned"):
                            fp = struct.unpack_from("<Q", current, 29 * 8)[0]
                            launch_record["submit_success"] = bool(
                                int(arguments[0], 16) & 255
                            )
                            launch_record["error_pointer"] = hex(
                                struct.unpack(
                                    "<Q", read_current_user_bytes(fp - 40, 8)
                                )[0]
                            )
                        elif name.endswith("submit error description"):
                            pointer = int(arguments[0], 16)
                            raw = read_current_user_bytes(pointer, 32)
                            launch_record["description_object_bytes"] = raw.hex()
                            flags, chars, length = struct.unpack_from("<QQQ", raw, 8)
                            if flags & 128 == 0 and 0 < length < 0x800:
                                launch_record["description_candidate"] = (
                                    read_current_user_bytes(chars, length).decode(
                                        errors="replace"
                                    )
                                )
                    except (AssertionError, ValueError, struct.error) as exc:
                        launch_record["launch_inspection_error"] = str(exc)
                if name.startswith("AV startup:"):
                    report["original_guest_graphics_method_hits"][-1]["x19_x24"] = [
                        hex(x) for x in struct.unpack_from("<6Q", current, 19 * 8)
                    ]
                    if "timeout preference read" in name:
                        try:
                            sp = struct.unpack_from("<Q", current, 31 * 8)[0]
                            report["original_guest_graphics_method_hits"][-1][
                                "preference_found"
                            ] = bool(read_current_user_bytes(sp + 15, 1)[0])
                        except (AssertionError, ValueError, struct.error) as exc:
                            report["original_guest_graphics_method_hits"][-1][
                                "preference_read_error"
                            ] = str(exc)
                with (RUN / "graphics-methods.jsonl").open("a") as output:
                    output.write(
                        json.dumps(report["original_guest_graphics_method_hits"][-1])
                        + "\n"
                    )
                if name in (
                    "_CGBitmapContextCreateImage",
                    "_CGContextRelease",
                    "_CGContextFlush",
                ):
                    bitmap = report["original_guest_bitmap_contexts"].get(arguments[0])
                    if (
                        bitmap
                        and bitmap["process_at_creation"].get("pid")
                        == active.get("pid")
                        and (bitmap["width"] >= 128)
                        and (bitmap["height"] >= 128)
                        and (name == "_CGBitmapContextCreateImage")
                    ):
                        bitmap.setdefault("captured_at", []).append(name)
                        capture_registered_guest_bitmap(bitmap, name + " entry")
                if name in (
                    "_IOMobileFramebufferGetMainDisplay",
                    "_IOMobileFramebufferGetDisplaySize",
                    "MobileGestalt::screenGeometryFramebufferProducer",
                    "_CGBitmapContextCreate",
                    "_CGBitmapContextCreateWithData",
                    "_CGBitmapContextGetData",
                    "_FigSharedPlayerCreate",
                    "_FigSharedPlayerGetDefaultEngineTopology",
                    "_FigPlayerCMSessionOneTimeInitialization",
                    "_FigMediaServerStart",
                    "_FigMovieStartServing",
                    "_FigSandboxReacquireServer",
                    "_nanosleep",
                ):
                    returned = struct.unpack_from("<Q", current, 30 * 8)[0]
                    if (
                        returned not in milestones
                        or milestones[returned] == "original graphics user return"
                    ):
                        graphics_user_returns.setdefault(returned, []).append(
                            {
                                "thread": active.get("thread"),
                                "function": name,
                                "sp": struct.unpack_from("<Q", current, 31 * 8)[0],
                                "arguments": arguments,
                            }
                        )
                        if returned not in milestones:
                            milestones[returned] = "original graphics user return"
                            breakpoint(returned)
                breakpoint(address, False)
                packet("s")
                if counts[name] < 500:
                    breakpoint(address)
                else:
                    del milestones[address]
                continue
            if label.startswith("original SkankKit method: "):
                report["original_skank_method_total"] += 1
                active = capture_active_guest_process(from_user=True)
                name = label.removeprefix("original SkankKit method: ")
                if name == "SKUIApplication::showWindow":
                    live_app_candidates[active["thread"]] = dict(
                        app=struct.unpack_from("<Q", current)[0], process=active
                    )
                if name == "SKUIApplication::showModule":
                    report["original_skank_module_seen"] = True
                    if live_bridge:
                        live_bridge.observe_app(
                            active["thread"],
                            struct.unpack_from("<Q", current)[0],
                            active,
                        )
                    if not report.get("original_capture_call_started"):
                        values_at_entry = struct.unpack_from("<33Q", current)
                        returned = values_at_entry[30]
                        switchboard_path = (
                            "/AppleInternal/Applications/SwitchBoard.app/SwitchBoard"
                        )
                        if active.get("comm") == "launchd" and any(
                            (
                                event.get("requested_exec_path") == switchboard_path
                                and event["process"].get("pid") == active.get("pid")
                                and (event["process"].get("proc") == active.get("proc"))
                                for event in report.get("fast_process_events", ())
                            )
                        ):
                            try:
                                original = (profile / "SwitchBoard.macho").read_bytes()
                                if matches_switchboard_menu_caller(
                                    original, read_current_user_bytes, returned
                                ):
                                    active.update(
                                        comm="SwitchBoard",
                                        identity_source="original Mach-O and menu caller",
                                    )
                                    guest_verified_thread_owners[
                                        int(active["thread"], 16)
                                    ]["comm"] = "SwitchBoard"
                            except (
                                AssertionError,
                                OSError,
                                ValueError,
                                struct.error,
                            ) as error:
                                report["switchboard_menu_caller_check_error"] = str(
                                    error
                                )
                        if active.get("comm") == "SwitchBoard":
                            if returned not in milestones:
                                capture_menu_returns[returned] = {
                                    "thread": active["thread"],
                                    "sp": values_at_entry[31],
                                    "app": values_at_entry[0],
                                }
                                milestones[returned] = (
                                    "original SwitchBoard menu construction returned"
                                )
                                breakpoint(returned)
                            else:
                                report["capture_request_return_collision"] = hex(
                                    returned
                                )
                if len(report["original_skank_method_hits"]) < 120:
                    report["original_skank_method_hits"].append(
                        {
                            "method": name,
                            "pc": hex(address),
                            "after_seconds": time.monotonic() - started_at,
                            "active": active,
                            "x0_x3": [
                                hex(x) for x in struct.unpack_from("<4Q", current)
                            ],
                        }
                    )
                    with (RUN / "skank-methods.jsonl").open("a") as output:
                        output.write(
                            json.dumps(report["original_skank_method_hits"][-1]) + "\n"
                        )
                breakpoint(address, False)
                packet("s")
                if report["original_skank_method_total"] < 5000:
                    breakpoint(address)
                else:
                    del milestones[address]
                continue
            if label == "AppleARMPerformanceController update DVD parameters entry":
                register_tuple = struct.unpack_from("<33Q", current)
                owner, domain = (register_tuple[0], register_tuple[1] & 0xFFFFFFFF)
                if not (
                    0xFFFFFF0000000000 <= owner < 0xFFFFFFFFFFFFFFFF
                    and 0 <= domain <= 2
                ):
                    raise RuntimeError(
                        "Original performance controller owner/domain invalid"
                    )
                table_base = struct.unpack("<Q", read_memory(owner + 0x308, 8))[0]
                assert 0xFFFFFF0000000000 <= table_base < 0xFFFFFFFFFFFFFFFF
                entry = table_base + domain * 0x350
                count = struct.unpack("<I", read_memory(entry + 4, 4))[0]
                if count == 0:
                    records = report["uninitialized_performance_table_noops"]
                    if len(records) < 60:
                        records.append(
                            {
                                "pid": capture_active_guest_process().get("pid"),
                                "owner": hex(owner),
                                "domain": domain,
                                "table": hex(table_base),
                                "state_count": count,
                                "skip_return_pc": hex(register_tuple[30]),
                            }
                        )
                    assert 0xFFFFFF8000000000 <= register_tuple[30] < 0xFFFFFF8100000000
                    struct.pack_into("<Q", current, 32 * 8, register_tuple[30])
                    write_regs(current)
                    continue
                breakpoint(address, False)
                packet("s")
                breakpoint(address)
                continue
            if label.startswith("MIPI SAC "):
                controller = struct.unpack_from("<Q", current, 20 * 8)[0]
                mipi_state = {
                    "stage": label,
                    "pc": hex(address),
                    "controller": hex(controller),
                    "x19": hex(struct.unpack_from("<Q", current, 19 * 8)[0]),
                    "x0": hex(struct.unpack_from("<Q", current, 0)[0]),
                    "w10": hex(
                        struct.unpack_from("<Q", current, 10 * 8)[0] & 0xFFFFFFFF
                    ),
                    "source_clock_x22": hex(
                        struct.unpack_from("<Q", current, 22 * 8)[0]
                    ),
                    "x8": hex(struct.unpack_from("<Q", current, 8 * 8)[0]),
                    "x9": hex(struct.unpack_from("<Q", current, 9 * 8)[0]),
                    "x12": hex(struct.unpack_from("<Q", current, 12 * 8)[0]),
                }
                if 0xFFFFFF0000000000 <= controller < 0xFFFFFFFFFFFFFFFF:
                    mipi_state["object_freq_fields"] = read_memory(
                        controller + 0x1B8, 24
                    ).hex()
                if (
                    address == 0xFFFFFF800157EC5C
                    and struct.unpack_from("<Q", current, 0)[0] == 0
                ):
                    mipi_state["original_nclk"] = 0
                    mipi_state["diagnostic_nclk"] = 24000000
                    struct.pack_into("<Q", current, 0, 24000000)
                    write_regs(current)
                report["mipi_sac_frequency_trace"].append(mipi_state)
                breakpoint(address, False)
                packet("s")
                continue
            if label.startswith("original Mach IPC: "):
                report["switchboard_mach_ipc_total_stops"] += 1
                owner = capture_active_guest_process()
                tracked = owner.get("comm") in (
                    "SwitchBoard",
                    "hidd.nonui",
                ) or owner.get("comm", "").startswith("MobileGestalt")
                if owner.get("pid") == 24 or tracked:
                    observations = report["skank_guest_user_execution_samples"]
                    if len(observations) < 240:
                        sample = capture_graphics_user_context(owner, label)
                        observations.append(sample)
                        with (RUN / "graphics-contexts.jsonl").open("a") as output:
                            output.write(json.dumps(sample) + "\n")
                    if (
                        "skank_verified_shared_cache_slide" in report
                        and "skank_relocated_graphics_breakpoints" not in report
                    ):
                        slide = int(
                            report["skank_verified_shared_cache_slide"]["slide"], 16
                        )
                        installed = {}
                        for sites, prefix in (
                            (skank_methods, "original SkankKit method: "),
                            (context_methods, "original guest graphics method: "),
                        ):
                            for original, method in sites.items():
                                runtime = original + slide
                                if runtime not in milestones:
                                    milestones[runtime] = prefix + method
                                    breakpoint(runtime)
                                    installed[hex(runtime)] = method
                        for original, point in {
                            0x185BC37C0: "after IOIteratorNext",
                            0x185BC37E4: "after IOObjectIsEqualTo",
                            0x185BC37FC: "after skipping comparison-equal service",
                            0x185BC381C: "after IOMobileFramebufferOpen",
                            0x185BC382C: "after IsMainDisplay",
                            0x185BC3834: "main-display boolean loaded",
                            0x185BC387C: "failed open/display check",
                            0x185BC386C: "service iteration exhausted",
                            0x185BC38F8: "candidate list exhausted",
                        }.items():
                            runtime = original + slide
                            milestones[runtime] = "MGFB original branch: " + point
                            breakpoint(runtime)
                            installed[hex(runtime)] = "MGFB " + point
                        report["skank_relocated_graphics_breakpoints"] = installed
                if owner.get("pid") == 24 and "skank_runtime_vm_layout" not in report:
                    vm_sample = {
                        "process": owner,
                        "entries": [],
                        "note": "XNU vm_map doubly-linked entries, not guessed image locations",
                    }
                    try:
                        procptr = int(owner["proc"], 16)
                        taskptr = struct.unpack("<Q", read_memory(procptr + 24, 8))[0]
                        mapptr = struct.unpack("<Q", read_memory(taskptr + 40, 8))[0]
                        hdr = read_memory(mapptr, 64)
                        first = struct.unpack_from("<Q", hdr, 24)[0]
                        last = struct.unpack_from("<Q", hdr, 32)[0]
                        vm_sample.update(
                            task=hex(taskptr),
                            vm_map=hex(mapptr),
                            first=hex(first),
                            last=hex(last),
                        )
                        ptr = first
                        seen = set()
                        for _ in range(150):
                            if ptr in seen or ptr == mapptr + 24:
                                break
                            if not 0xFFFFFF0000000000 <= ptr < 0xFFFFFFFFFFFFFFFF:
                                vm_sample["invalid_pointer"] = hex(ptr)
                                break
                            seen.add(ptr)
                            ent = read_memory(ptr, 40)
                            nxt, prev, begin, end, flags = struct.unpack_from(
                                "<5Q", ent
                            )
                            if begin < end and begin < 0x200000000:
                                vm_sample["entries"].append(
                                    {
                                        "ptr": hex(ptr),
                                        "begin": hex(begin),
                                        "end": hex(end),
                                        "bytes": end - begin,
                                        "next": hex(nxt),
                                        "flags": hex(flags),
                                    }
                                )
                            ptr = nxt
                        vm_sample["visited"] = len(seen)
                        vm_sample["truncated"] = len(seen) >= 150
                        vm_sample["shared_region_is_not_cache_slide_proof"] = True
                    except (
                        AssertionError,
                        ValueError,
                        IndexError,
                        struct.error,
                    ) as exc:
                        vm_sample["error"] = str(exc)
                    report["skank_runtime_vm_layout"] = vm_sample
                if owner.get("pid") in (24, 38) or tracked:
                    samples = report["switchboard_mach_ipc_events"]
                    if len(samples) < 120:
                        observation = {
                            "pc": hex(address),
                            "trap": label[19:],
                            "pid": owner.get("pid"),
                            "comm": owner.get("comm"),
                            "arguments": [
                                hex(x) for x in struct.unpack_from("<6Q", current)
                            ],
                        }
                        samples.append(observation)
                if "skank_relocated_graphics_breakpoints" in report:
                    if "mgfb_early_mach_trace_disabled_at_stop" not in report:
                        report["mgfb_early_mach_trace_disabled_at_stop"] = report[
                            "switchboard_mach_ipc_total_stops"
                        ]
                    for mach_addr, mach_label in list(milestones.items()):
                        if mach_label.startswith("original Mach IPC: "):
                            breakpoint(mach_addr, False)
                            del milestones[mach_addr]
                    packet("s")
                    continue
                if (
                    report["switchboard_mach_ipc_total_stops"] >= 8000
                    or len(report["switchboard_mach_ipc_events"]) >= 240
                ):
                    breakpoint(address, False)
                    del milestones[address]
                else:
                    breakpoint(address, False)
                    packet("s")
                    breakpoint(address)
                continue
            if label.startswith("PINOT original: "):
                pinot_regs = struct.unpack_from("<33Q", current)
                pinot_stage = label.removeprefix("PINOT original: ")
                pinot_owner = capture_active_guest_process()
                if pinot_stage == "MIPI SAC allocation call" and False:
                    report["pinot_sac_thread"] = pinot_owner.get("thread")
                    scoped = {
                        0xFFFFFF8000ACB02C: "char provider entry",
                        0xFFFFFF8000ACB054: "symbol provider return",
                        0xFFFFFF8000ACB084: "symbol provider entry",
                        0xFFFFFF8000ACB0D4: "property returned",
                        0xFFFFFF8000ACB124: "OSData bytes read",
                        0xFFFFFF8000ACB1B4: "platform callback dispatch",
                        0xFFFFFF8000ACB1B8: "platform callback returned",
                        0xFFFFFF8000ACB22C: "function init returned",
                        0xFFFFFF8000ACB24C: "function cleanup",
                    }
                    for at, stage in scoped.items():
                        if at not in milestones:
                            milestones[at] = (
                                "PINOT original: AppleARMFunction original " + stage
                            )
                            breakpoint(at)
                pinot_capture = not pinot_stage.startswith(
                    "AppleARMFunction original"
                ) or pinot_owner.get("thread") == report.get("pinot_sac_thread")
                if pinot_capture and len(report["pinot_panel_stages"]) < 180:
                    report["pinot_panel_stages"].append(
                        {
                            "stage": label.removeprefix("PINOT original: "),
                            "pc": hex(address),
                            "args": [hex(x) for x in pinot_regs[:4]],
                            "lr": hex(pinot_regs[30]),
                            "sp": hex(pinot_regs[31]),
                            "w8": hex(pinot_regs[8] & 0xFFFFFFFF),
                            "x19": hex(pinot_regs[19]),
                            "x25": hex(pinot_regs[25]),
                            "owner": pinot_owner,
                        }
                    )
                    if address in (
                        0xFFFFFF800157E734,
                        0xFFFFFF800157E738,
                        0xFFFFFF800157E740,
                    ):
                        entry = report["pinot_panel_stages"][-1]
                        try:
                            entry["panel_config_flag_stack"] = hex(
                                struct.unpack(
                                    "<I", read_memory(pinot_regs[31] + 12, 4)
                                )[0]
                            )
                            entry["controller_status_1b4"] = hex(
                                struct.unpack(
                                    "<I", read_memory(pinot_regs[19] + 0x1B4, 4)
                                )[0]
                            )
                        except (ValueError, AssertionError, struct.error) as exc:
                            entry["state_read_error"] = str(exc)
                    entry = report["pinot_panel_stages"][-1]
                    if address == 0xFFFFFF8001480D64:
                        entry["requested_iic_config"] = read_memory(
                            pinot_regs[1], 16
                        ).hex()
                        entry["maximum_bus_rate"] = struct.unpack(
                            "<I", read_memory(pinot_regs[0] + 0x11C, 4)
                        )[0]
                    if pinot_stage == "ApplePinotLCD::start":
                        report["pinot_start_entry"] = {
                            "this": hex(pinot_regs[0]),
                            "provider": hex(pinot_regs[1]),
                            "thread": pinot_owner.get("thread"),
                            "sp": hex(pinot_regs[31]),
                            "return_pc": hex(pinot_regs[30]),
                        }
                    original_entry = report.get("pinot_start_entry", {})
                    if pinot_stage.startswith("Pinot ") and original_entry.get(
                        "thread"
                    ) == pinot_owner.get("thread"):
                        entry["start_thread_verified"] = True
                        try:
                            obj = int(original_entry["this"], 16)
                            raw = read_memory(obj + 136, 68)
                            entry["panel_id"] = hex(
                                struct.unpack_from("<I", raw, 52)[0]
                            )
                            entry["panel_class"] = struct.unpack_from("<I", raw, 56)[0]
                            entry["callbacks"] = {
                                name: hex(struct.unpack_from("<Q", raw, off)[0])
                                for name, off in (
                                    ("mipi", 0),
                                    ("ldo", 8),
                                    ("reset", 16),
                                    ("gpio", 24),
                                )
                            }
                        except (ValueError, AssertionError, struct.error) as exc:
                            entry["panel_state_error"] = str(exc)
                        if pinot_stage == "Pinot start final boolean":
                            report["pinot_start_return"] = entry.copy()
                    with (RUN / "panel-progress.jsonl").open("a") as output:
                        output.write(json.dumps(entry) + "\n")
                breakpoint(address, False)
                del milestones[address]
                continue
            if label.startswith("AppleARMFunction original: "):
                armfn_regs = struct.unpack_from("<33Q", current)
                owner = capture_active_guest_process()
                point = label.removeprefix("AppleARMFunction original: ")
                if (
                    owner.get("thread") == report.get("armfunction_primary_thread")
                    and len(report["armfunction_primary_trace"]) < 120
                ):
                    sample = {
                        "point": point,
                        "pc": hex(address),
                        "thread": owner["thread"],
                        "x0": hex(armfn_regs[0]),
                        "x1": hex(armfn_regs[1]),
                        "x19": hex(armfn_regs[19]),
                        "x20": hex(armfn_regs[20]),
                    }
                    if point == "withProvider(char*) entry":
                        try:
                            sample["function_property"] = (
                                read_memory(armfn_regs[1], 64)
                                .split(b"\x00")[0]
                                .decode("utf-8", "replace")
                            )
                        except (ValueError, AssertionError) as exc:
                            sample["name_read_error"] = str(exc)
                    report["armfunction_primary_trace"].append(sample)
                breakpoint(address, False)
                packet("s")
                if len(report["armfunction_primary_trace"]) < 120:
                    breakpoint(address)
                else:
                    del milestones[address]
                continue
            if label.startswith("ADBE0 original startup: "):
                adbe0_regs = struct.unpack_from("<33Q", current)
                sample = {
                    "stage": label.removeprefix("ADBE0 original startup: "),
                    "pc": hex(address),
                    "x0": hex(adbe0_regs[0]),
                    "x1": hex(adbe0_regs[1]),
                    "x19": hex(adbe0_regs[19]),
                    "x20": hex(adbe0_regs[20]),
                    "owner": capture_active_guest_process(),
                }
                if "IOMFB" in sample["stage"]:
                    instance = adbe0_regs[19]
                    if 0xFFFFFF0000000000 <= instance < 0xFFFFFFFFFFFFFFFF:
                        try:
                            virtual = struct.unpack("<Q", read_memory(instance, 8))[0]
                            target = struct.unpack(
                                "<Q", read_memory(virtual + 0x678, 8)
                            )[0]
                            sample.update(
                                instance=hex(instance),
                                vtable=hex(virtual),
                                original_dispatch_target=hex(target),
                            )
                        except (ValueError, AssertionError, struct.error) as exc:
                            sample["vtable_inspect_error"] = str(exc)
                if len(report["adbe0_startup_trace"]) < 64:
                    report["adbe0_startup_trace"].append(sample)
                with (RUN / "display-progress.jsonl").open("a") as output:
                    output.write(json.dumps(sample) + "\n")
                breakpoint(address, False)
                single_step_stop = packet("s")
                if len(report["adbe0_startup_trace"]) < 64:
                    breakpoint(address)
                else:
                    del milestones[address]
                continue
            if label == "PMGR state transition ack diagnostic":
                base = struct.unpack_from("<Q", current, 9 * 8)[0]
                offset = struct.unpack_from("<Q", current, 22 * 8)[0]
                assert 0xFFFFFF0000000000 <= base < 0xFFFFFFFFFFFFFFFF
                assert offset in (0x20000, 0x20008)
                location = base + offset
                before = struct.unpack("<I", read_memory(location, 4))[0]
                request = before & 15
                after = before & ~240 | request << 4
                assert len(report["pmgr_ack_trace"]) < 100
                write_memory(location, struct.pack("<I", after))
                assert struct.unpack("<I", read_memory(location, 4))[0] == after
                report["pmgr_ack_trace"].append(
                    {
                        "guest_va": hex(location),
                        "before": hex(before),
                        "after": hex(after),
                        "requested_state": request,
                    }
                )
                breakpoint(address, False)
                packet("s")
                breakpoint(address)
                continue
            if label == "load_init_program":
                proc = struct.unpack_from("<Q", current)[0]
                (pid,) = struct.unpack("<I", read_memory(proc + 16, 4))
                event["pid"] = pid
                report["init_pid"] = pid
                head = 0xFFFFFF8000A4B270
                assert read_memory(0xFFFFFF8000A33134, 16) == bytes.fromhex(
                    "fd7bbfa9fd030091f44fbfa9f657bfa9"
                )
                node_address = VA + ARGS_PA - PA + 0x2000
                assert read_memory(head, 8) == bytes(8)
                node = loaded_trust_node()
                assert node_address + len(node) < VA + DT_PA - PA
                write_memory(node_address, node)
                assert read_memory(node_address, len(node)) == node
                write_memory(head, struct.pack("<Q", node_address))
                assert read_memory(head, 8) == struct.pack("<Q", node_address)
                event.update(
                    exact_cache_trust_entry=cache_audit, trust_node=hex(node_address)
                )
                report["exact_cache_trust_installed"] = True
            if label == "dyld bootstrap returned":
                main_entry = struct.unpack_from("<Q", current)[0]
                report["dyld_bootstrap_returned"] = True
                launchd = (profile / "launchd.macho").read_bytes()
                assert (
                    hashlib.sha256(launchd).hexdigest()
                    == "5fe0a117f10cbd5a9249b6efab2291f424a94978bdc542b0b701e931dc396945"
                )
                slide = main_entry - 0x100005F58
                assert 0 <= slide < 0x10000000 and slide % 0x1000 == 0
                launchd_entry_bytes = launchd[0x5F58 : 0x5F58 + 32]
                event.update(main_entry=hex(main_entry), launchd_slide=hex(slide))
                milestones[main_entry] = "launchd original entry"
                breakpoint(main_entry)
            if label.startswith("display start phase: "):
                phase_event = {
                    "stage": label,
                    "pc": hex(address),
                    "registers_x0_x3": [
                        hex(x) for x in struct.unpack_from("<4Q", current)
                    ],
                }
                if address == 0xFFFFFF80015C7D6C:
                    actual = struct.unpack("<Q", read_memory(0xFFFFFF80015D6100, 8))[0]
                    phase_event["callback_import_target"] = hex(actual)
                    report["display_callback_import_target"] = hex(actual)
                    phase_event["arguments_x0_x4"] = [
                        hex(x) for x in struct.unpack_from("<5Q", current)
                    ]
                    if 0xFFFFFF8000000000 <= actual < 0xFFFFFF8100000000:
                        milestones[actual] = "display callback target reached"
                        breakpoint(actual)
                report.setdefault("display_start_phases", []).append(phase_event)
                breakpoint(address, False)
                del milestones[address]
                packet("s")
                continue
            if label.startswith("AIC registry: "):
                count = report.setdefault("aic_registry_counts", {}).get(label, 0) + 1
                report["aic_registry_counts"][label] = count
                if count <= 14:
                    registers = struct.unpack_from("<5Q", current)
                    trace = {
                        "stage": label,
                        "pc": hex(address),
                        "x0_x4": [hex(x) for x in registers],
                        "ordinal": count,
                    }
                    if address in (
                        0xFFFFFF80019A8298,
                        0xFFFFFF80005A32A4,
                        0xFFFFFF80005A3314,
                    ):
                        object_addr = registers[1]
                        if object_addr >= 0xFFFFFF0000000000:
                            try:
                                string_object = read_memory(object_addr, 32)
                                trace["symbol_object_first_32"] = string_object.hex()
                                cstring_address = struct.unpack_from(
                                    "<Q", string_object, 24
                                )[0]
                                if cstring_address >= 0xFFFFFF0000000000:
                                    trace["symbol_name"] = (
                                        read_memory(cstring_address, 64)
                                        .split(b"\x00", 1)[0]
                                        .decode(errors="replace")
                                    )
                            except (AssertionError, ValueError) as exc:
                                trace["symbol_read_error"] = str(exc)
                    report.setdefault("aic_registry_events", []).append(trace)
                if count == 14:
                    breakpoint(address, False)
                    del milestones[address]
                else:
                    breakpoint(address, False)
                    packet("s")
                    breakpoint(address)
                continue
            if label.startswith("IRQ factory phase: "):
                irq_event = {
                    "stage": label,
                    "pc": hex(address),
                    "x0_x3": [hex(x) for x in struct.unpack_from("<4Q", current)],
                }
                if address == 0xFFFFFF8000576038:
                    irq_event["controller_method_pointer"] = hex(
                        struct.unpack_from("<Q", current, 4 * 8)[0]
                    )
                if address == 0xFFFFFF8000591224:
                    irq_event["virtual_get_interrupt_type_target"] = hex(
                        struct.unpack_from("<Q", current, 8 * 8)[0]
                    )
                    report["virtual_get_interrupt_type_target"] = irq_event[
                        "virtual_get_interrupt_type_target"
                    ]
                report.setdefault("irq_factory_phases", []).append(irq_event)
                breakpoint(address, False)
                del milestones[address]
                packet("s")
                continue
            if label == "display callback target reached":
                report["display_callback_target_executed"] = True
                report["display_callback_target_arguments"] = [
                    hex(x) for x in struct.unpack_from("<5Q", current)
                ]
                breakpoint(address, False)
                del milestones[address]
                packet("s")
                continue
            if label.startswith("original graphics return: "):
                stack = surface_returns.get(address, [])
                owner_at_return = capture_active_guest_process()
                thread_at_return = owner_at_return.get("thread")
                sp_at_return = hex(struct.unpack_from("<Q", current, 31 * 8)[0])
                match_index = next(
                    (
                        i
                        for i in range(len(stack) - 1, -1, -1)
                        if stack[i].get("thread") == thread_at_return
                        and stack[i].get("entry_sp") == sp_at_return
                    ),
                    None,
                )
                if match_index is not None:
                    original = stack.pop(match_index)
                    value = struct.unpack_from("<Q", current, 0)[0]
                    record = {
                        "function": original["function"],
                        "this": original["this"],
                        "return_pc": hex(address),
                        "returned_x0": hex(value),
                        "return_boolean": bool(value),
                        "process": owner_at_return,
                        "entry_thread": original["thread"],
                        "entry_sp": original["entry_sp"],
                        "return_sp": sp_at_return,
                        "return_entry_thread_verified": True,
                        "return_entry_sp_verified": True,
                    }
                    report.setdefault("graphics_function_returns", []).append(record)
                    event.update(record)
                else:
                    unmatched = report.setdefault("unmatched_graphics_return_stops", [])
                    if len(unmatched) < 30:
                        unmatched.append(
                            {
                                "pc": hex(address),
                                "thread": thread_at_return,
                                "sp": sp_at_return,
                                "pending_threads": [x.get("thread") for x in stack],
                                "pending_sps": [x.get("entry_sp") for x in stack],
                            }
                        )
                breakpoint(address, False)
                handoff = False
                if handoff and False:
                    live = bytearray(regs())
                    assert pc(live) == 0xFFFFFF80016B1A50
                    struct.pack_into("<Q", live, 32 * 8, 0xFFFFFF80016B1A64)
                    write_regs(live)
                    report["adbe0_skipped_original_iolog_once"] = {
                        "original_pc": hex(address),
                        "resumed_original_code_at": "0xffffff80016b1a64",
                        "reason": "isolate post-pipe IOLog-blocking hypothesis",
                    }
                if handoff:
                    handoff_trace = []
                    for _ in range(36):
                        step_result = packet("s")
                        at_pc = pc(regs())
                        handoff_trace.append({"pc": hex(at_pc), "stop": step_result})
                        if not 0xFFFFFF80016B1A50 <= at_pc <= 0xFFFFFF80016B1BAC:
                            break
                        if at_pc in milestones and at_pc != address:
                            breakpoint(at_pc, False)
                            if milestones[at_pc].startswith("ADBE0 original startup: "):
                                del milestones[at_pc]
                    report["adbe0_pipe_return_step_trace"] = handoff_trace
                else:
                    packet("s")
                if (
                    stack
                    and len(report.get("unmatched_graphics_return_stops", [])) < 30
                ):
                    breakpoint(address)
                else:
                    surface_returns.pop(address, None)
                    del milestones[address]
                continue
            if label.startswith("original graphics: "):
                counter = report["graphics_call_counts"]
                counter[label] = counter.get(label, 0) + 1
                if counter[label] <= 12:
                    event["original_function"] = label[19:]
                    event["args_x0_x3"] = [
                        hex(x) for x in struct.unpack_from("<4Q", current)
                    ]
                    event["call_number"] = counter[label]
                    event["process"] = capture_active_guest_process()
                    if label == "original graphics: IOMobileFramebuffer::start":
                        candidate_this, candidate_provider = struct.unpack_from(
                            "<2Q", current
                        )
                        objects = {}
                        for role, ptr in (
                            ("this", candidate_this),
                            ("provider", candidate_provider),
                        ):
                            if 0xFFFFFF0000000000 <= ptr < 0xFFFFFFFFFFFFFFFF:
                                try:
                                    vptr = struct.unpack("<Q", read_memory(ptr, 8))[0]
                                    objects[role] = {
                                        "instance": hex(ptr),
                                        "vtable": hex(vptr),
                                    }
                                    if role == "this":
                                        objects[role]["display_controller"] = hex(
                                            struct.unpack(
                                                "<Q", read_memory(ptr + 0x3D0, 8)
                                            )[0]
                                        )
                                        objects[role]["startup_flags"] = read_memory(
                                            ptr + 0x580, 4
                                        ).hex()
                                except (
                                    ValueError,
                                    AssertionError,
                                    struct.error,
                                ) as exc:
                                    objects[role] = {
                                        "instance": hex(ptr),
                                        "error": str(exc),
                                    }
                        event["original_display_object_vtables"] = objects
                    if label in (
                        "original graphics: IOMobileFramebuffer::swap_submit",
                        "original graphics: IOMobileFramebuffer::swap_queue",
                    ):
                        name = (
                            "swap-submit"
                            if label.endswith("swap_submit")
                            else "swap-queue"
                        )
                        object_pointer = struct.unpack_from("<Q", current, 8)[0]
                        if 0xFFFFFF0000000000 <= object_pointer < 0xFFFFFFFFFFFFFFFF:
                            try:
                                length = min(0x240, 0x1000 - (object_pointer & 0xFFF))
                                raw = read_memory(object_pointer, length)
                                (RUN / f"guest-{name}-object.bin").write_bytes(raw)
                                event["captured_guest_object"] = {
                                    "address": hex(object_pointer),
                                    "length": len(raw),
                                    "sha256": hashlib.sha256(raw).hexdigest(),
                                    "nonzero_bytes": sum((1 for b in raw if b)),
                                    "first_128_bytes": raw[:128].hex(),
                                    "candidate_kernel_pointers": [
                                        {"offset": hex(offset), "value": hex(value)}
                                        for offset in range(0, len(raw) - 7, 8)
                                        if (
                                            value := struct.unpack_from(
                                                "<Q", raw, offset
                                            )[0]
                                        )
                                        >= 0xFFFFFF0000000000
                                    ][:48],
                                }
                                report.setdefault("real_guest_swap_objects", []).append(
                                    event["captured_guest_object"]
                                )
                            except (AssertionError, ValueError, struct.error) as exc:
                                event["swap_object_inspection_error"] = str(exc)
                                report.setdefault(
                                    "swap_object_inspection_errors", []
                                ).append(
                                    {"address": hex(object_pointer), "error": str(exc)}
                                )
                    report.setdefault("graphics_call_samples", []).append(event)
                if label in (
                    "original graphics: IOMobileFramebuffer::start",
                    "original graphics: AppleDisplayPipe::start_hardware",
                ):
                    ret_pc = struct.unpack_from("<Q", current, 30 * 8)[0]
                    if ret_pc >= 0xFFFFFF8000000000 and ret_pc != address:
                        pending = surface_returns.setdefault(ret_pc, [])
                        first_pending_return = not pending
                        pending.append(
                            {
                                "function": label,
                                "this": hex(struct.unpack_from("<Q", current, 0)[0]),
                                "thread": capture_active_guest_process().get("thread"),
                                "entry_sp": hex(
                                    struct.unpack_from("<Q", current, 31 * 8)[0]
                                ),
                            }
                        )
                        if first_pending_return:
                            milestones[ret_pc] = (
                                "original graphics return: " + label[19:]
                            )
                            breakpoint(ret_pc)
                        event["return_breakpoint"] = hex(ret_pc)
                if counter[label] == 12:
                    breakpoint(address, False)
                    del milestones[address]
                else:
                    breakpoint(address, False)
                    packet("s")
                    breakpoint(address)
                continue
            if label == "launchd original entry":
                assert struct.unpack_from("<I", current, 33 * 8)[0] & 15 == 0
                entry_memory = packet(f"m{address:x},20")
                if entry_memory == "E14":
                    event["entry_page_pending"] = True
                    report["events"].append(event)
                    breakpoint(address, False)
                    packet("s")
                    breakpoint(address)
                    continue
                assert bytes.fromhex(entry_memory) == launchd_entry_bytes
                event["original_entry_bytes_verified"] = True
                report["launchd_entry_verified"] = True
                guest_process_log.write("launchd started\n")
                capture_console()
                next_instruction = address + 4
                assert launchd_entry_bytes[:4] != b"\x00" * 4
                milestones[next_instruction] = "launchd first instruction completed"
                breakpoint(next_instruction)
                del milestones[address]
                event["continuation_breakpoint"] = hex(next_instruction)
            if label == "launchd first instruction completed":
                assert report.get("launchd_entry_verified")
                assert struct.unpack_from("<I", current, 33 * 8)[0] & 15 == 0
                assert read_memory(address, 16) == launchd_entry_bytes[4:20]
                report["launchd_first_instruction_executed"] = True
                capture_framebuffer()
                event["original_instruction_bytes_verified"] = True
                del milestones[address]
                for label_to_disable in (
                    "unix_syscall from userland",
                    "EL0 synchronous exception",
                    "EL1 synchronous exception (SP0)",
                    "EL1 synchronous exception (SP1)",
                    "raw RAM-disk mdevrw",
                ):
                    for old_pc, old_label in tuple(milestones.items()):
                        if old_label == label_to_disable:
                            breakpoint(old_pc, False)
                            del milestones[old_pc]
                for entry_pc, entry_label in (
                    (0xFFFFFF80004D995C, "native kernel execve"),
                    (0xFFFFFF80004D87B8, "native kernel posix_spawn"),
                    (0xFFFFFF80004D9EE4, "native kernel exit1"),
                ):
                    milestones[entry_pc] = entry_label
                    breakpoint(entry_pc)
                monitor_result = packet("qRcmd," + b"log unimp,guest_errors".hex())
                report["fast_qemu_log_mode"] = monitor_result
                report["fast_mode_started_at_launchd_entry"] = True
            if label in (
                "native kernel execve",
                "native kernel posix_spawn",
                "native kernel exit1",
            ):
                guest_proc = capture_active_guest_process()
                event["process"] = guest_proc
                event["kernel_call_args"] = [
                    hex(x) for x in struct.unpack_from("<4Q", current)
                ]
                if label in ("native kernel execve", "native kernel posix_spawn"):
                    args_va = struct.unpack_from("<Q", current, 8)[0]
                    path_offset = 8 if label == "native kernel posix_spawn" else 0
                    try:
                        path_pointer = struct.unpack(
                            "<Q", read_memory(args_va + path_offset, 8)
                        )[0]
                        assert path_pointer != 0
                        event["requested_exec_path"] = (
                            read_memory(path_pointer, 0x100)
                            .split(b"\x00", 1)[0]
                            .decode(errors="replace")
                        )
                    except (AssertionError, ValueError, struct.error) as exc:
                        event["path_probe_error"] = str(exc)
                    if "SwitchBoard" in event.get("requested_exec_path", ""):
                        report.setdefault("requested_graphics_launches", []).append(
                            event["requested_exec_path"]
                        )
                        executable_name = pathlib.Path(
                            event["requested_exec_path"]
                        ).name[:16]
                        names = report.setdefault("live_app_exec_names", [])
                        if executable_name not in names:
                            names.append(executable_name)
                item = {
                    "stage": label,
                    "process": guest_proc,
                    "after_seconds": time.monotonic() - started_at,
                    "requested_exec_path": event.get("requested_exec_path"),
                    "path_probe_error": event.get("path_probe_error"),
                    "event_ordinal": len(report.get("fast_process_events", [])) + 1,
                }
                report.setdefault("fast_process_events", []).append(item)
                if not live_bridge and (
                    item["event_ordinal"] == 28
                    or "SwitchBoard" in (item["requested_exec_path"] or "")
                ):
                    original_mach_sites = {
                        0xFFFFFF800022D074: "original Mach IPC: mach_msg_overwrite_trap",
                        0xFFFFFF800022D228: "original Mach IPC: mach_msg_trap",
                        0xFFFFFF800024B9DC: "original Mach IPC: semaphore_wait_trap",
                    }
                    for mach_pc, mach_name in original_mach_sites.items():
                        if mach_pc not in milestones:
                            milestones[mach_pc] = mach_name
                            breakpoint(mach_pc)
                    report["mach_tracing_enabled_after_launch_event"] = item[
                        "event_ordinal"
                    ]
                if item["event_ordinal"] in (28, 55, 70):
                    snapshot = capture_guest_process_list()
                    snapshot["after_launch_event"] = item["event_ordinal"]
                    report.setdefault("process_list_snapshots", []).append(snapshot)
                    matches = [
                        p
                        for p in snapshot["processes"]
                        if p["comm"] in ("SwitchBoard", "backboardd", "SpringBoard")
                    ]
                    if matches:
                        report.setdefault("graphics_process_seen", []).extend(matches)
                with (RUN / "service-events.jsonl").open("a") as output:
                    output.write(json.dumps(item) + "\n")
                if item["requested_exec_path"]:
                    guest_process_log.write(
                        f"{item['after_seconds']:7.2f}s  {item['requested_exec_path']}\n"
                    )
                report["events"].append(event)
                if guest_proc.get("comm") in (
                    "SwitchBoard",
                    "backboardd",
                    "SpringBoard",
                ):
                    report.setdefault("graphics_process_seen", []).append(guest_proc)
                breakpoint(address, False)
                packet("s")
                breakpoint(address)
                continue
            if label == "user read returned":
                fd, buffer, requested, caller = pending_user_reads.pop(address)
                actual = struct.unpack_from("<Q", current, 0)[0]
                pstate = struct.unpack_from("<I", current, 33 * 8)[0]
                event.update(
                    fd=fd,
                    requested=requested,
                    result_x0=actual,
                    buffer=hex(buffer),
                    entry_process=caller,
                    return_pstate=hex(pstate),
                    syscall_return_error=bool(pstate & 1 << 29),
                )
                if requested == 0x8000:
                    event["buffer_page_validity"] = [
                        {
                            "offset": hex(pos),
                            "valid": capture_user_translation(buffer + pos)["valid"],
                        }
                        for pos in (0, 0x1000, 0x3000, 0x5000, 0x7000)
                    ]
                if (
                    not event["syscall_return_error"]
                    and 0 < actual <= requested <= 0x10000
                ):
                    event["returned_bytes_first_64"] = read_memory(
                        buffer, min(actual, 64)
                    ).hex()
                    if actual >= 1056:
                        event["returned_bytes_at_1024"] = read_memory(
                            buffer + 0x400, 32
                        ).hex()
                report["events"].append(event)
                breakpoint(address, False)
                del milestones[address]
                continue
            if label == "unix_syscall from userland":
                report["userland_syscall_reached"] = True
                saved_state_pointer = struct.unpack_from("<Q", current)[0]
                saved = read_memory(saved_state_pointer, 0x128)
                (flavor,) = struct.unpack_from("<I", saved)
                assert flavor == 21
                number, effective_number, arguments = unix_syscall(saved)
                (user_pc,) = struct.unpack_from("<Q", saved, 0x108)
                (user_pstate,) = struct.unpack_from("<I", saved, 0x110)
                assert user_pstate & 15 == 0
                event.update(
                    syscall=number, user_pc=hex(user_pc), user_pstate=hex(user_pstate)
                )
                event["effective_syscall"] = effective_number
                event["arguments"] = [hex(x) for x in arguments]
                if effective_number in (1, 59, 244) or (
                    effective_number == 3 and arguments[2] == 0x8000
                ):
                    event["process"] = capture_active_guest_process()
                report["user_syscall_count"] = report.get("user_syscall_count", 0) + 1
                bucket = str(effective_number)
                histogram = report["syscall_histogram"]
                histogram[bucket] = histogram.get(bucket, 0) + 1
                if report["user_syscall_count"] % 64 == 0:
                    sample = capture_active_guest_process()
                    if "pid" in sample:
                        report["observed_processes"][str(sample["pid"])] = sample
                if report["user_syscall_count"] == 1:
                    assert number == 372
                    slide = user_pc - 0x12001F10C
                    assert 0 <= slide < 0x10000000 and slide % 0x1000 == 0
                    assert read_memory(user_pc - 8, 8) == bytes.fromhex(
                        "902e80d2011000d4"
                    )
                    event.update(
                        binary="original dyld ARM64 __thread_selfid",
                        dyld_slide=hex(slide),
                        syscall_instruction_verified=True,
                    )
                    returned = 0x120001054 + slide
                    milestones[returned] = "dyld bootstrap returned"
                    breakpoint(returned)
                if report.get("launchd_first_instruction_executed"):
                    report["launchd_post_entry_syscalls"] = (
                        report.get("launchd_post_entry_syscalls", 0) + 1
                    )
                    if (
                        effective_number in (3, 396)
                        and report.get("user_read_trace_count", 0) < 32
                    ):
                        fd, buffer, requested = arguments[:3]
                        if (
                            0 < requested <= 0x10000
                            and user_pc not in pending_user_reads
                        ):
                            if requested == 0x8000:
                                event["buffer_page_validity_on_entry"] = [
                                    {
                                        "offset": hex(pos),
                                        "valid": capture_user_translation(buffer + pos)[
                                            "valid"
                                        ],
                                    }
                                    for pos in (0, 0x1000, 0x3000, 0x5000, 0x7000)
                                ]
                            pending_user_reads[user_pc] = (
                                fd,
                                buffer,
                                requested,
                                event.get("process"),
                            )
                            milestones[user_pc] = "user read returned"
                            breakpoint(user_pc)
                            report["user_read_trace_count"] = (
                                report.get("user_read_trace_count", 0) + 1
                            )
                    if effective_number in (59, 244):
                        try:
                            path_pointer = (
                                arguments[0] if effective_number == 59 else arguments[1]
                            )
                            path = read_memory(path_pointer, 0x100).split(b"\x00", 1)[0]
                            event["exec_path"] = path.decode(errors="replace")
                        except (AssertionError, ValueError) as read_error:
                            event["exec_path_read_error"] = str(read_error)
                if effective_number in (4, 397):
                    fd, buffer, count = arguments[:3]
                    if fd in (1, 2) and 0 < count <= 0x1000:
                        data = read_memory(buffer, count)
                        with (RUN / "userland-output.txt").open("ab") as output:
                            output.write(data)
                        event["console_write_bytes"] = count
                        event["written_text"] = data[:512].decode(errors="replace")
                if effective_number == 1:
                    event["exit_status"] = arguments[0]
                    report["observed_process_exit_syscalls"] = (
                        report.get("observed_process_exit_syscalls", 0) + 1
                    )
                if event.get("process", {}).get("pid") is not None:
                    process_info = event["process"]
                    report["observed_processes"][str(process_info["pid"])] = (
                        process_info
                    )
                if any(
                    (
                        field in event
                        for field in (
                            "exec_path",
                            "exec_path_read_error",
                            "exit_status",
                            "written_text",
                        )
                    )
                ):
                    lifecycle = {
                        "number": report["user_syscall_count"],
                        "pid": (event.get("process") or {}).get("pid"),
                        "comm": (event.get("process") or {}).get("comm"),
                        "syscall": effective_number,
                    }
                    for field in (
                        "exec_path",
                        "exec_path_read_error",
                        "exit_status",
                        "written_text",
                    ):
                        if field in event:
                            lifecycle[field] = event[field]
                    with (RUN / "service-events.jsonl").open("a") as service_output:
                        service_output.write(
                            json.dumps(lifecycle, ensure_ascii=False) + "\n"
                        )
                    report["service_events_count"] += 1
                    if (
                        event.get("process", {}).get("pid") == 1
                        and effective_number == 1
                    ):
                        report["init_process_requested_exit"] = True
                if (
                    "exec_path" in event
                    or "exit_status" in event
                    or "written_text" in event
                    or (report["user_syscall_count"] % 0x100 == 0)
                ):
                    report["events"].append(event)
                syscall_limit = None
                if (
                    effective_number == 1
                    and False
                    or (
                        syscall_limit is not None
                        and report["user_syscall_count"] >= syscall_limit
                    )
                ):
                    report["userland_trace_stop"] = (
                        "exit requested"
                        if effective_number == 1
                        else "syscall observation limit"
                    )
                    break
                breakpoint(address, False)
                packet("s")
                breakpoint(address)
                continue
            if label == "IOSecureBSDRoot":
                (provider,) = struct.unpack("<Q", read_memory(0xFFFFFF8000853788, 8))
                event["platform_expert"] = hex(provider)
                if provider:
                    (vtable,) = struct.unpack("<Q", read_memory(provider, 8))
                    (method,) = struct.unpack("<Q", read_memory(vtable + 0x3A0, 8))
                    event["SecureRootName_handler"] = hex(method)
                else:
                    report["missing_platform_expert_at_secure_root"] = True
                    report["events"].append(event)
                    break
            if label == "postmount thread wait":
                capture_backtrace()
                frames = report["backtrace"]
                if any(
                    (
                        "_IOSecureBSDRoot+" in f["symbol"]
                        or "_bsd_init+" in f["symbol"]
                        for f in frames
                    )
                ):
                    event["backtrace"] = frames
                    report["postmount_blocked_context"] = frames
                    report["events"].append(event)
                    break
                breakpoint(address, False)
                packet("s")
                breakpoint(address)
                continue
            if label == "vfs_mountroot returned":
                error_code = struct.unpack_from("<Q", current, 0)[0] & 0xFFFFFFFF
                event["errno"] = error_code
                report["root_mount_succeeded"] = error_code == 0
                guest_process_log.write(f"vfs_mountroot returned {error_code}\n")
                capture_console()
            if label == "raw RAM-disk mdevrw":
                uio = struct.unpack_from("<Q", current, 8)[0]
                if uio >= 0xFFFFFF0000000000:
                    memory = read_memory(uio, 40)
                    event.update(
                        uio=hex(uio),
                        disk_offset=hex(struct.unpack_from("<Q", memory, 16)[0]),
                        seg_flag=struct.unpack_from("<I", memory, 24)[0],
                        direction=struct.unpack_from("<I", memory, 28)[0],
                        remaining=struct.unpack_from("<Q", memory, 32)[0],
                    )
            if label == "raw RAM-disk uiomove64":
                source, count, uio = struct.unpack_from("<QQQ", current)
                if RAMDISK_PA <= source < RAMDISK_PA + root_size:
                    assert 0 < count <= 0x8000
                    assert source + count <= RAMDISK_PA + root_size
                    assert uio >= 0xFFFFFF0000000000
                    uio_flags = struct.unpack("<II", read_memory(uio + 24, 8))
                    assert uio_flags[1] == 0, f"Expected disk UIO_READ, got {uio_flags}"
                    bounce_pa = ARGS_PA + 0x4000
                    assert bounce_pa + count < DT_PA
                    event["native_copy_readback_verified"] = native_ramdisk_copy(
                        source, bounce_pa, count
                    )
                    struct.pack_into("<Q", current, 0, bounce_pa)
                    write_regs(current)
                    event.update(
                        original_disk_address=hex(source),
                        bounce_pa=hex(bounce_pa),
                        length=count,
                        uio_flags=list(uio_flags),
                        original_uiomove64_will_execute=True,
                    )
                    report["raw_disk_bounced_bytes"] = (
                        report.get("raw_disk_bounced_bytes", 0) + count
                    )
                    report["events"].append(event)
                else:
                    if count <= 0x100000 and uio >= 0xFFFFFF0000000000:
                        uio_flags = struct.unpack("<II", read_memory(uio + 24, 8))
                        if uio_flags[0] == 10 and uio_flags[1] == 0:
                            report.setdefault("unhandled_physical_uiomoves", []).append(
                                {
                                    "source": hex(source),
                                    "count": count,
                                    "uio": hex(uio),
                                    "flags": list(uio_flags),
                                }
                            )
                    breakpoint(address, False)
                    packet("s")
                    breakpoint(address)
                    continue
            if label == "physical RAM-disk copy":
                source, destination, count = struct.unpack_from("<QQQ", current)
                source_is_disk = (
                    RAMDISK_PA <= source and source + count <= RAMDISK_PA + root_size
                )
                destination_is_disk = (
                    RAMDISK_PA <= destination
                    and destination + count <= RAMDISK_PA + root_size
                )
                if source_is_disk != destination_is_disk:
                    assert source_is_disk == (address == DISK_READ_CALL)
                    assert report.get("physical_ramdisk_registered")
                    assert 0 < count <= 0x1000
                    other = destination if source_is_disk else source
                    assert PA <= other and other + count <= PA + RAM_SIZE
                    event.update(
                        source=hex(source),
                        destination=hex(destination),
                        bytes=count,
                        direction="read" if source_is_disk else "write",
                    )
                    if native_ramdisk_copy(
                        source, destination, count, allow_direct=True
                    ):
                        event["native_copy_readback_verified"] = True
                        report["events"].append(event)
                    returned = address + 4
                    struct.pack_into("<Q", current, 30 * 8, returned)
                    struct.pack_into("<Q", current, 32 * 8, returned)
                    write_regs(current)
                    continue
                breakpoint(address, False)
                packet("s")
                breakpoint(address)
                continue
            if label == "RTC service wait timeout":
                timeout_ns = struct.unpack_from("<Q", current, 8)[0]
                assert timeout_ns == 30000000000
                event.update(original_timeout_ns=timeout_ns, diagnostic_timeout_ns=0)
                struct.pack_into("<Q", current, 8, 0)
                write_regs(current)
            if label.startswith("AIC register"):
                offset = struct.unpack_from("<Q", current, 8)[0] & 0xFFFFFFFF
                assert offset & 3 == 0 and offset < 0x6000
                if label.endswith("read"):
                    value = aic_registers.get(offset, 0)
                    struct.pack_into("<Q", current, 0, value)
                else:
                    value = struct.unpack_from("<Q", current, 16)[0] & 0xFFFFFFFF
                    aic_registers[offset] = value
                event.update(
                    offset=hex(offset), value=hex(value), irq_delivery_implemented=False
                )
                report["events"].append(event)
                struct.pack_into("<Q", current, 32 * 8, address + 4)
                write_regs(current)
                continue
            if label.startswith("A7 cache-error register"):
                word = int.from_bytes(
                    bytes.fromhex(packet(f"m{address:x},4")), "little"
                )
                assert word in (0xD53BF808, 0xD51BF808)
                sysreg, register = (word >> 5 & 0x7FFF, word & 31)
                if word & 1 << 21:
                    value = apple_sysreg_values.get(sysreg, 0)
                    struct.pack_into("<Q", current, register * 8, value)
                else:
                    value = struct.unpack_from("<Q", current, register * 8)[0]
                    apple_sysreg_values[sysreg] = value
                event.update(system_register="S3_3_C15_C8_0", value=hex(value))
                report["events"].append(event)
                struct.pack_into("<Q", current, 32 * 8, address + 4)
                write_regs(current)
                continue
            if label == "mdevadd":
                device, base_page, page_count, physical = struct.unpack_from(
                    "<QQQQ", current
                )
                expected_base = (RAMDISK_PA - PA + VA & (1 << 64) - 1) >> 12
                assert device & 0xFFFFFFFF == 0xFFFFFFFF
                assert (
                    base_page == expected_base
                    and page_count == root_size >> 12
                    and (physical == 0)
                )
                struct.pack_into("<Q", current, 8, RAMDISK_PA >> 12)
                struct.pack_into("<Q", current, 24, 1)
                write_regs(current)
                event.update(
                    physical_ramdisk_adapter=True,
                    original_base_page=hex(base_page),
                    physical_base_page=hex(RAMDISK_PA >> 12),
                    page_count=page_count,
                )
                report["physical_ramdisk_registered"] = True
            if label == "L4_Aux secure monitor call":
                operation, vector, arg2, arg3 = struct.unpack_from("<QQQQ", current)
                event.update(
                    operation=hex(operation),
                    reset_vector_pa=hex(vector),
                    arg2=hex(arg2),
                    arg3=hex(arg3),
                )
                report["events"].append(event)
                if operation != 0x800 or arg2 != 0 or arg3 != 0:
                    report["unhandled_secure_monitor_operation"] = hex(operation)
                    break
                report["registered_reset_vector_pa"] = hex(vector)
                struct.pack_into("<Q", current, 0, 0)
                struct.pack_into("<Q", current, 32 * 8, address + 4)
                write_regs(current)
                continue
            if label == "panic":
                fmt = struct.unpack_from("<Q", current)[0]
                response = packet(f"m{fmt:x},100")
                if not response.startswith("E"):
                    event["format"] = (
                        bytes.fromhex(response)
                        .split(b"\x00")[0]
                        .decode(errors="replace")
                    )
                assert packet("Qqemu.PhyMemMode:1") == "OK"
                try:
                    pmgr = read_memory(0x20E000000, 0x40000)
                finally:
                    assert packet("Qqemu.PhyMemMode:0") == "OK"
                (RUN / "guest-pmgr-regs-at-panic.bin").write_bytes(pmgr)
                nonzero_words = [
                    (hex(off), hex(value))
                    for off in range(0, len(pmgr), 4)
                    if (value := struct.unpack_from("<I", pmgr, off)[0])
                ]
                event["pmgr_nonzero_words"] = nonzero_words[:80]
                event["pmgr_nonzero_words_total"] = len(nonzero_words)
                report["pmgr_register_snapshot_captured"] = True
            if label not in (
                "EL0 synchronous exception",
                "raw RAM-disk uiomove64",
                "physical RAM-disk copy",
            ) or (
                label == "EL0 synchronous exception"
                and event.get("repetitions", 0) >= 7
            ):
                report["events"].append(event)
            if label == "vm_fault for shared cache":
                values = struct.unpack_from("<8Q", current)
                if (
                    report.get("traced_late_vm_fault")
                    and fault_target is not None
                    and (values[1] & ~0xFFF != fault_target & ~0xFFF)
                ):
                    breakpoint(address, False)
                    packet("s")
                    breakpoint(address)
                    continue
                event["arguments"] = [hex(x) for x in values]
                (returned,) = struct.unpack_from("<Q", current, 30 * 8)
                milestones[returned] = "shared-cache vm_fault returned"
                vm_fault_returns.add(returned)
                breakpoint(returned)
                breakpoint(address, False)
                packet("s")
                breakpoint(address)
                continue
            if label == "shared-cache vm_fault returned":
                event["kern_return"] = struct.unpack_from("<Q", current)[0]
                event["selected_repeating_address"] = hex(fault_target)
                report["selected_vm_fault_result"] = event["kern_return"]
                event["vm_page_free_count"] = struct.unpack(
                    "<I", read_memory(0xFFFFFF8000803E48, 4)
                )[0]
                event["translation"] = capture_user_translation(fault_target)
                breakpoint(address, False)
                del milestones[address]
                continue
            if "exception" in label:
                recent_log = (RUN / "qemu.log").read_text(errors="replace")[-0x1000:]
                last_exception = (
                    "Taking exception" + recent_log.split("Taking exception")[-1]
                )
                user_vm_abort = (
                    label == "EL0 synchronous exception"
                    and last_exception.startswith(
                        (
                            "Taking exception 4 [Data Abort]",
                            "Taking exception 3 [Prefetch Abort]",
                        )
                    )
                )
                if user_vm_abort:
                    far_match = re.search("with FAR (0x[0-9a-f]+)", last_exception)
                    elr_match = re.search("with ELR (0x[0-9a-f]+)", last_exception)
                    if far_match and elr_match:
                        key = (far_match[1], elr_match[1])
                        ttbr_reg, _ = system_registers["TTBR0_EL1"]
                        ttbr = int.from_bytes(
                            bytes.fromhex(packet(f"p{ttbr_reg:x}")), "little"
                        )
                        fault_identity = (ttbr & 0xFFFFFFFFF000, *key)
                        event["fault_address_space_ttbr0"] = hex(fault_identity[0])
                        user_faults[fault_identity] = (
                            user_faults.get(fault_identity, 0) + 1
                        )
                        count = user_faults[fault_identity]
                        event.update(
                            fault_address=key[0], user_pc=key[1], repetitions=count
                        )
                        if count == 7 and int(key[0], 16) >= 0x180000000:
                            event["process"] = capture_active_guest_process()
                            report["repeating_fault_process"] = event["process"]
                            fault_target = int(key[0], 16)
                            event["translation"] = capture_user_translation(
                                fault_target
                            )
                            report["postlaunchd_fault_translation"] = event[
                                "translation"
                            ]
                            if not report.get("traced_late_vm_fault"):
                                milestones[0xFFFFFF800027B2F0] = (
                                    "vm_fault for shared cache"
                                )
                                breakpoint(0xFFFFFF800027B2F0)
                                report["traced_late_vm_fault"] = True
                        if count >= 12:
                            report["repeated_user_page_fault"] = {
                                "address": key[0],
                                "pc": key[1],
                                "count": count,
                            }
                            report["repeated_user_page_fault"]["ttbr0"] = hex(
                                fault_identity[0]
                            )
                            report["fault_at_stop_translation"] = (
                                capture_user_translation(int(key[0], 16))
                            )
                            report["fault_at_stop_process"] = (
                                capture_active_guest_process()
                            )
                            report["vm_page_counts_at_stop"] = {
                                "free": struct.unpack(
                                    "<I", read_memory(0xFFFFFF8000803E48, 4)
                                )[0],
                                "wire": struct.unpack(
                                    "<I", read_memory(0xFFFFFF8000803E4C, 4)
                                )[0],
                                "active": struct.unpack(
                                    "<I", read_memory(0xFFFFFF8000803F20, 4)
                                )[0],
                                "inactive": struct.unpack(
                                    "<I", read_memory(0xFFFFFF8000803F24, 4)
                                )[0],
                            }
                            break
                if (
                    last_exception.startswith("Taking exception 4 [Data Abort]")
                    or user_vm_abort
                    or (
                        label == "EL0 synchronous exception"
                        and last_exception.startswith("Taking exception 2")
                    )
                ):
                    breakpoint(address, False)
                    packet("s")
                    breakpoint(address)
                    event["original_fault_handler_allowed"] = True
                    continue
            if label == "unix_syscall from userland":
                report["userland_syscall_reached"] = True
            if (
                "exception" in label
                or label
                in ("panic", "unix_syscall from userland", "unclassified debugger stop")
                or (label == "bsd_init" and False)
                or (label == "machine_startup" and False)
            ):
                break
            breakpoint(address, False)
    report["monitor_registers_response"] = packet("qRcmd," + b"info registers".hex())
except Exception as error:
    if isinstance(error, LiveDisplayClosed) or live_window_closed.is_set():
        report["live_display_closed_by_user"] = True
    else:
        report["error"] = str(error)
    if not isinstance(error, (TimeoutError, LiveDisplayClosed)) and (
        not live_window_closed.is_set()
    ):
        report["inspection_error_traceback"] = traceback.format_exc()
    if (
        isinstance(error, TimeoutError)
        and (not live_window_closed.is_set())
        and connection
        and (process.poll() is None)
    ):
        try:
            connection.settimeout(5)
            if guest_running:
                connection.sendall(b"\x03")
                report["timeout_stop"] = receive_packet()
                guest_running = False
            else:
                report["timeout_stop"] = "already stopped at diagnostic breakpoint"
            report["timeout_pc"] = hex(pc(regs()))
            packet("qRcmd," + b"info registers".hex())
            report.pop("error", None)
            report["diagnostic_time_budget_reached"] = True
        except Exception as diagnostic_error:
            report["timeout_diagnostic_error"] = str(diagnostic_error)
finally:
    live_monitor_done.set()
    if live_frame_stream:
        live_frame_stream.close()
    reason = (
        "Window closed"
        if live_window_closed.is_set() or report.get("live_display_closed_by_user")
        else "Session time limit"
        if report.get("diagnostic_time_budget_reached")
        else "Error"
        if report.get("error")
        else "Stopped"
    )
    status = IPC / "live-status.json.tmp"
    status.write_text(json.dumps(dict(state="stopped", reason=reason)))
    status.replace(IPC / "live-status.json")
    if connection and process.poll() is None and report.get("setup_verified"):
        try:
            for bitmap in list(
                report.get("original_guest_bitmap_contexts", {}).values()
            ):
                if bitmap["process_at_creation"].get("comm") == "SwitchBoard":
                    capture_registered_guest_bitmap(
                        bitmap, "bounded test final snapshot"
                    )
            capture_backtrace()
            capture_console()
            capture_framebuffer()
        except Exception as console_error:
            report["console_capture_error"] = str(console_error)
    if live_ram:
        report["native_read_only_frame_transport"] = dict(
            bytes_read=live_ram.bytes_read,
            requests=live_ram.requests,
            verified_foreground_address_spaces=len(live_ram_verified_owners),
        )
        live_ram.close()
    if connection:
        connection.close()
    if process.poll() is None:
        process.terminate()
        try:
            process.wait(timeout=3)
        except subprocess.TimeoutExpired:
            process.kill()
            process.wait()
    console.close()
    guest_process_log.close()
    direct_copies = re.search(
        "NonUI RAM-disk: direct reads=(\\d+) writes=(\\d+) bytes=(\\d+)",
        (RUN / "console.log").read_text(errors="replace"),
    )
    if direct_copies:
        reads, writes, copied_bytes = map(int, direct_copies.groups())
        report["native_ramdisk_copy"]["direct_totals"] = dict(
            reads=reads, writes=writes, bytes=copied_bytes
        )
    if graphics_cache:
        graphics_cache.close()
    report["qemu_exit"] = process.returncode
    report["child_max_resident_bytes"] = resource.getrusage(
        resource.RUSAGE_CHILDREN
    ).ru_maxrss
    (RUN / "result.json").write_text(json.dumps(report, indent=2) + "\n")
    sockpath.unlink(missing_ok=True)
    live_ram_path.unlink(missing_ok=True)
    (IPC / "qemu.pid").unlink(missing_ok=True)
sys.exit(1 if "error" in report else 0)
