import bisect
import mmap
import struct
from arm64_vm import walk_4k


def read_user_memory(read_physical, ttbr, address, count, address_bits=39):
    if (
        address < 0x1000
        or count < 0
        or count > 0x20000
        or (address + count > 1 << address_bits)
    ):
        raise ValueError("Invalid or excessive user-memory read")
    result = bytearray()
    while len(result) < count:
        va = address + len(result)
        mapping = walk_4k(read_physical, ttbr, va, address_bits)
        if not mapping["valid"]:
            raise ValueError("User page is not resident at " + hex(va))
        size = min(count - len(result), 0x1000 - (va & 0xFFF))
        result.extend(read_physical(int(mapping["physical"], 16), size))
    return bytes(result)


def matches_switchboard_menu_caller(original, read_user, returned):
    offset = 0x5EAC
    base = returned - offset
    if base & 0xFFF or not 0x100000000 <= base < 0x200000000:
        return False
    header_size = 32 + struct.unpack_from("<I", original, 20)[0]
    return (
        read_user(base, header_size) == original[:header_size]
        and read_user(returned - 4, 16) == original[offset - 4 : offset + 12]
    )


def saved_user_state(saved):
    flavor, count = struct.unpack_from("<II", saved)
    if (flavor, count) != (21, 72):
        raise ValueError("Not this build's ARM_SAVED_STATE64: " + str((flavor, count)))
    words = struct.unpack_from("<31Q", saved, 8)
    sp, pc = struct.unpack_from("<QQ", saved, 0x100)
    pstate = struct.unpack_from("<I", saved, 0x110)[0]
    if pstate & 15:
        raise ValueError("Saved state is not EL0")
    return {
        "saved_flavor": flavor,
        "saved_count": count,
        "user_pc": hex(pc),
        "user_lr": hex(words[30]),
        "user_fp": hex(words[29]),
        "user_sp": hex(sp),
        "user_pstate": hex(pstate),
        "user_x16": hex(words[16]),
        "user_x0_x7": [hex(v) for v in words[:8]],
    }


def user_backtrace(state, read_user, limit=20):
    frames = [
        {"pc": state["user_pc"], "source": "saved PC"},
        {"pc": state["user_lr"], "source": "saved LR"},
    ]
    fp, sp = (int(state["user_fp"], 16), int(state["user_sp"], 16))
    seen = set()
    for _ in range(limit):
        if fp in seen or fp & 15 or (not sp <= fp < sp + 0x800000):
            break
        seen.add(fp)
        try:
            parent, returned = struct.unpack("<QQ", read_user(fp, 16))
        except (AssertionError, ValueError, struct.error) as exc:
            frames.append({"frame_pointer": hex(fp), "read_error": str(exc)})
            break
        frames.append({"pc": hex(returned), "frame_pointer": hex(fp)})
        if parent <= fp:
            break
        fp = parent
    return frames


def process_user_threads(read_kernel, proc, limit=64):

    def q(address):
        return struct.unpack("<Q", read_kernel(address, 8))[0]

    task = q(proc + 24)
    vm_map = q(task + 40)
    pmap = q(vm_map + 88)
    ttbr = q(pmap + 8)
    count = struct.unpack("<I", read_kernel(task + 104, 4))[0]
    if not (task >= 0xFFFFFF0000000000 and 0 < count <= 0x1000 and (ttbr & 0xFFF == 0)):
        raise ValueError("Invalid original task/thread map metadata")
    result = dict(
        proc=hex(proc),
        task=hex(task),
        vm_map=hex(vm_map),
        pmap=hex(pmap),
        ttbr0_physical=hex(ttbr),
        thread_count=count,
        threads=[],
    )
    thread, seen = (q(task + 72), set())
    for _ in range(min(count, limit)):
        if thread in seen or thread < 0xFFFFFF0000000000 or thread == task + 72:
            raise ValueError("Invalid original thread list")
        seen.add(thread)
        if q(thread + 0x6A0) != task:
            raise ValueError("Original thread.task does not match owner task")
        item = dict(thread=hex(thread))
        try:
            saved = q(thread + 0x660)
            item["saved_ptr"] = hex(saved)
            item.update(saved_user_state(read_kernel(saved, 0x128)))
        except (AssertionError, ValueError, struct.error) as exc:
            item["saved_state_error"] = str(exc)
        result["threads"].append(item)
        thread = q(thread + 0x300)
    result["truncated"] = count > limit
    result["original_queue_sentinel_verified"] = (
        thread == task + 72 if count <= limit else None
    )
    return result


class OriginalCache:
    def __init__(self, path):
        with open(path, "rb") as source:
            self.data = mmap.mmap(source.fileno(), 0, access=mmap.ACCESS_READ)
        if not self.data[:16].startswith(b"dyld_v1   arm64"):
            raise ValueError("Not the original arm64 cache format")
        mo, mn, io, ni = struct.unpack_from("<4I", self.data, 16)
        self.regions = [
            struct.unpack_from("<3Q2I", self.data, mo + i * 32) for i in range(mn)
        ]
        self.images = {}
        self.symbols = []
        for i in range(ni):
            va, _, _, po, _ = struct.unpack_from("<3Q2I", self.data, io + i * 32)
            name = self.cstring_offset(po)
            self.images[name] = va
            for cmd, off, size in self.commands(va):
                if cmd == 2:
                    so, n, st, sz = struct.unpack_from("<4I", self.data, off + 8)
                    for j in range(n):
                        si, typ, _, _, value = struct.unpack_from(
                            "<IBBHQ", self.data, so + j * 16
                        )
                        if value and typ & 14 == 14 and (si < sz):
                            self.symbols.append(
                                (value, self.cstring_offset(st + si), name)
                            )
        self.symbols.sort()
        self.addresses = [x[0] for x in self.symbols]

    def offset(self, address, count=1):
        for va, length, off, *_ in self.regions:
            if va <= address and address + count <= va + length:
                return off + address - va
        raise ValueError("Address outside original cache: " + hex(address))

    def read(self, address, count):
        off = self.offset(address, count)
        return self.data[off : off + count]

    def cstring_offset(self, off):
        end = self.data.find(b"\x00", off, off + 2048)
        if end < off:
            raise ValueError("Unterminated original cache string")
        return self.data[off:end].decode("utf8", "replace")

    def text(self, address):
        return self.cstring_offset(self.offset(address)) if address else ""

    def commands(self, address):
        header = self.offset(address, 32)
        magic, _, _, _, n, *_ = struct.unpack_from("<8I", self.data, header)
        if magic != 0xFEEDFACF or n > 200:
            raise ValueError("Invalid original cached Mach-O")
        off = header + 32
        for _ in range(n):
            cmd, size = struct.unpack_from("<II", self.data, off)
            if size < 8:
                raise ValueError("Invalid original load command")
            yield (cmd, off, size)
            off += size

    def methods(self, image_suffix, wanted_classes):
        (image,) = [v for k, v in self.images.items() if k.endswith(image_suffix)]
        result = {}
        for cmd, off, size in self.commands(image):
            if cmd != 25:
                continue
            for i in range(struct.unpack_from("<I", self.data, off + 64)[0]):
                sect = off + 72 + i * 80
                if self.data[sect : sect + 16].split(b"\x00")[0] != b"__objc_classlist":
                    continue
                start, length = struct.unpack_from("<QQ", self.data, sect + 32)
                for j in range(length // 8):
                    cls = struct.unpack("<Q", self.read(start + j * 8, 8))[0]
                    isa, _, _, _, bits = struct.unpack("<5Q", self.read(cls, 40))
                    name = self.text(
                        struct.unpack("<Q", self.read((bits & ~7) + 24, 8))[0]
                    )
                    if name not in wanted_classes:
                        continue
                    for kind, ptr in (("-", cls), ("+", isa)):
                        data = struct.unpack("<Q", self.read(ptr + 32, 8))[0] & ~7
                        methods = struct.unpack("<Q", self.read(data + 32, 8))[0]
                        if not methods:
                            continue
                        entsize, count = struct.unpack("<II", self.read(methods, 8))
                        stride = entsize & ~3
                        if not 24 <= stride <= 64 or count > 500:
                            raise ValueError("Unsupported original ObjC methods")
                        for k in range(count):
                            sel, _, imp = struct.unpack(
                                "<3Q", self.read(methods + 8 + k * stride, 24)
                            )
                            result[imp] = kind + "[" + name + " " + self.text(sel) + "]"
        return result

    def describe(self, address, slide):
        original = address - slide
        index = bisect.bisect_right(self.addresses, original) - 1
        if index < 0:
            return None
        value, name, image = self.symbols[index]
        if original - value > 0x20000 or not any(
            (v <= original < v + n for v, n, *_ in self.regions)
        ):
            return None
        return {"symbol": name, "offset": hex(original - value), "image": image}

    def close(self):
        self.data.close()
