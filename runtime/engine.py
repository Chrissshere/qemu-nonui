import hashlib
import struct
import subprocess
from pathlib import Path

from firmware import sha256

FRAMEWORK = "qemu-aarch64-softmmu.framework"
EXECUTABLE = Path(FRAMEWORK) / "Versions/A/qemu-aarch64-softmmu"
ORIGINAL_HASH = "f9b26b6520f5793f8104b49979a75a7cc8bddde6380a749531347884b0c0b53b"
TEXT_HASH = "ccc0f74a719d4a2b72a60c1fe1c3c883d2201fc76dd557335cb15aec70864621"
ARM64 = 0x0100000C
TB_FLUSH_CALL = 0x3A4620
BRANCH_WORD = 0x9411A8FB
NOP = 0xD503201F


def arm64_slice(data):
    magic, count = struct.unpack_from(">II", data)
    if magic != 0xCAFEBABE:
        raise ValueError("Expected the universal QEMU binary.")
    offset = next(
        (
            offset
            for cpu, _, offset, _, _ in struct.iter_unpack(
                ">5I", data[8 : 8 + count * 20]
            )
            if cpu == ARM64
        ),
        None,
    )
    if offset is None:
        raise ValueError("QEMU has no ARM64 slice.")
    return offset


def text_and_site(data):
    base = arm64_slice(data)
    (commands,) = struct.unpack_from("<I", data, base + 16)
    position = base + 32
    for _ in range(commands):
        command, size = struct.unpack_from("<II", data, position)
        if command == 0x19:
            (sections,) = struct.unpack_from("<I", data, position + 64)
            for index in range(sections):
                section = position + 72 + index * 80
                name = data[section : section + 16].split(b"\0")[0]
                address, length, offset = struct.unpack_from("<QQI", data, section + 32)
                if name == b"__text" and address <= TB_FLUSH_CALL < address + length:
                    start = base + offset
                    return start, length, start + TB_FLUSH_CALL - address
        position += size
    raise ValueError("The QEMU debugger cache-flush site was not found.")


def cache_flush_site(data):
    _, _, site = text_and_site(data)
    return site


def text_hash(data):
    start, length, site = text_and_site(data)
    blob = bytearray(data[start : start + length])
    struct.pack_into("<I", blob, site - start, BRANCH_WORD)
    return hashlib.sha256(blob).hexdigest()


def debugger_cache_patch(data):
    site = cache_flush_site(data)
    if struct.unpack_from("<I", data, site)[0] != BRANCH_WORD:
        raise ValueError("The QEMU debugger cache-flush instruction changed.")
    struct.pack_into("<I", data, site, NOP)


def framework_binary(root, name):
    base = name.removesuffix(".framework")
    for relative in (f"{name}/Versions/A/{base}", f"{name}/{base}"):
        path = root / relative
        if path.is_file():
            return path
    raise ValueError(f"Missing {name}.")


def linked_frameworks(binary):
    output = subprocess.check_output(["/usr/bin/otool", "-L", str(binary)], text=True)
    names = []
    for line in output.splitlines()[1:]:
        name = line.strip().split(" (", 1)[0]
        if ".framework/" not in name:
            continue
        if name.startswith(("@rpath/", "@loader_path/", "@executable_path/")):
            names.append(
                name.split(".framework/", 1)[0].rsplit("/", 1)[-1] + ".framework"
            )
    return names


def framework_closure(root):
    pending = [FRAMEWORK]
    ordered = []
    seen = set()
    while pending:
        name = pending.pop(0)
        if name in seen:
            continue
        seen.add(name)
        ordered.append(name)
        for dependency in linked_frameworks(framework_binary(root, name)):
            if dependency not in seen:
                pending.append(dependency)
    return ordered


def install_engine(source, destination):
    binary = framework_binary(source, FRAMEWORK)
    if sha256(binary) != ORIGINAL_HASH:
        raise ValueError("QEMU is not the 4.7.5 build 118 binary.")
    destination.mkdir(parents=True, exist_ok=True)
    for name in framework_closure(source):
        subprocess.run(
            ["/usr/bin/ditto", str(source / name), str(destination / name)], check=True
        )
    copy = destination / EXECUTABLE
    data = bytearray(copy.read_bytes())
    debugger_cache_patch(data)
    copy.write_bytes(data)
    if hashlib.sha256(data).hexdigest() == ORIGINAL_HASH:
        raise ValueError("The QEMU cache-flush patch did not apply.")


def prepare_engine(frameworks):
    binary = frameworks / EXECUTABLE
    if not binary.is_file():
        raise ValueError("This app has no QEMU. Build it with ./build.sh.")
    data = binary.read_bytes()
    if text_hash(data) != TEXT_HASH:
        raise ValueError("QEMU in this app is not the 4.7.5 build.")
    if struct.unpack_from("<I", data, cache_flush_site(data))[0] != NOP:
        raise ValueError("QEMU in this app is not prepared.")
    return binary
