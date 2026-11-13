import json
import plistlib
import shutil
import struct
import subprocess
import tempfile
from pathlib import Path

from firmware import sha256

UTM_VERSION = "4.7.5"
UTM_BUILD = "118"
FRAMEWORK = "qemu-aarch64-softmmu.framework"
EXECUTABLE = Path(FRAMEWORK) / "Versions/A/qemu-aarch64-softmmu"
ORIGINAL_HASH = "f9b26b6520f5793f8104b49979a75a7cc8bddde6380a749531347884b0c0b53b"
ARM64 = 0x0100000C
TB_FLUSH_CALL = 0x3A4620
BRANCH_WORD = 0x9411A8FB
NOP = 0xD503201F


def debugger_cache_patch(data):
    magic, count = struct.unpack_from(">II", data)
    if magic != 0xCAFEBABE:
        raise ValueError("Expected the universal UTM QEMU binary.")
    arm64_slice = next(
        (
            offset
            for cpu, _, offset, _, _ in struct.iter_unpack(
                ">5I", data[8 : 8 + count * 20]
            )
            if cpu == ARM64
        ),
        None,
    )
    if arm64_slice is None:
        raise ValueError("UTM has no ARM64 QEMU slice.")
    (commands,) = struct.unpack_from("<I", data, arm64_slice + 16)
    position = arm64_slice + 32
    for _ in range(commands):
        command, size = struct.unpack_from("<II", data, position)
        if command == 0x19:
            (sections,) = struct.unpack_from("<I", data, position + 64)
            for index in range(sections):
                section = position + 72 + index * 80
                name = data[section : section + 16].split(b"\0")[0]
                address, length, offset = struct.unpack_from("<QQI", data, section + 32)
                if name == b"__text" and address <= TB_FLUSH_CALL < address + length:
                    site = arm64_slice + offset + TB_FLUSH_CALL - address
                    if struct.unpack_from("<I", data, site)[0] != BRANCH_WORD:
                        raise ValueError(
                            "The QEMU debugger cache-flush instruction changed."
                        )
                    struct.pack_into("<I", data, site, NOP)
                    return
        position += size
    raise ValueError("The QEMU debugger cache-flush site was not found.")


def prepare_engine(utm, directory):
    requirement = f"Install UTM {UTM_VERSION} (build {UTM_BUILD}) in Applications."
    info_file = utm / "Contents/Info.plist"
    frameworks = utm / "Contents/Frameworks"
    source = frameworks / EXECUTABLE
    if not info_file.is_file() or not source.is_file():
        raise ValueError(requirement)
    with info_file.open("rb") as info:
        version = plistlib.load(info)
    if (
        version.get("CFBundleShortVersionString") != UTM_VERSION
        or str(version.get("CFBundleVersion")) != UTM_BUILD
        or sha256(source) != ORIGINAL_HASH
    ):
        raise ValueError(f"This UTM build is unsupported. {requirement}")

    binary = directory / EXECUTABLE
    manifest = directory / "engine.json"
    if manifest.is_file() and binary.is_file():
        receipt = json.loads(manifest.read_text())
        if receipt == {"utm": str(utm), "sha256": sha256(binary)}:
            return binary
    directory.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    with tempfile.TemporaryDirectory(
        prefix=".engine-", dir=directory.parent
    ) as staging:
        stage = Path(staging) / "Frameworks"
        stage.mkdir()
        target = stage / FRAMEWORK
        subprocess.run(
            ["/usr/bin/ditto", str(frameworks / FRAMEWORK), str(target)], check=True
        )
        copy = stage / EXECUTABLE
        data = bytearray(copy.read_bytes())
        debugger_cache_patch(data)
        copy.write_bytes(data)
        for path in frameworks.glob("*.framework"):
            if path.name != FRAMEWORK:
                (stage / path.name).symlink_to(path, target_is_directory=True)
        subprocess.run(
            ["/usr/bin/codesign", "--force", "--sign", "-", str(target)],
            check=True,
            capture_output=True,
        )
        (stage / "engine.json").write_text(
            json.dumps({"utm": str(utm), "sha256": sha256(copy)}) + "\n"
        )
        if directory.exists():
            shutil.rmtree(directory)
        stage.rename(directory)
    return binary
