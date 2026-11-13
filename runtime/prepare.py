import json
import os
import plistlib
import re
import subprocess
import tempfile
from pathlib import Path

from firmware import (
    BOOT_FILE_HASHES,
    decode_tree,
    kernelcache,
    matches_proven,
    retail_tree,
    select_inputs,
    sha256,
    var_seed,
    verify_file,
)

PROFILE_VERSION = 1
ROOT_BYTES = 0x50000000


def report(message):
    print(message, flush=True)


def check_hfs(path):
    attach = subprocess.run(
        [
            "/usr/bin/hdiutil",
            "attach",
            "-readonly",
            "-nomount",
            "-imagekey",
            "diskimage-class=CRawDiskImage",
            "-plist",
            str(path),
        ],
        check=True,
        capture_output=True,
    )
    devices = [
        item["dev-entry"]
        for item in plistlib.loads(attach.stdout)["system-entities"]
        if "dev-entry" in item
    ]
    whole = next(
        device for device in devices if re.fullmatch(r"/dev/disk[0-9]+", device)
    )
    try:
        checked = subprocess.run(
            ["/sbin/fsck_hfs", "-fn", devices[-1]], capture_output=True
        )
        if checked.returncode:
            raise OSError(
                checked.stdout.decode(errors="replace")
                + checked.stderr.decode(errors="replace")
            )
    finally:
        subprocess.run(
            ["/usr/bin/hdiutil", "detach", whole], check=True, capture_output=True
        )


def build_guest_disk(builder, root, seed, output, experimental):
    process = subprocess.Popen(
        [str(builder), str(root), str(seed), str(output)],
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
    )
    last = ""
    assert process.stdout is not None
    for line in process.stdout:
        last = line.rstrip()
        print(line, end="", flush=True)
    if process.wait():
        message = last or "The guest disk builder failed."
        if experimental:
            message = "Experimental import failed: " + message
        raise ValueError(message)


def prepare(profile, paths, builder, experimental=False):
    profile.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    with tempfile.TemporaryDirectory(prefix=".import-", dir=profile.parent) as staging:
        staging = Path(staging)
        output = staging / "profile"
        output.mkdir(mode=0o700)
        report("Checking import files")
        root, var, ipsw = select_inputs(paths, staging, experimental=experimental)
        if experimental:
            report(
                "Files match 11A24580o."
                if matches_proven(root, var)
                else "These files are not 11A24580o. Trying them anyway."
            )
        report("Reading the N51 DeviceTree")
        tree = json.dumps(
            decode_tree(retail_tree(ipsw, experimental=experimental)),
            separators=(",", ":"),
        )
        seed = staging / "seed.json"
        seed.write_text(json.dumps(var_seed(var, experimental=experimental)))
        report("Building the guest disk")
        build_guest_disk(builder, root, seed, output, experimental)
        image = output / "root.hfs"
        if image.stat().st_size != ROOT_BYTES:
            raise ValueError("The guest disk has an unexpected size.")
        container = output / "kernelcache.im4p"
        (output / "kernelcache.macho").write_bytes(
            kernelcache(container.read_bytes(), experimental=experimental)
        )
        container.unlink()
        (output / "devicetree.json").write_text(tree)
        problems = []
        for name, digest in BOOT_FILE_HASHES.items():
            path = output / name
            if experimental and (not path.is_file() or sha256(path) != digest):
                problems.append(name)
            elif not experimental:
                verify_file(path, digest)
        if problems:
            raise ValueError(
                "Experimental import failed: "
                + ", ".join(problems)
                + " do not match 11A24580o. Only 11A24580o is set up to boot."
            )
        report("Checking the guest disk")
        check_hfs(image)
        receipt = {
            "version": PROFILE_VERSION,
            "root": sha256(image),
            "devicetree": sha256(output / "devicetree.json"),
        }
        (output / "profile.json").write_text(json.dumps(receipt, indent=2) + "\n")
        os.rename(output, profile)
    report("Import complete")


def verify_profile(profile):
    receipt = json.loads((profile / "profile.json").read_text())
    if receipt["version"] != PROFILE_VERSION:
        raise ValueError("Import this build again with the current version of NonUI.")
    if (profile / "root.hfs").stat().st_size != ROOT_BYTES:
        raise ValueError("The prepared disk has an unexpected size.")
    verify_file(profile / "root.hfs", receipt["root"])
    verify_file(profile / "devicetree.json", receipt["devicetree"])
    for name, digest in BOOT_FILE_HASHES.items():
        verify_file(profile / name, digest)
