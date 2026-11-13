import base64
import hashlib
import plistlib
import struct
import subprocess
import tarfile
import urllib.request
import zipfile
import zlib
from pathlib import PurePosixPath

BUILD = "11A24580o"
ROOT_NAME = f"N51AP_{BUILD}_rootfs.dmg"
VAR_NAME = f"N51AP_{BUILD}_var.tar"
INPUTS = {
    ROOT_NAME: (
        1_334_065_040,
        "aac75b69a1bec3276b6f7ec69e69a02ed5f5f622d623e0d2a469424707cc81fb",
    ),
    VAR_NAME: (
        55_808,
        "10e84d3e5ac46aeee32824523488724e85ee2f4339e787cf711c0f4543350f6c",
    ),
}
RETAIL_IPSW = (
    "https://secure-appldnld.apple.com/iOS7/031-0290.20130914.khyTp/"
    "iPhone6,1_7.0.1_11A470a_Restore.ipsw"
)
TREE_MEMBER = "Firmware/all_flash/all_flash.n51ap.production/DeviceTree.n51ap.im4p"
TREE_CONTAINER_HASH = "8718afad1032de3a549734b4f44430155647c554bb0cd90dddc5d2e270304bb0"
TREE_HASH = "7e57e0e92cab938b491c4f8aa221a19059639d66c2875de91dd74386db9879a6"
KERNEL_HASH = "9d918f96f6f840b95ff0fadddb57ea65f85de19c262aee358d756789ac24163f"
BOOT_FILE_HASHES = {
    "kernel-development.macho": "fc14f06ea3347c45524a47212bbb87ef66b97cfe565604977519d93039dcfd7e",
    "launchd.macho": "5fe0a117f10cbd5a9249b6efab2291f424a94978bdc542b0b701e931dc396945",
    "SwitchBoard.macho": "feac56c613e37a33f5c423c5dedf16b44db6ef091f87a6bc5e13bbf2d2c8ba1a",
    "dyld_shared_cache_arm64": "1385b898f30354b39d6fc9852b3e1355515f1811340844afcb4f79a3a263b8c4",
    "kernelcache.macho": KERNEL_HASH,
}
KERNEL_KEY = (
    "071c9f908a0bb9d24b1193839ea2d864"
    "79b633ee5017bad30fd603144e2963eb398d850b1e58e7721022d5f2ab3398c8"
)
TREE_KEY = (
    "e751f67e587827078385f9062d916915"
    "c59a43d6ad9eb4389b11094d88b1255ee09e84bf99f5f0a40f59724eecbe3752"
)


def sha256(path):
    with path.open("rb") as source:
        return hashlib.file_digest(source, "sha256").hexdigest()


def verify_file(path, expected):
    if sha256(path) != expected:
        raise ValueError(f"Unexpected SHA-256 for {path.name}.")


def matches_proven(root, var):
    return sha256(root) == INPUTS[ROOT_NAME][1] and sha256(var) == INPUTS[VAR_NAME][1]


def _member_name(name):
    base = PurePosixPath(name).name
    if not base or base in {".", ".."}:
        raise ValueError(f"Invalid archive member {name}.")
    return base


def _is_tar_name(name):
    lower = name.lower()
    return lower.endswith((".tar", ".tar.gz", ".tar.bz2", ".tar.xz", ".tgz"))


def _var_parts(name):
    parts = [part for part in PurePosixPath(name).parts if part not in {".", ""}]
    if ".." in parts or PurePosixPath(name).is_absolute():
        return None
    if parts[:2] == ["private", "var"]:
        return ["var", *parts[2:]]
    if parts[:1] == ["var"]:
        return parts
    return None


def _extract_stream(source, directory, name, size):
    if size <= 0:
        raise ValueError(f"{name} is empty.")
    if size > 8 * 1024**3:
        raise ValueError(f"{name} is larger than 8 GB.")
    path = directory / _member_name(name)
    if path.exists():
        raise ValueError(f"Duplicate archive member {path.name}.")
    remaining = size
    with path.open("xb") as target:
        while remaining:
            chunk = source.read(min(remaining, 1 << 20))
            if not chunk:
                raise ValueError(f"{name} is truncated.")
            target.write(chunk)
            remaining -= len(chunk)
    return path


def _prefer(items, proven):
    def rank(item):
        name = _member_name(item["name"]).lower()
        if name == proven.lower():
            group = 0
        elif "rootfs" in name or "var" in name:
            group = 1
        else:
            group = 2
        return group, -item["size"]

    return sorted(items, key=rank)[0]


def _pack_var(records, directory, open_file):
    files = [item for item in records if _var_parts(item["name"])]
    if not files:
        return None
    path = directory / "var-experimental.tar"
    with tarfile.open(path, "w") as packed:
        for item in files:
            parts = _var_parts(item["name"])
            info = tarfile.TarInfo("/".join(parts))
            info.mode = item.get("mode", 0o755 if item["kind"] == "dir" else 0o644)
            info.uid = item.get("uid", 0)
            info.gid = item.get("gid", 0)
            info.mtime = item.get("mtime", 0)
            if item["kind"] == "dir":
                info.type = tarfile.DIRTYPE
                packed.addfile(info)
            elif item["kind"] == "symlink":
                info.type = tarfile.SYMTYPE
                info.linkname = item.get("link", "")
                packed.addfile(info)
            elif item["kind"] == "file":
                info.type = tarfile.REGTYPE
                info.size = item["size"]
                with open_file(item) as source:
                    packed.addfile(info, source)
            else:
                raise ValueError(f"Unsupported archive member {item['name']}.")
    return path


def _archive_choice(records, extract_file, open_file, directory):
    dmgs = [
        item
        for item in records
        if item["kind"] == "file"
        and _member_name(item["name"]).lower().endswith(".dmg")
    ]
    tars = [
        item
        for item in records
        if item["kind"] == "file" and _is_tar_name(_member_name(item["name"]))
    ]
    if dmgs or tars:
        root = extract_file(_prefer(dmgs, ROOT_NAME)) if dmgs else None
        var_members = [
            item for item in tars if "var" in _member_name(item["name"]).lower()
        ]
        if not var_members and len(tars) == 1:
            var_members = tars
        var = extract_file(_prefer(var_members, VAR_NAME)) if var_members else None
        if var is None:
            var = _pack_var(records, directory, open_file)
        return root, var, False
    tree = bool(records) and all(
        _var_parts(item["name"]) or item["name"] in {".", "./"} for item in records
    )
    return None, None, not tree


def copy_member(member, directory, name, size):
    expected_size, expected_hash = INPUTS[name]
    if size != expected_size:
        raise ValueError(f"{name} has an unexpected size.")
    path = directory / name
    digest = hashlib.sha256()
    remaining = size
    with path.open("xb") as target:
        while remaining:
            chunk = member.read(min(remaining, 1 << 20))
            if not chunk:
                raise ValueError(f"{name} is truncated.")
            target.write(chunk)
            digest.update(chunk)
            remaining -= len(chunk)
    if digest.hexdigest() != expected_hash:
        raise ValueError(f"{name} has an unexpected SHA-256.")
    return path


def archive_inputs(archive, directory):
    result = {}
    if zipfile.is_zipfile(archive):
        with zipfile.ZipFile(archive) as bundle:
            for item in bundle.infolist():
                name = PurePosixPath(item.filename).name
                if name not in INPUTS:
                    continue
                if (
                    name in result
                    or item.is_dir()
                    or item.external_attr >> 28 not in (0, 8)
                ):
                    raise ValueError(f"Invalid or duplicate archive member {name}.")
                with bundle.open(item) as source:
                    result[name] = copy_member(source, directory, name, item.file_size)
    else:
        with tarfile.open(archive, "r|*") as bundle:
            for item in bundle:
                name = PurePosixPath(item.name).name
                if name not in INPUTS:
                    continue
                if name in result or not item.isfile():
                    raise ValueError(f"Invalid or duplicate archive member {name}.")
                with bundle.extractfile(item) as source:
                    result[name] = copy_member(source, directory, name, item.size)
    return result


def _experimental_tar(path, directory):
    try:
        archive = tarfile.open(path, "r:*")
    except tarfile.TarError as error:
        raise ValueError(f"Experimental import could not read {path.name}.") from error
    with archive:
        records = []
        for item in archive.getmembers():
            kind = (
                "dir"
                if item.isdir()
                else "symlink"
                if item.issym()
                else "file"
                if item.isfile()
                else "other"
            )
            records.append(
                {
                    "name": item.name,
                    "kind": kind,
                    "size": item.size,
                    "mode": item.mode,
                    "uid": item.uid,
                    "gid": item.gid,
                    "mtime": item.mtime,
                    "link": item.linkname,
                    "member": item,
                }
            )

        def extract_file(item):
            source = archive.extractfile(item["member"])
            if source is None:
                raise ValueError(f"Could not read {item['name']}.")
            with source:
                return _extract_stream(source, directory, item["name"], item["size"])

        def open_file(item):
            source = archive.extractfile(item["member"])
            if source is None:
                raise ValueError(f"Could not read {item['name']}.")
            return source

        root, var, rejected = _archive_choice(
            records, extract_file, open_file, directory
        )
    if rejected:
        raise ValueError(
            f"Experimental import tried {path.name} as a root image. It is not a DMG and it does not contain one. Only 11A24580o is set up to boot."
        )
    if root is None and var is None:
        return None, path
    return root, var


def _experimental_zip(path, directory):
    with zipfile.ZipFile(path) as archive:
        records = []
        for item in archive.infolist():
            name = PurePosixPath(item.filename)
            if name.is_absolute() or ".." in name.parts:
                raise ValueError(f"Invalid archive member {item.filename}.")
            records.append(
                {
                    "name": item.filename,
                    "kind": "dir" if item.is_dir() else "file",
                    "size": item.file_size,
                    "member": item,
                }
            )

        def extract_file(item):
            with archive.open(item["member"]) as source:
                return _extract_stream(source, directory, item["name"], item["size"])

        def open_file(item):
            return archive.open(item["member"])

        root, var, rejected = _archive_choice(
            records, extract_file, open_file, directory
        )
        if rejected:
            raise ValueError(
                f"Experimental import tried {path.name} as a root image. It is not a DMG and it does not contain one. Only 11A24580o is set up to boot."
            )
        if root is None and var is None:
            packed = _pack_var(records, directory, open_file)
            if packed is None:
                raise ValueError(
                    f"Experimental import tried {path.name} and did not find a var tar inside it."
                )
            return None, packed
        return root, var


def select_experimental(paths, directory):
    root = None
    var = None
    ipsw = None

    def assign_root(path):
        nonlocal root
        if root is not None:
            raise ValueError("Experimental import found more than one root DMG.")
        if path.stat().st_size <= 0:
            raise ValueError(f"{path.name} is empty.")
        if path.stat().st_size > 8 * 1024**3:
            raise ValueError(f"{path.name} is larger than 8 GB.")
        root = path

    def assign_var(path):
        nonlocal var
        if var is not None:
            raise ValueError("Experimental import found more than one var tar.")
        if path.stat().st_size <= 0:
            raise ValueError(f"{path.name} is empty.")
        var = path

    for path in paths:
        if not path.is_file():
            raise ValueError(f"Choose a file instead of {path.name}.")
        suffix = path.suffix.lower()
        if suffix == ".ipsw":
            if ipsw is not None:
                raise ValueError("Choose one retail IPSW.")
            ipsw = path
            continue
        if suffix == ".dmg":
            assign_root(path)
            continue
        if zipfile.is_zipfile(path):
            found_root, found_var = _experimental_zip(path, directory)
        elif _is_tar_name(path.name):
            found_root, found_var = _experimental_tar(path, directory)
        else:
            raise ValueError(
                f"Experimental import cannot use {path.name}. Choose a DMG or a tar."
            )
        if found_root is not None:
            assign_root(found_root)
        if found_var is not None:
            assign_var(found_var)
    if root is None:
        raise ValueError(
            "Experimental import did not find a root DMG. 11A24580o boots from a root DMG and a var tar."
        )
    if var is None:
        raise ValueError(
            "Experimental import did not find a var tar. 11A24580o boots from a root DMG and a var tar."
        )
    return root, var, ipsw


def select_inputs(paths, directory, experimental=False):
    if experimental:
        return select_experimental(paths, directory)
    found = {}
    ipsw = None
    for path in paths:
        if not path.is_file():
            raise ValueError(f"Choose a file instead of {path.name}.")
        if path.suffix.lower() == ".ipsw":
            if ipsw is not None:
                raise ValueError("Choose one retail IPSW.")
            ipsw = path
            continue
        name = path.name
        size = path.stat().st_size
        if path.suffix.lower() == ".dmg":
            name = ROOT_NAME
        elif path.suffix.lower() == ".tar" and size == INPUTS[VAR_NAME][0]:
            name = VAR_NAME
        if name in INPUTS:
            expected_size, expected = INPUTS[name]
            if size != expected_size:
                raise ValueError(f"{path.name} has an unexpected size for {name}.")
            verify_file(path, expected)
            candidates = {name: path}
        else:
            candidates = archive_inputs(path, directory)
        for name, candidate in candidates.items():
            if name in found:
                raise ValueError(f"Choose one copy of {name}.")
            found[name] = candidate
    missing = INPUTS.keys() - found.keys()
    if missing:
        raise ValueError("Missing " + " and ".join(sorted(missing)) + ".")
    return found[ROOT_NAME], found[VAR_NAME], ipsw


def var_seed(path, experimental=False):
    result = {}
    with tarfile.open(path) as archive:
        for member in archive:
            name = PurePosixPath(member.name)
            if name == PurePosixPath("."):
                continue
            if experimental:
                parts = _var_parts(member.name)
                if not parts:
                    raise ValueError(
                        "Experimental import tried this tar as the var seed, but its paths are not under var/. The proven file is "
                        + VAR_NAME
                        + "."
                    )
                name = PurePosixPath(*parts)
            elif name.is_absolute() or ".." in name.parts or name.parts[0] != "var":
                raise ValueError("Unexpected path in the var archive.")
            if member.isdir():
                kind = "directory"
                data = b""
            elif member.issym():
                kind = "symlink"
                data = b""
            elif member.isfile():
                kind = "file"
                with archive.extractfile(member) as source:
                    data = source.read()
            else:
                raise ValueError(f"Unsupported var archive member {name}.")
            if str(name) in result:
                raise ValueError(f"Duplicate var archive member {name}.")
            result[str(name)] = {
                "path": str(name),
                "kind": kind,
                "link": member.linkname,
                "uid": member.uid,
                "gid": member.gid,
                "mode": member.mode,
                "data": base64.b64encode(data).decode("ascii"),
            }
    preferences = plistlib.dumps({"mediaengine": "fig", "rpc_timeout": 120})
    for user, owner in (("root", 0), ("mobile", 501)):
        name = f"var/{user}/Library/Preferences/com.apple.coremedia.plist"
        result[name] = {
            "path": name,
            "kind": "file",
            "link": "",
            "uid": owner,
            "gid": owner,
            "mode": 0o644,
            "data": base64.b64encode(preferences).decode("ascii"),
        }
    return list(result.values())


def der_node(data, position):
    tag = data[position]
    position += 1
    if tag & 31 == 31:
        while data[position] & 128:
            position += 1
        position += 1
    length = data[position]
    position += 1
    if length & 128:
        octets = length & 127
        if not 0 < octets <= 4:
            raise ValueError("Invalid Image4 length.")
        length = int.from_bytes(data[position : position + octets], "big")
        position += octets
    end = position + length
    if end > len(data):
        raise ValueError("Truncated Image4 node.")
    children = []
    if tag & 0x20:
        cursor = position
        while cursor < end:
            child, cursor = der_node(data, cursor)
            children.append(child)
        if cursor != end:
            raise ValueError("Invalid Image4 container.")
    return (tag, data[position:end], children), end


def image4_payload(data, kind):
    root, _ = der_node(data, 0)
    nodes = [root]
    while nodes:
        _, _, children = nodes.pop()
        if len(children) >= 4 and children[0][1] == b"IM4P" and children[1][1] == kind:
            tag, payload, _ = children[3]
            if tag == 4:
                return payload
        nodes.extend(children)
    raise ValueError(f"Missing {kind.decode()} Image4 payload.")


def decrypt(data, kind, key):
    return subprocess.run(
        [
            "/usr/bin/openssl",
            "enc",
            "-d",
            "-aes-256-cbc",
            "-nopad",
            "-iv",
            key[:32],
            "-K",
            key[32:],
        ],
        input=image4_payload(data, kind),
        capture_output=True,
        check=True,
    ).stdout


def decompress_kernel(compressed, expected_size):
    window = bytearray(b" " * 4096)
    write_at = 4096 - 18
    position = flags = 0
    result = bytearray()
    while len(result) < expected_size:
        flags >>= 1
        if flags & 0x100 == 0:
            flags = compressed[position] | 0xFF00
            position += 1
        if flags & 1:
            token = compressed[position : position + 1]
            position += 1
            if not token:
                raise ValueError("Truncated kernel literal.")
            result.extend(token)
            window[write_at] = token[0]
            write_at = (write_at + 1) & 4095
        else:
            low, high = compressed[position : position + 2]
            position += 2
            read_at = low | ((high & 0xF0) << 4)
            for index in range((high & 15) + 3):
                value = window[(read_at + index) & 4095]
                result.append(value)
                window[write_at] = value
                write_at = (write_at + 1) & 4095
    if len(result) != expected_size:
        raise ValueError("Unexpected decompressed kernel length.")
    return bytes(result)


def kernelcache(container, experimental=False):
    try:
        compressed = decrypt(container, b"krnl", KERNEL_KEY)
    except subprocess.CalledProcessError as error:
        if not experimental:
            raise
        raise ValueError(
            "Experimental import failed: the kernel did not decrypt with the 11A24580o key. Only 11A24580o is set up to boot."
        ) from error
    failure = "Experimental import failed: kernelcache does not match 11A24580o. Only 11A24580o is set up to boot."
    try:
        if not compressed.startswith(b"complzss"):
            raise ValueError("Unexpected kernel compression.")
        checksum, size, packed = struct.unpack_from(">III", compressed, 8)
        kernel = decompress_kernel(compressed[0x180 : 0x180 + packed], size)
    except (ValueError, IndexError, struct.error) as error:
        if not experimental:
            raise
        raise ValueError(failure) from error
    if (
        zlib.adler32(kernel) != checksum
        or hashlib.sha256(kernel).hexdigest() != KERNEL_HASH
    ):
        if experimental:
            raise ValueError(failure)
        raise ValueError("Kernelcache verification failed.")
    return kernel


def retail_tree(ipsw, experimental=False):
    if ipsw:
        with zipfile.ZipFile(ipsw) as archive:
            try:
                info = archive.getinfo(TREE_MEMBER)
            except KeyError as error:
                if not experimental:
                    raise
                raise ValueError(
                    "Experimental import failed: the DeviceTree does not match the N51 tree for 11A24580o. Only 11A24580o is set up to boot."
                ) from error
            if info.file_size != 142_203:
                if experimental:
                    raise ValueError(
                        "Experimental import failed: the DeviceTree does not match the N51 tree for 11A24580o. Only 11A24580o is set up to boot."
                    )
                raise ValueError("Unexpected N51 DeviceTree size.")
            container = archive.read(info)
    else:
        start, length, total = 1_433_282_631, 142_248, 1_489_997_303
        end = start + length - 1
        span = f"bytes={start}-{end}"
        request = urllib.request.Request(RETAIL_IPSW, headers={"Range": span})
        with urllib.request.urlopen(request, timeout=30) as response:
            if (
                response.status != 206
                or response.headers.get("Content-Range")
                != f"bytes {start}-{end}/{total}"
            ):
                raise OSError(
                    "Apple did not return the DeviceTree range. Supply the 11A470a IPSW."
                )
            compressed = response.read(length + 1)
        if len(compressed) != length:
            raise ValueError("The DeviceTree download was truncated.")
        container = zlib.decompress(compressed, -15)
    if hashlib.sha256(container).hexdigest() != TREE_CONTAINER_HASH:
        if experimental:
            raise ValueError(
                "Experimental import failed: the DeviceTree does not match the N51 tree for 11A24580o. Only 11A24580o is set up to boot."
            )
        raise ValueError("The N51 DeviceTree does not match build 11A470a.")
    try:
        tree = decrypt(container, b"dtre", TREE_KEY)
    except subprocess.CalledProcessError as error:
        if not experimental:
            raise
        raise ValueError(
            "Experimental import failed: the DeviceTree did not decrypt with the 11A24580o key. Only 11A24580o is set up to boot."
        ) from error
    if hashlib.sha256(tree).hexdigest() != TREE_HASH:
        if experimental:
            raise ValueError(
                "Experimental import failed: the DeviceTree does not match the N51 tree for 11A24580o. Only 11A24580o is set up to boot."
            )
        raise ValueError("DeviceTree verification failed.")
    return tree


def decode_tree(data):
    def node(position):
        properties, children = struct.unpack_from("<II", data, position)
        position += 8
        values = {}
        descendants = []
        for _ in range(properties):
            name, length = struct.unpack_from("<32sI", data, position)
            position += 36
            values[name.split(b"\0", 1)[0].decode()] = data[
                position : position + length
            ].hex()
            position += (length + 3) & ~3
        for _ in range(children):
            child, position = node(position)
            descendants.append(child)
        return {"props": values, "children": descendants}, position

    tree, consumed = node(0)
    if any(data[consumed:]):
        raise ValueError("Unexpected data after the DeviceTree.")
    return tree
