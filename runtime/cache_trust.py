import hashlib
import struct
import uuid

CACHE_SHA256 = "1385b898f30354b39d6fc9852b3e1355515f1811340844afcb4f79a3a263b8c4"
CDHASH = "1cef888473fcd5021a28344df18a8520fb8a1a64"
CACHE_BYTES = 0x109DECA2


def audit_cache(path):
    cache = memoryview(path.read_bytes())
    if len(cache) != CACHE_BYTES or hashlib.sha256(cache).hexdigest() != CACHE_SHA256:
        raise ValueError("Cache extent/hash mismatch")
    (signature,) = struct.unpack_from("<Q", cache, 40)
    magic, length, count = struct.unpack_from(">III", cache, signature)
    assert magic == 0xFADE0CC0 and signature + length == CACHE_BYTES
    directories = []
    for index in range(count):
        kind, offset = struct.unpack_from(">II", cache, signature + 12 + index * 8)
        if kind == 0:
            directories.append(signature + offset)
    assert len(directories) == 1
    cd = directories[0]
    magic, size, version, flags, hashes, ident, special, slots, limit = (
        struct.unpack_from(">9I", cache, cd)
    )
    assert magic == 0xFADE0C02 and version == 0x20100
    assert struct.unpack_from("4B", cache, cd + 36) == (20, 1, 0, 12)
    assert hashlib.sha1(cache[cd : cd + size]).hexdigest() == CDHASH
    (scatter,) = struct.unpack_from(">I", cache, cd + 44)
    position = cd + scatter
    checked = 0
    previous_end = 0
    while True:
        assert cd <= position and position + 24 <= cd + size
        pages, first, target, reserved = struct.unpack_from(">IIQQ", cache, position)
        position += 24
        if not pages:
            break
        assert first >= previous_end and first + pages <= slots
        previous_end = first + pages
        for page in range(first, first + pages):
            start = page * 4096
            assert start < limit
            actual = hashlib.sha1(cache[start : min(start + 4096, limit)]).digest()
            expected = bytes(
                cache[cd + hashes + checked * 20 : cd + hashes + (checked + 1) * 20]
            )
            if actual != expected:
                raise ValueError(f"Signed cache page {page:#x} changed")
            checked += 1
    assert checked == 59712
    return {
        "cache_sha256": CACHE_SHA256,
        "cdhash": CDHASH,
        "signed_pages_verified": checked,
        "failed_pages": 0,
    }


def loaded_trust_node():
    identity = uuid.uuid5(uuid.NAMESPACE_URL, "nonui-11A24580o:" + CDHASH).bytes
    return struct.pack("<Q16sI", 0, identity, 1) + bytes.fromhex(CDHASH)


def embedded_cache_trust(kernel):
    if (
        hashlib.sha256(kernel).hexdigest()
        != "9d918f96f6f840b95ff0fadddb57ea65f85de19c262aee358d756789ac24163f"
    ):
        raise ValueError("Uninspected AMFI build")
    amfi = memoryview(kernel)[0x802000:0x82B000]
    digest = bytes.fromhex(CDHASH)
    count, first = struct.unpack_from("<HH", amfi, 0x723C + digest[0] * 4)
    return any(
        (
            bytes(amfi[0x763C + i * 19 : 0x763C + (i + 1) * 19]) == digest[1:]
            for i in range(first, first + count)
        )
    )
