import struct
import xml.etree.ElementTree as ET


def register_numbers(fetch_xml, preserve_first=False):
    result = {}
    next_number = 0

    def visit(name):
        nonlocal next_number
        xml = fetch_xml(name).replace("xi:include", "include")
        for item in ET.fromstring(xml):
            if item.tag.endswith("include"):
                visit(item.attrib["href"])
            elif item.tag == "reg":
                next_number = int(item.attrib.get("regnum", next_number))
                key = item.attrib["name"].upper()
                if not preserve_first or key not in result:
                    result[key] = (next_number, int(item.attrib["bitsize"]))
                next_number += 1

    visit("target.xml")
    return result


def save_guest_call_state(packet, primary_registers, general):
    assert len(general) == 268, "Unexpected ARM64 general register packet"
    extra = {}
    for name in [f"V{i}" for i in range(32)] + ["FPSR", "FPCR"]:
        number, bits = primary_registers[name]
        assert bits == (128 if name.startswith("V") else 32)
        value = packet(f"p{number:x}")
        assert len(bytes.fromhex(value)) == bits // 8, name
        extra[name] = {"number": number, "value": value}
    return {"general": bytes(general).hex(), "extra": extra}


def restore_guest_call_state(packet, state):
    for item in state["extra"].values():
        assert packet(f"P{item['number']:x}={item['value']}") == "OK"
    assert packet("G" + state["general"]) == "OK"
    assert packet("g") == state["general"]
    for name, item in state["extra"].items():
        assert packet(f"p{item['number']:x}") == item["value"], name


def walk_4k(read_physical, ttbr, address, address_bits=39):
    if not 25 <= address_bits <= 48:
        raise ValueError("Unsupported input address size")
    table = ttbr & 0xFFFFFFFFF000
    start_level = max(0, 3 - (address_bits - 13) // 9)
    trace = []
    for level in range(start_level, 4):
        shift = 12 + (3 - level) * 9
        slot = table + (address >> shift & 511) * 8
        (descriptor,) = struct.unpack("<Q", read_physical(slot, 8))
        trace.append({"level": level, "slot": hex(slot), "descriptor": hex(descriptor)})
        kind = descriptor & 3
        if kind == 0 or kind == 2 or (level == 3 and kind != 3):
            return {"valid": False, "trace": trace}
        if kind == 1 or level == 3:
            mask = (1 << shift) - 1
            physical = descriptor & 0xFFFFFFFFF000 & ~mask | address & mask
            return {
                "valid": True,
                "physical": hex(physical),
                "trace": trace,
                "access_flag": bool(descriptor & 1 << 10),
                "ap": descriptor >> 6 & 3,
            }
        table = descriptor & 0xFFFFFFFFF000
    raise AssertionError("Unreachable translation level")


def unix_syscall(saved):
    (raw,) = struct.unpack_from("<Q", saved, 136)
    arguments = list(struct.unpack_from("<8Q", saved, 8))
    return (
        raw,
        arguments[0] if raw == 0 else raw,
        arguments[1:] if raw == 0 else arguments,
    )
