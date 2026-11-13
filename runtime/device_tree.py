import struct


def device_tree(tree, ram_base, ram_size, disk_base, disk_size):
    PA, RAM_SIZE, RAMDISK_PA, root_size = (ram_base, ram_size, disk_base, disk_size)
    MMIO_REGISTER_WINDOWS = []

    def named(node):
        return bytes.fromhex(node["props"]["name"]).rstrip(b"\x00").decode()

    assert bytes.fromhex(tree["props"]["secure-root-prefix"]) == b"md\x00"
    del tree["props"]["secure-root-prefix"]
    defaults = next((n for n in tree["children"] if named(n) == "defaults"))
    defaults["props"]["no-effaceable-storage"] = struct.pack("<I", 1).hex()
    allowed_root_nodes = (
        "chosen",
        "options",
        "cpus",
        "memory",
        "pram",
        "nvram",
        "stram",
        "arm-io",
        "defaults",
        "buttons",
        "product",
    )
    original_sacm = next((n for n in tree["children"] if named(n) == "sacm"))
    assert bytes.fromhex(original_sacm["props"]["AAPL,phandle"]) == bytes.fromhex(
        "0000007b"
    )
    allowed_root_nodes += ("sacm",)
    buttons = next((n for n in tree["children"] if named(n) == "buttons"))
    assert buttons["props"]["AAPL,phandle"] == "00000076"
    for key in ("function-wake_button_hold", "function-wake_button_menu"):
        buttons["props"].pop(key)
    tree["children"] = [n for n in tree["children"] if named(n) in allowed_root_nodes]
    armio = next((n for n in tree["children"] if named(n) == "arm-io"))
    frequencies = bytearray.fromhex(armio["props"]["clock-frequencies"])
    assert len(frequencies) >= (25 + 1) * 4
    assert struct.unpack_from("<I", frequencies, 25 * 4)[0] == 0
    struct.pack_into("<I", frequencies, 25 * 4, 24000000)
    armio["props"]["clock-frequencies"] = frequencies.hex()
    allowed_nodes = (
        "aic",
        "aic-timebase",
        "disp0",
        "disp1",
        "mipi-dsim",
        "sgx",
        "pmgr",
    )
    i2c0 = next((n for n in armio["children"] if named(n) == "i2c0"))
    chestnut = next((n for n in i2c0["children"] if named(n) == "display-pmu"))
    assert chestnut["props"]["AAPL,phandle"] == "0000004b"
    i2c0["children"] = [chestnut]
    gpio = next((n for n in armio["children"] if named(n) == "gpio"))
    assert gpio["props"]["AAPL,phandle"] == "0000001a"
    allowed_nodes += ("gpio", "i2c0")
    mipi = next((n for n in armio["children"] if named(n) == "mipi-dsim"))
    lcd = next((n for n in mipi["children"] if named(n) == "lcd"))
    assert lcd["props"]["lcd-panel-id"] == "00000000"
    lcd["props"]["lcd-panel-id"] = struct.pack("<I", 0xA1970FCE).hex()
    disp0 = next((n for n in armio["children"] if named(n) == "disp0"))
    assert "display-timing-info" not in disp0["props"]
    virtual_timing = (640, 16, 4, 16, 1136, 8, 2, 8)
    disp0["props"]["display-timing-info"] = struct.pack("<8I", *virtual_timing).hex()
    disp0["props"]["dot-pitch"] = struct.pack("<I", 326).hex()
    armio["children"] = [n for n in armio["children"] if named(n) in allowed_nodes]
    pmgr_node = next((n for n in armio["children"] if named(n) == "pmgr"))
    pmgr_node["props"]["cpu-max-core-count"] = struct.pack("<I", 1).hex()
    pmgr_node["props"]["#performance-domains"] = struct.pack("<I", 1).hex()
    pmgr_node["props"]["performance-domain-features"] = pmgr_node["props"][
        "performance-domain-features"
    ][:8]
    pmgr_node["children"] = [
        x for x in pmgr_node["children"] if named(x) != "pmc-perf-controller"
    ]
    pmgr_node["children"] = [
        x
        for x in pmgr_node["children"]
        if (
            not named(x).endswith("-perf-controller")
            or named(x) == "fb-perf-controller"
        )
        and named(x) != "test-perf0"
    ]
    framebuffer_perf = next(
        (x for x in pmgr_node["children"] if named(x) == "fb-perf-controller")
    )
    assert (
        struct.unpack("<I", bytes.fromhex(framebuffer_perf["props"]["AAPL,phandle"]))[0]
        == 0x12000000
    )
    disp0_for_fb = next((x for x in armio["children"] if named(x) == "disp0"))
    assert bytes.fromhex(disp0_for_fb["props"]["function-frame_swap"]) == bytes.fromhex(
        "0000001250575346"
    )
    windows = []
    for io_device in armio["children"]:
        backed_nodes = ("pmgr", "sgx", "disp0", "disp1", "mipi-dsim")
        backed_nodes += ("gpio", "i2c0")
        if named(io_device) not in backed_nodes:
            continue
        pairs = bytes.fromhex(io_device["props"]["reg"])
        assert len(pairs) % 16 == 0
        for off, size in struct.iter_unpack("<QQ", pairs):
            assert off % 0x1000 == size % 0x1000 == 0 and 0 < size <= 0x200000
            windows.append((0x200000000 + off, 0x200000000 + off + size))
    for begin, end in sorted(windows):
        if MMIO_REGISTER_WINDOWS and begin < MMIO_REGISTER_WINDOWS[-1][1]:
            lo, prior_end = MMIO_REGISTER_WINDOWS[-1]
            MMIO_REGISTER_WINDOWS[-1] = (lo, max(prior_end, end))
        else:
            MMIO_REGISTER_WINDOWS.append((begin, end))
    assert 1 <= len(MMIO_REGISTER_WINDOWS) <= 48
    aic = next((n for n in armio["children"] if named(n) == "aic"))
    aic["props"]["#main-cpus"] = "00000000"
    chosen = next((n for n in tree["children"] if named(n) == "chosen"))
    chosen["props"]["debug-enabled"] = struct.pack("<I", 1).hex()
    chosen["props"]["display-scale"] = struct.pack("<I", 2).hex()
    nvram = bytearray(0x2000)
    struct.pack_into("<BBH", nvram, 0, 112, 0, len(nvram) // 16)
    nvram[4:16] = b"common".ljust(12, b"\x00")
    checksum = sum(nvram[:16])
    nvram[1] = (checksum & 255) + (checksum >> 8)
    variables = b"auto-boot?=true\x00\x00"
    nvram[16 : 16 + len(variables)] = variables
    chosen["props"]["nvram-proxy-data"] = nvram.hex()
    memory = next((n for n in tree["children"] if named(n) == "memory"))
    memory["props"]["reg"] = struct.pack("<QQ", PA, RAM_SIZE).hex()
    pram = next((n for n in tree["children"] if named(n) == "pram"))
    pram["props"]["reg"] = struct.pack("<QQ", PA + 0x2800000, 0x10000).hex()
    cpus = next((n for n in tree["children"] if named(n) == "cpus"))
    cpus["children"] = [n for n in cpus["children"] if named(n) == "cpu0"]
    cpus["children"][0]["props"]["timebase-frequency"] = struct.pack(
        "<Q", 62500000
    ).hex()
    cpus["children"][0]["props"]["clock-frequency"] = struct.pack(
        "<Q", 1300000000
    ).hex()

    def encode(node):
        result = bytearray(
            struct.pack("<II", len(node["props"]), len(node["children"]))
        )
        for name, value in node["props"].items():
            value = bytes.fromhex(value)
            result += name.encode().ljust(32, b"\x00") + struct.pack("<I", len(value))
            result += value + b"\x00" * (-len(value) & 3)
        for child in node["children"]:
            result += encode(child)
        return result

    memory_map = next(n for n in chosen["children"] if named(n) == "memory-map")
    memory_map["props"]["RAMDisk"] = struct.pack("<QQ", RAMDISK_PA, root_size).hex()
    return encode(tree), MMIO_REGISTER_WINDOWS
