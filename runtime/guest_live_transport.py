import json
import math
import struct
import time
import zlib
from arm64_vm import save_guest_call_state, restore_guest_call_state


class LiveDisplayClosed(RuntimeError):
    pass


def rgba_png(pixels, width, height, stride):
    assert 0 < width <= 2048 and 0 < height <= 4096
    assert stride >= width * 4 and len(pixels) == height * stride

    def chunk(kind, body):
        return (
            struct.pack(">I", len(body))
            + kind
            + body
            + struct.pack(">I", zlib.crc32(kind + body))
        )

    scanlines = b"".join(
        (b"\x00" + pixels[y * stride : y * stride + width * 4] for y in range(height))
    )
    return (
        b"\x89PNG\r\n\x1a\n"
        + chunk(b"IHDR", struct.pack(">2I5B", width, height, 8, 6, 0, 0, 0))
        + chunk(b"IDAT", zlib.compress(scanlines, 1))
        + chunk(b"IEND", b"")
    )


def touch_record(event, timestamp):
    assert event["phase"] in (1, 2, 6)
    if event["type"] == "button":
        assert event["phase"] in (1, 6)
        hold = float(event.get("holdSeconds", 0))
        assert math.isfinite(hold) and 0 <= hold <= 3
        codes = {
            "home": (1001, 1000),
            "sleep": (1010, 1011),
            "volume_up": (1006, 1007),
            "volume_down": (1008, 1009),
        }
        assert event["button"] in codes
        data = bytearray(128)
        struct.pack_into("<I", data, 0, codes[event["button"]][event["phase"] == 6])
        struct.pack_into("<Q", data, 48, timestamp)
        return bytes(data)
    assert event["type"] == "pointer"
    assert event["width"] == 640 and event["height"] == 1136
    x, y = (float(event["x"]), float(event["y"]))
    assert math.isfinite(x) and math.isfinite(y) and (0 <= x < 640) and (0 <= y < 1136)
    data = bytearray(128)
    struct.pack_into("<I", data, 0, 3001)
    struct.pack_into("<dd", data, 24, x, y)
    struct.pack_into("<Q", data, 48, timestamp)
    struct.pack_into("<I", data, 72, 40)
    struct.pack_into("<IHH", data, 88, event["phase"], 1, 1)
    return bytes(data)


class LiveGuestBridge:
    symbols = {
        "calloc": 0x18AC145C0,
        "string": 0x18134ABC0,
        "capture": 0x18759AA34,
        "timestamp": 0x1858C6210,
        "touch": 0x1858C7AB0,
        "runloop": 0x18134A090,
        "now": 0x181349874,
        "timer": 0x18135D038,
        "add_timer": 0x18135D460,
        "bitmap": 0x18759A948,
        "translate": 0x1814D730C,
        "scale": 0x1814D73F8,
        "clear": 0x1814D1984,
        "render": 0x18A4FB9C0,
        "flush": 0x1815366C0,
        "button_time": 0x181349874,
    }

    def __init__(
        self,
        *,
        packet,
        regs,
        write_regs,
        breakpoint,
        read_user,
        write_user,
        register_map,
        system_map,
        cache,
        milestones,
        report,
        run,
        ipc,
        slide,
        thread,
        app,
        on_frame=None,
        process=None,
        fast_frames=False,
        scanout_active=None,
    ):
        self.packet, self.regs, self.write_regs = (packet, regs, write_regs)
        self.breakpoint, self.read_user, self.write_user = (
            breakpoint,
            read_user,
            write_user,
        )
        self.register_map, self.system_map = (register_map, system_map)
        self.cache, self.milestones, self.report, self.run = (
            cache,
            milestones,
            report,
            run,
        )
        self.slide, self.thread, self.app = (slide, int(thread, 16), app)
        self.safe_point = 0x18ABCDCB8 + slide
        self.return_point = 0x187597510 + slide
        self.safe_enabled = True
        self.active = True
        self.pending = None
        self.process = process or {}
        self.previous_apps = []
        self.next_app = None
        self.events_since_frame = 0
        self.on_frame = on_frame
        self.fast_frames = fast_frames
        self.scanout_active = scanout_active or (lambda: False)
        self.heartbeat = 1 / 60 if fast_frames else 0.05
        self.ipc = ipc
        self.runloop = self.timer = self.context = self.guest_now = None
        self.timer_added = self.translated = self.scaled = False
        self.buffer = self.path = None
        self.next_frame = 0
        self.queue = []
        self.input_offset = 0
        self.input_partial = b""
        self.pressed = False
        self.buttons_pressed = set()
        self.held_buttons = {}
        self.button_check_due = False
        self.event = None
        assert self.safe_point not in milestones
        milestones[self.safe_point] = "live guest bridge safe point"
        breakpoint(self.safe_point)
        assert self.return_point not in milestones
        milestones[self.return_point] = "live guest bridge return point"
        breakpoint(self.return_point)
        report["live_bridge"] = dict(
            diagnostic_original_guest_api_bridge=True,
            safe_point=hex(self.safe_point),
            return_point=hex(self.return_point),
            thread=thread,
            app=hex(app),
            input_file="control.jsonl",
            frame_transport="raw socket" if fast_frames else "PNG",
            guest_heartbeat_seconds=self.heartbeat,
            batched_render_calls=fast_frames,
            calls=[],
            original_input_endpoint="_GSSendSystemAppEvent",
            full_register_preservation=True,
        )

    def note(self, **record):
        record["host_monotonic"] = time.monotonic()
        with (self.run / "live-events.jsonl").open("a") as out:
            out.write(json.dumps(record) + "\n")

    resource_fields = (
        "buffer",
        "path",
        "runloop",
        "timer",
        "context",
        "guest_now",
        "timer_added",
        "translated",
        "scaled",
        "pressed",
    )

    def observe_app(self, thread, app, process):
        if int(thread, 16) == self.thread and app == self.app:
            return
        if self.pending:
            self.next_app = (thread, app, process)
            return
        if self.active:
            self.previous_apps.append(
                (
                    self.thread,
                    self.app,
                    self.process,
                    {name: getattr(self, name) for name in self.resource_fields},
                )
            )
        self.thread, self.app, self.process = (int(thread, 16), app, process)
        self.active = True
        self.set_safe_point(True)
        for name in self.resource_fields:
            setattr(
                self,
                name,
                False
                if name in ("timer_added", "translated", "scaled", "pressed")
                else None,
            )
        self.next_frame = 0
        self.events_since_frame = 0
        self.buttons_pressed = set()
        self.held_buttons = {}
        self.button_check_due = False
        self.note(
            foreground_skank_app=dict(thread=thread, app=hex(app), process=process)
        )
        self.report["live_bridge"]["foreground"] = process

    def apply_next_app(self):
        if self.next_app:
            candidate, self.next_app = (self.next_app, None)
            self.observe_app(*candidate)

    def process_exited(self, process):
        if self.process.get("pid") is not None:
            if self.process["pid"] != process.get("pid"):
                return
        elif process.get("thread") != hex(self.thread):
            return
        self.pending = None
        self.buttons_pressed.clear()
        self.held_buttons.clear()
        self.button_check_due = False
        self.queue.clear()
        if self.previous_apps:
            self.thread, self.app, self.process, resources = self.previous_apps.pop()
            for name, value in resources.items():
                setattr(self, name, value)
            self.next_frame = 0
            self.pressed = False
            self.note(foreground_restored_after_guest_exit=self.process)
        else:
            self.active = False
            self.set_safe_point(False)
            self.note(foreground_source_exited=process)
            status = self.ipc / "live-status.json.tmp"
            status.write_text(
                json.dumps(
                    dict(state="launching", reason="Waiting for original guest app")
                )
            )
            status.replace(self.ipc / "live-status.json")
            self.apply_next_app()

    def poll_input(self):
        file = self.ipc / "control.jsonl"
        if not file.exists():
            return
        with file.open("rb") as source:
            source.seek(self.input_offset)
            data = source.read(65536)
            self.input_offset += len(data)
        lines = (self.input_partial + data).split(b"\n")
        self.input_partial = lines.pop()
        assert len(self.input_partial) < 65536, "Oversize input record"
        for line in lines:
            try:
                event = json.loads(line)
                assert isinstance(event, dict)
                if event.get("type") == "shutdown":
                    raise LiveDisplayClosed("Native display closed")
                touch_record(event, 1)
                if (
                    event["type"] == "pointer"
                    and event["phase"] == 2
                    and self.queue
                    and (self.queue[-1]["phase"] == 2)
                ):
                    self.queue[-1] = event
                else:
                    assert len(self.queue) < 256, "Input backlog exceeded bound"
                    self.queue.append(event)
            except (ValueError, KeyError, TypeError, AssertionError) as error:
                self.note(input_rejected=str(error))

    def invoke(self, current, operation, arguments=(), doubles=(), saved=None):
        state = (
            saved
            if saved is not None
            else save_guest_call_state(self.packet, self.register_map, current)
        )
        target = self.symbols[operation]
        try:
            assert self.read_user(target + self.slide, 12) == self.cache.read(
                target, 12
            )
        except ValueError as error:
            self.note(original_api_not_yet_resident=operation, detail=str(error))
        self.pending = dict(
            operation=operation,
            state=state,
            sp=struct.unpack_from("<Q", current, 31 * 8)[0],
            began=time.monotonic(),
        )
        self.set_safe_point(False)
        modified = bytearray(current)
        for i, value in enumerate(arguments):
            struct.pack_into("<Q", modified, i * 8, value)
        struct.pack_into("<Q", modified, 30 * 8, self.return_point)
        struct.pack_into("<Q", modified, 32 * 8, target + self.slide)
        self.write_regs(modified)
        if saved is not None:
            for name in ("FPSR", "FPCR"):
                item = saved["extra"][name]
                assert self.packet(f"P{item['number']:x}={item['value']}") == "OK"
        for i, value in enumerate(doubles):
            number, bits = self.register_map[f"V{i}"]
            assert bits == 128
            assert (
                self.packet(
                    f"P{number:x}=" + (struct.pack("<d", value) + bytes(8)).hex()
                )
                == "OK"
            )
        self.note(call_started=operation, target=hex(target + self.slide))

    def set_safe_point(self, enabled):
        if self.safe_enabled != enabled:
            self.breakpoint(self.safe_point, enabled)
            self.safe_enabled = enabled

    def step_original(self, address=None):
        address = self.safe_point if address is None else address
        if address == self.return_point:
            self.breakpoint(self.return_point, False)
            self.packet("s")
            self.breakpoint(self.return_point)
            return
        self.set_safe_point(False)
        self.packet("s")
        self.set_safe_point(self.active)

    def handle(self, current):
        number, _ = self.system_map["TPIDR_EL1"]
        thread = int.from_bytes(bytes.fromhex(self.packet(f"p{number:x}")), "little")
        address = struct.unpack_from("<Q", current, 32 * 8)[0]
        sp = struct.unpack_from("<Q", current, 31 * 8)[0]
        if thread != self.thread or (self.pending and sp != self.pending["sp"]):
            self.step_original(address)
            return
        if address == self.return_point and (not self.pending):
            self.step_original(address)
            return
        if self.pending:
            job = self.pending
            returned = struct.unpack_from("<Q", current)[0]
            returned_float = None
            if job["operation"] in ("now", "button_time"):
                number, _ = self.register_map["V0"]
                (returned_float,) = struct.unpack(
                    "<d", bytes.fromhex(self.packet(f"p{number:x}"))[:8]
                )
            chained = self.fast_frames and job["operation"] in ("clear", "render")
            if not chained:
                restore_guest_call_state(self.packet, job["state"])
            self.pending = None
            record = dict(
                operation=job["operation"],
                returned=hex(returned),
                seconds=time.monotonic() - job["began"],
            )
            if "profile" in job:
                profile = job["profile"]
                profile["debugger_handling_seconds"] = max(
                    0,
                    record["seconds"]
                    - profile["continue_wait_seconds"]
                    - profile["single_step_wait_seconds"],
                )
                record["profile"] = profile
            record[
                "original_state_still_saved" if chained else "all_registers_restored"
            ] = True
            self.report["live_bridge"]["calls"].append(record)
            self.note(call_returned=record)
            current = bytearray.fromhex(job["state"]["general"])
            if job["operation"] == "calloc":
                assert returned != 0
                self.buffer = returned
            elif job["operation"] == "runloop":
                assert returned != 0
                self.runloop = returned
            elif job["operation"] == "now":
                assert math.isfinite(returned_float)
                self.guest_now = returned_float
            elif job["operation"] == "button_time":
                assert math.isfinite(returned_float)
                for key, held in list(self.held_buttons.items()):
                    if held["deadline"] is None:
                        held["deadline"] = returned_float + held["duration"]
                    elif returned_float >= held["deadline"]:
                        self.queue.insert(0, dict(type="button", button=key, phase=6))
                        del self.held_buttons[key]
                self.button_check_due = False
            elif job["operation"] == "timer":
                assert returned != 0
                self.timer = returned
            elif job["operation"] == "add_timer":
                self.timer_added = True
            elif job["operation"] == "bitmap":
                assert returned != 0
                self.context = returned
            elif job["operation"] == "translate":
                self.translated = True
            elif job["operation"] == "scale":
                self.scaled = True
            elif job["operation"] == "timestamp":
                record_bytes = touch_record(self.event, returned)
                self.write_user(self.buffer + 128, record_bytes)
                self.invoke(current, "touch", (self.buffer + 128,))
                return
            elif job["operation"] == "touch":
                self.note(input_delivered=self.event)
                self.report["live_save_input_frame"] = True
                self.report["live_last_input_host"] = time.monotonic()
                self.events_since_frame += 1
                if (
                    self.event["type"] == "button"
                    and self.event["phase"] == 1
                    and self.event.get("holdSeconds", 0)
                ):
                    self.held_buttons[self.event["button"]] = dict(
                        deadline=None, duration=float(self.event["holdSeconds"])
                    )
                    self.button_check_due = True
                self.event = None
                self.next_frame = 0
                self.step_original()
                self.apply_next_app()
                return
            elif job["operation"] == "clear":
                (layer,) = struct.unpack("<Q", self.read_user(self.app + 40, 8))
                if not layer:
                    if chained:
                        restore_guest_call_state(self.packet, job["state"])
                    self.note(waiting_for_original_main_layer=hex(self.app))
                    self.next_frame = time.monotonic() + 0.25
                    self.step_original()
                    return
                (selector,) = struct.unpack(
                    "<Q", self.read_user(0x18C629040 + self.slide, 8)
                )
                assert self.read_user(selector, 17) == b"renderInContext:\x00"
                self.invoke(
                    current,
                    "render",
                    (layer, selector, self.context),
                    saved=job["state"] if chained else None,
                )
                return
            elif job["operation"] == "render":
                self.invoke(
                    current,
                    "flush",
                    (self.context,),
                    saved=job["state"] if chained else None,
                )
                return
            elif job["operation"] == "flush":
                assert self.on_frame is not None
                self.on_frame(self.context)
                self.events_since_frame = 0
                self.button_check_due = bool(self.held_buttons)
                self.next_frame = 0 if self.fast_frames else time.monotonic() + 0.03
                self.step_original()
                self.apply_next_app()
                return
        if self.next_app:
            self.step_original()
            self.apply_next_app()
            return
        (fp,) = struct.unpack_from("<Q", current, 29 * 8)
        (caller,) = struct.unpack("<Q", self.read_user(fp + 8, 8))
        (options,) = struct.unpack_from("<Q", current, 8)
        if caller != 0x18140ACAC + self.slide or options & 1:
            self.report["live_bridge"]["non_idle_stops_skipped"] = (
                self.report["live_bridge"].get("non_idle_stops_skipped", 0) + 1
            )
            self.step_original()
            return
        self.poll_input()
        scanout_active = self.scanout_active()
        if self.buffer is None:
            self.invoke(current, "calloc", (1, 512))
        elif self.runloop is None:
            self.invoke(current, "runloop")
        elif self.guest_now is None:
            self.invoke(current, "now")
        elif self.timer is None:
            self.invoke(
                current,
                "timer",
                (0, 0, 0, 0x18ABE5AB8 + self.slide, 0),
                (self.guest_now + self.heartbeat, self.heartbeat),
            )
        elif not self.timer_added:
            (mode,) = struct.unpack("<Q", self.read_user(0x18AE512C8 + self.slide, 8))
            self.invoke(current, "add_timer", (self.runloop, self.timer, mode))
        elif not scanout_active and self.context is None:
            self.invoke(current, "bitmap", (640, 1136))
        elif not scanout_active and (not self.translated):
            self.invoke(current, "translate", (self.context,), (0.0, 1136.0))
        elif not scanout_active and (not self.scaled):
            self.invoke(current, "scale", (self.context,), (1.0, -1.0))
        elif self.button_check_due:
            self.invoke(current, "button_time")
        elif self.queue and (scanout_active or self.events_since_frame < 2):
            event = self.queue.pop(0)
            if event["type"] == "button":
                key = event["button"]
                if event["phase"] == 1:
                    if key in self.buttons_pressed:
                        self.note(input_rejected="button already held", event=event)
                        self.step_original()
                        return
                    self.buttons_pressed.add(key)
                elif key in self.buttons_pressed:
                    self.buttons_pressed.remove(key)
                else:
                    self.note(input_rejected="button up without down", event=event)
                    self.step_original()
                    return
            elif event["phase"] == 1:
                self.pressed = True
            elif not self.pressed:
                self.note(input_rejected="move/up without active down", event=event)
                self.step_original()
                return
            if event["type"] == "pointer" and event["phase"] == 6:
                self.pressed = False
            self.event = event
            self.invoke(current, "timestamp")
        elif not scanout_active and time.monotonic() >= self.next_frame:
            self.invoke(current, "clear", (self.context,), (0.0, 0.0, 640.0, 1136.0))
        else:
            self.step_original()
