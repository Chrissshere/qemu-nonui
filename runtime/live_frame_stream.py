import contextlib
import socket
import struct
import threading


class LiveFrameStream:
    width = 640
    height = 1136
    bytes_per_frame = width * height * 4

    def __init__(self, path):
        self.path = path
        self.condition = threading.Condition()
        self.latest = None
        self.closed = False
        self.listener = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        try:
            self.listener.bind(str(path))
            self.listener.listen(1)
            self.listener.settimeout(0.25)
        except OSError:
            self.listener.close()
            raise
        self.thread = threading.Thread(target=self.serve, daemon=True)
        self.thread.start()

    def publish(self, sequence, pixels):
        assert len(pixels) == self.bytes_per_frame
        with self.condition:
            self.latest = (sequence, pixels)
            self.condition.notify()

    def serve(self):
        while not self.closed:
            try:
                client, _ = self.listener.accept()
            except TimeoutError:
                continue
            except OSError:
                break
            with client:
                client.settimeout(1)
                sequence = None
                with contextlib.suppress(OSError):
                    while True:
                        with self.condition:
                            self.condition.wait_for(
                                lambda: (
                                    self.closed
                                    or (
                                        self.latest is not None
                                        and self.latest[0] != sequence
                                    )
                                )
                            )
                            if self.closed:
                                return
                            sequence, pixels = self.latest
                        client.sendall(
                            struct.pack("<4sIQ", b"NUIF", len(pixels), sequence)
                        )
                        client.sendall(pixels)

    def close(self):
        with self.condition:
            self.closed = True
            self.condition.notify_all()
        self.listener.close()
        self.thread.join(timeout=2)
        self.path.unlink(missing_ok=True)
