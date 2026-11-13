import errno
import socket
import struct


class LiveRAMReader:
    base = 0x40000000
    size = 0x20000000

    def __init__(self, path):
        self.connection = socket.socket(socket.AF_UNIX)
        self.connection.settimeout(3)
        self.connection.connect(str(path))
        self.bytes_read = self.requests = 0

    def close(self):
        self.connection.close()

    def covers(self, address, count):
        return (
            count > 0
            and self.base <= address
            and (address + count <= self.base + self.size)
        )

    def receive(self, count):
        data = bytearray(count)
        view = memoryview(data)
        offset = 0
        while offset < count:
            received = self.connection.recv_into(view[offset:])
            assert received, "Read-only RAM transport closed"
            offset += received
        return bytes(data)

    def exchange(self, *words):
        self.connection.sendall(struct.pack("<" + "Q" * len(words), *words))
        return struct.unpack("<2Q", self.receive(16))

    def request(self, count, *words):
        error, length = self.exchange(*words)
        if error == errno.EFAULT and length == 0:
            raise ValueError("Guest virtual range is not resident in mapped main RAM")
        assert error == 0 and length == count, f"Native RAM request refused: {error}"
        data = self.receive(count)
        self.bytes_read += count
        self.requests += 1
        return data

    def read(self, address, count):
        assert self.covers(address, count) and count <= 0x400000
        return self.request(count, 0x4E4F4E554952414D, address, count)

    def read_user(self, ttbr, address, count, bits):
        assert 0 < count <= 0x400000
        return self.request(count, 0x4E4F4E5549564952, address, count, ttbr, bits)

    def copy_disk(self, source, destination, count):
        assert 0 < count <= 0x8000
        error, length = self.exchange(0x4E4F4E554944534B, source, count, destination)
        if length == 0 and error in (errno.ENOTSUP, errno.EFAULT):
            return False
        assert error == 0 and length == count, f"Native RAM-disk copy refused: {error}"
        return True

    def arm_direct_disk_copy(self, direction):
        error, length = self.exchange(0x4E4F4E554941524D, direction, 0)
        if length == 0 and error in (errno.ENOTSUP, errno.EINVAL):
            return False
        assert error == 0 and length == 0, (
            f"Cannot enable direct RAM-disk copy: {error}"
        )
        return True
