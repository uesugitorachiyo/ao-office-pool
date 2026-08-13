import os
import stat
from contextlib import ExitStack, contextmanager
from unittest import mock


O_BINARY = 1 << 29


@contextmanager
def windows_text_mode():
    """Emulate the Windows CRT transformations on non-binary os.open fds."""
    real_open = os.open
    real_read = os.read
    real_write = os.write
    real_close = os.close
    binary = {}
    text_eof = set()

    def open_file(path, flags, mode=0o777, *, dir_fd=None):
        descriptor = real_open(path, flags & ~O_BINARY, mode, dir_fd=dir_fd)
        if stat.S_ISREG(os.fstat(descriptor).st_mode):
            binary[descriptor] = bool(flags & O_BINARY)
        return descriptor

    def read_file(descriptor, amount):
        if binary.get(descriptor, True):
            return real_read(descriptor, amount)
        if descriptor in text_eof:
            return b""
        raw = real_read(descriptor, amount)
        if b"\x1a" in raw:
            raw = raw.split(b"\x1a", 1)[0]
            text_eof.add(descriptor)
        return raw.replace(b"\r\n", b"\n")

    def write_file(descriptor, data):
        raw = bytes(data)
        if binary.get(descriptor, True):
            return real_write(descriptor, raw)
        physical = raw.replace(b"\n", b"\r\n")
        written = real_write(descriptor, physical)
        if written != len(physical):
            raise OSError("short emulated Windows text write")
        return len(raw)

    def close_file(descriptor):
        binary.pop(descriptor, None)
        text_eof.discard(descriptor)
        return real_close(descriptor)

    with ExitStack() as stack:
        stack.enter_context(mock.patch.object(os, "O_BINARY", O_BINARY, create=True))
        stack.enter_context(mock.patch.object(os, "open", open_file))
        stack.enter_context(mock.patch.object(os, "read", read_file))
        stack.enter_context(mock.patch.object(os, "write", write_file))
        stack.enter_context(mock.patch.object(os, "close", close_file))
        yield
