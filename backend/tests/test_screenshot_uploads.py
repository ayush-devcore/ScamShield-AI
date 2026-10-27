import asyncio
import struct
import zlib

import pytest
from PIL import Image

from app.services.screenshot_analysis import (
    MAX_IMAGE_PIXELS,
    ScreenshotTooLargeError,
    read_screenshot_upload,
    validate_screenshot_upload,
)


class FakeUpload:
    def __init__(self, content: bytes):
        self.content = content
        self.read_sizes: list[int] = []
        self.closed = False

    async def read(self, size: int) -> bytes:
        self.read_sizes.append(size)
        chunk, self.content = self.content[:size], self.content[size:]
        return chunk

    async def close(self) -> None:
        self.closed = True


def png_bytes(size: tuple[int, int] = (2, 2)) -> bytes:
    from io import BytesIO

    output = BytesIO()
    Image.new("RGB", size, "white").save(output, format="PNG")
    return output.getvalue()


def oversized_png_header(width: int, height: int) -> bytes:
    def chunk(kind: bytes, data: bytes) -> bytes:
        body = kind + data
        return struct.pack(">I", len(data)) + body + struct.pack(">I", zlib.crc32(body) & 0xFFFFFFFF)

    return (
        b"\x89PNG\r\n\x1a\n"
        + chunk(b"IHDR", struct.pack(">IIBBBBB", width, height, 8, 2, 0, 0, 0))
        + chunk(b"IDAT", zlib.compress(b"\x00"))
        + chunk(b"IEND", b"")
    )


def test_oversized_upload_stops_at_limit_plus_one_and_closes() -> None:
    upload = FakeUpload(b"x" * 1_000_000)

    with pytest.raises(ScreenshotTooLargeError):
        asyncio.run(read_screenshot_upload(upload, max_bytes=100))

    assert upload.closed
    assert sum(upload.read_sizes) <= 101
    assert len(upload.read_sizes) == 1


@pytest.mark.parametrize(
    ("filename", "content_type"),
    [("spoof.jpg", "image/png"), ("image.png", "image/jpeg")],
)
def test_rejects_misleading_extension_or_mime(filename: str, content_type: str) -> None:
    with pytest.raises(ValueError, match="does not match"):
        validate_screenshot_upload(png_bytes(), filename, content_type)


def test_rejects_malformed_image() -> None:
    with pytest.raises(ValueError, match="valid supported image"):
        validate_screenshot_upload(b"not an image", "image.png", "image/png")


def test_rejects_excessive_dimensions_before_decoding() -> None:
    with pytest.raises(ValueError, match="dimensions are too large"):
        validate_screenshot_upload(
            oversized_png_header(MAX_IMAGE_PIXELS + 1, 1),
            "large.png",
            "image/png",
        )


def test_accepts_valid_supported_image() -> None:
    validate_screenshot_upload(png_bytes(), "valid.png", "image/png")
