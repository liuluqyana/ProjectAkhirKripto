"""Steganografi gambar LSB (Least Significant Bit) memakai Pillow.

Satu bit pesan disimpan di bit terendah tiap kanal warna (R, G, B) secara
berurutan. Gambar keluaran HARUS disimpan sebagai PNG (lossless); JPEG akan
merusak bit tersembunyi.

Payload tertanam:  b"KGS1" | panjang(uint32) | CRC32(uint32) | pesan
"""
import io
import struct
import zlib

from PIL import Image, ImageDraw, ImageFont

import config

STG_MAGIC = b"KGS1"
HEADER_BYTES = 12


class StegoError(Exception):
    """Kesalahan steganografi yang aman ditampilkan ke pengguna."""


def load_image(data: bytes) -> Image.Image:
    try:
        img = Image.open(io.BytesIO(data))
        img.load()
    except Exception as exc:  # noqa: BLE001 - Pillow melempar banyak tipe error
        raise StegoError("Berkas bukan gambar yang valid (gunakan PNG/JPG).") from exc
    if img.width * img.height > config.MAX_IMAGE_PIXELS:
        raise StegoError("Resolusi gambar terlalu besar (maksimum 16 megapiksel).")
    return img.convert("RGB")


def capacity_bytes(img: Image.Image) -> int:
    """Kapasitas pesan (byte) setelah dikurangi header."""
    return max(0, (img.width * img.height * 3) // 8 - HEADER_BYTES)


def embed_message(img: Image.Image, message: bytes) -> Image.Image:
    if not message:
        raise StegoError("Pesan tidak boleh kosong.")
    rgb = img.convert("RGB")
    if len(message) > capacity_bytes(rgb):
        raise StegoError(
            f"Pesan ({len(message)} byte) melebihi kapasitas gambar ({capacity_bytes(rgb)} byte)."
        )
    raw = bytearray(rgb.tobytes())
    payload = STG_MAGIC + struct.pack(">II", len(message), zlib.crc32(message)) + message
    for i, byte in enumerate(payload):
        base = i * 8
        for b in range(8):
            raw[base + b] = (raw[base + b] & 0xFE) | ((byte >> (7 - b)) & 1)
    return Image.frombytes("RGB", rgb.size, bytes(raw))


def _read_bytes(raw: bytes, byte_offset: int, count: int) -> bytes:
    out = bytearray()
    start = byte_offset * 8
    for i in range(count):
        value = 0
        for b in range(8):
            value = (value << 1) | (raw[start + i * 8 + b] & 1)
        out.append(value)
    return bytes(out)


def extract_message(img: Image.Image) -> bytes:
    raw = img.convert("RGB").tobytes()
    if len(raw) < HEADER_BYTES * 8:
        raise StegoError("Gambar terlalu kecil.")
    header = _read_bytes(raw, 0, HEADER_BYTES)
    if header[:4] != STG_MAGIC:
        raise StegoError("Tidak ditemukan pesan tersembunyi pada gambar ini.")
    length, crc = struct.unpack(">II", header[4:])
    if length == 0 or (HEADER_BYTES + length) * 8 > len(raw):
        raise StegoError("Header steganografi tidak valid.")
    message = _read_bytes(raw, HEADER_BYTES, length)
    if zlib.crc32(message) != crc:
        raise StegoError("Pesan rusak (CRC tidak cocok). Gambar mungkin sudah dikompres/diedit.")
    return message


def image_to_png_bytes(img: Image.Image) -> bytes:
    buf = io.BytesIO()
    img.save(buf, format="PNG")
    return buf.getvalue()


def ensure_logo(path, size: int = 640) -> None:
    """Buat logo placeholder bila belum ada. Ganti berkas ini dengan Logo UPN resmi."""
    if path.exists():
        return
    path.parent.mkdir(parents=True, exist_ok=True)
    navy, crimson, maroon, bg = (20, 33, 61), (181, 18, 27), (128, 0, 0), (247, 248, 250)
    img = Image.new("RGB", (size, size), bg)
    d = ImageDraw.Draw(img)
    for y in range(size):  # latar bergradasi halus agar LSB tidak mencolok
        t = y / size
        d.line([(0, y), (size, y)], fill=(int(bg[0] - 28 * t), int(bg[1] - 36 * t), int(bg[2] - 18 * t)))
    d.ellipse([30, 30, size - 30, size - 30], fill=navy)
    d.ellipse([62, 62, size - 62, size - 62], fill=crimson)
    d.ellipse([104, 104, size - 104, size - 104], fill=maroon)
    d.ellipse([146, 146, size - 146, size - 146], fill=bg)
    font = None
    for candidate in ("DejaVuSans-Bold.ttf", "arialbd.ttf", "Arial Bold.ttf"):
        try:
            font = ImageFont.truetype(candidate, size // 5)
            break
        except OSError:
            continue
    if font is None:
        try:
            font = ImageFont.load_default(size=size // 5)
        except TypeError:
            font = ImageFont.load_default()
    left, top, right, bottom = d.textbbox((0, 0), "UPN", font=font)
    d.text(((size - (right - left)) / 2 - left, (size - (bottom - top)) / 2 - top), "UPN", font=font, fill=navy)
    img.save(path, format="PNG")
