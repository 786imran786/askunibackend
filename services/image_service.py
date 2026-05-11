"""
Image compression and upload service.
Compresses images before uploading to Supabase Storage to reduce
payload sizes and improve load times.
"""
import uuid
import io
import logging

logger = logging.getLogger(__name__)

# Try to import Pillow — graceful fallback if not installed
try:
    from PIL import Image
    PILLOW_AVAILABLE = True
except ImportError:
    PILLOW_AVAILABLE = False
    logger.warning("Pillow not installed — image compression disabled")

from database.supabase_client import supabase

# ── Configuration ─────────────────────────────────────────
MAX_DIMENSION = 1920   # max width or height
JPEG_QUALITY = 85
WEBP_QUALITY = 80


def _compress_image(file_content: bytes, content_type: str) -> tuple:
    """
    Compress image:
      - Resize if larger than MAX_DIMENSION
      - Convert to WebP when possible (much smaller)
      - Fall back to JPEG compression for unsupported formats

    Returns (compressed_bytes, new_content_type, extension).
    """
    if not PILLOW_AVAILABLE:
        ext = ".jpg" if "jpeg" in content_type else ".png"
        return file_content, content_type, ext

    try:
        img = Image.open(io.BytesIO(file_content))

        # Convert RGBA to RGB for JPEG/WebP (no alpha channel)
        if img.mode in ("RGBA", "LA", "P"):
            background = Image.new("RGB", img.size, (255, 255, 255))
            if img.mode == "P":
                img = img.convert("RGBA")
            background.paste(img, mask=img.split()[-1] if "A" in img.mode else None)
            img = background

        # Resize if too large
        if max(img.size) > MAX_DIMENSION:
            img.thumbnail((MAX_DIMENSION, MAX_DIMENSION), Image.LANCZOS)

        # Try WebP first (best compression)
        buf = io.BytesIO()
        try:
            img.save(buf, format="WEBP", quality=WEBP_QUALITY, method=4)
            return buf.getvalue(), "image/webp", ".webp"
        except Exception:
            pass

        # Fallback to JPEG
        buf = io.BytesIO()
        img.save(buf, format="JPEG", quality=JPEG_QUALITY, optimize=True)
        return buf.getvalue(), "image/jpeg", ".jpg"

    except Exception as e:
        logger.error(f"Image compression failed: {e}")
        ext = ".jpg" if "jpeg" in content_type else ".png"
        return file_content, content_type, ext


def upload_file(file) -> str | None:
    """
    Compress and upload a file to Supabase Storage.
    Returns the public URL or None on error.
    """
    try:
        file_content = file.read()
        content_type = file.content_type or "application/octet-stream"

        # Compress if it's an image
        if content_type.startswith("image/"):
            file_content, content_type, ext = _compress_image(file_content, content_type)
            filename = f"{uuid.uuid4()}{ext}"
        else:
            filename = f"{uuid.uuid4()}_{file.filename}"

        # Upload to Supabase Storage (bucket: 'images')
        supabase.storage.from_("images").upload(
            path=filename,
            file=file_content,
            file_options={"content-type": content_type},
        )

        return supabase.storage.from_("images").get_public_url(filename)
    except Exception as e:
        logger.error(f"File upload error: {e}")
        return None
