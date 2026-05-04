"""HWPX text extraction (Phase 4, T4.4/T4.5).

HWPX is the modern OOXML-style Hangeul format: a ZIP archive containing
``Contents/section{N}.xml`` files with the document's BodyText. We
extract all text-bearing elements with lxml.

The legacy HWP 5 binary format is *not* supported on Linux (the only
viable parser, ``pyhwp``, is AGPL-3.0). HWP 5 uploads surface as
REQ-4033 (unsupported attachment type).
"""

from __future__ import annotations

import asyncio
import io
import zipfile
from typing import TYPE_CHECKING

from lxml import etree  # type: ignore[import-untyped]

from app.extractors.fetcher import ExtractionError

if TYPE_CHECKING:
    pass

HWP5_MIMES = frozenset({"application/x-hwp", "application/haansofthwp"})

# HWPX text-bearing tags from the Hancom OWPML spec. We strip the namespace
# prefix during traversal so the local name match is namespace-agnostic.
_TEXT_LOCALNAMES = frozenset({"t", "char"})


def _is_hwpx(data: bytes) -> bool:
    """HWPX files are ZIP containers; HWP 5 binaries start with a
    Compound File Binary signature (D0 CF 11 E0)."""
    return data[:4] == b"PK\x03\x04"


def _local(tag: str) -> str:
    """Strip XML namespace prefix from a tag name."""
    return tag.split("}", 1)[1] if "}" in tag else tag


def _extract_sync(data: bytes, filename: str, mime_type: str) -> str:
    """Synchronous core run on a worker thread."""
    if mime_type in HWP5_MIMES:
        raise ExtractionError("REQ-4033", filename=filename, detail="HWP 5 binary format")

    if not _is_hwpx(data):
        # Some clients send HWPX with the wrong mime; if it isn't a ZIP
        # container either we treat it as a corrupted upload.
        raise ExtractionError(
            "REQ-4033",
            filename=filename,
            detail="not an HWPX (ZIP) container",
        )

    try:
        zf = zipfile.ZipFile(io.BytesIO(data))
    except zipfile.BadZipFile as e:
        raise ExtractionError("REQ-4042", filename=filename, detail=f"bad zip: {e}") from e

    parts: list[str] = []
    try:
        # Sort so section order is deterministic for tests.
        names = sorted(
            n
            for n in zf.namelist()
            if n.startswith("Contents/") and n.endswith(".xml") and "section" in n.lower()
        )
        if not names:
            # Some HWPX exports stash content under a different prefix.
            names = sorted(
                n for n in zf.namelist() if n.endswith(".xml") and "section" in n.lower()
            )
        for name in names:
            try:
                xml_bytes = zf.read(name)
                root = etree.fromstring(xml_bytes)
            except (etree.XMLSyntaxError, KeyError) as e:
                raise ExtractionError(
                    "REQ-4042",
                    filename=filename,
                    detail=f"xml parse error in {name}: {e}",
                ) from e
            for el in root.iter():
                if _local(el.tag) in _TEXT_LOCALNAMES and el.text:
                    parts.append(el.text)
    finally:
        zf.close()

    return "\n".join(parts)


async def extract_hwpx(data: bytes, filename: str, mime_type: str) -> str:
    """Extract concatenated text from an HWPX archive.

    HWP 5 binary uploads (``application/x-hwp``,
    ``application/haansofthwp``) raise REQ-4033 directly.
    """
    return await asyncio.to_thread(_extract_sync, data, filename, mime_type)
