"""XLSX text extraction (Phase 4b).

Walks every visible cell of every sheet in an OOXML workbook and
concatenates the string-valued cells into a single text blob the
analyzer can scan. Formula cells contribute their cached value;
numeric / boolean cells are coerced via ``str()`` so digit runs that
look like RRNs or phone numbers still surface.

Encrypted (MS-CFB) workbooks surface as REQ-4051 so the caller sees
the same envelope as a password-protected DOCX.
"""

from __future__ import annotations

import asyncio
import io
import zipfile

from app.extractors.fetcher import ExtractionError


def _is_encrypted_ooxml(data: bytes) -> bool:
    """Same MS-CFB sniff as the DOCX path (encrypted OOXML container)."""
    return data[:8] == b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1"


def _extract_sync(data: bytes, filename: str) -> str:
    """Walk every sheet and emit one string per non-empty cell."""
    import openpyxl  # type: ignore[import-untyped]

    if _is_encrypted_ooxml(data):
        raise ExtractionError("REQ-4051", filename=filename, detail="password-protected")

    try:
        # `data_only=True` returns cached formula results; `read_only=True`
        # streams cells without holding the whole workbook in memory.
        wb = openpyxl.load_workbook(
            io.BytesIO(data),
            data_only=True,
            read_only=True,
        )
    except zipfile.BadZipFile as e:
        raise ExtractionError("REQ-4042", filename=filename, detail=f"bad zip: {e}") from e
    except Exception as e:
        raise ExtractionError("REQ-4042", filename=filename, detail=str(e)) from e

    parts: list[str] = []
    try:
        for sheet in wb.worksheets:
            for row in sheet.iter_rows(values_only=True):
                for value in row:
                    if value is None:
                        continue
                    text = value if isinstance(value, str) else str(value)
                    text = text.strip()
                    if text:
                        parts.append(text)
    except Exception as e:
        raise ExtractionError("REQ-4042", filename=filename, detail=f"walk failed: {e}") from e
    finally:
        wb.close()

    return "\n".join(parts)


async def extract_xlsx(data: bytes, filename: str) -> str:
    """Extract concatenated text from an .xlsx (OOXML SpreadsheetML) file."""
    return await asyncio.to_thread(_extract_sync, data, filename)
