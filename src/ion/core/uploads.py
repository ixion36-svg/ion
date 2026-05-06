"""Size-bounded upload helpers (v0.19.18).

The default FastAPI / Starlette ``UploadFile.read()`` reads the entire
request body into memory before any caller-side check. For endpoints
that accept untrusted input (translator, PCAP, course images), this
opens an OOM/DoS vector — an authenticated user can POST a multi-GB
file and the whole payload is buffered before the size cap is even
consulted.

``read_upload_capped`` reads in 64 KiB chunks and raises HTTP 413 the
moment the running total exceeds ``max_bytes``. The handler doesn't
need to do its own length check afterwards.
"""
from __future__ import annotations

from fastapi import HTTPException, UploadFile

_DEFAULT_CHUNK = 64 * 1024  # 64 KiB


async def read_upload_capped(
    file: UploadFile,
    max_bytes: int,
    *,
    chunk: int = _DEFAULT_CHUNK,
) -> bytes:
    """Read an ``UploadFile`` into memory, bailing at ``max_bytes``.

    Parameters
    ----------
    file : UploadFile
        Starlette upload (``multipart/form-data``).
    max_bytes : int
        Hard cap. As soon as the running total exceeds this, ``413
        Payload Too Large`` is raised.
    chunk : int, optional
        Per-iteration read size. 64 KiB by default — small enough to
        bail before allocating GB-class buffers, large enough to
        amortise asyncio overhead.

    Returns
    -------
    bytes
        The complete file body.

    Raises
    ------
    HTTPException
        ``status_code=413`` if the upload exceeds ``max_bytes``.
    """
    if max_bytes <= 0:
        raise ValueError("max_bytes must be > 0")
    total = 0
    parts: list[bytes] = []
    while True:
        piece = await file.read(chunk)
        if not piece:
            break
        total += len(piece)
        if total > max_bytes:
            mb = max_bytes // (1024 * 1024)
            raise HTTPException(
                status_code=413,
                detail=f"File exceeds {mb} MB cap",
            )
        parts.append(piece)
    return b"".join(parts)
