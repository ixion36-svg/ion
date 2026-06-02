"""v0.39.0 — JA4 / JA4S TLS fingerprinting (FoxIO JA4+).

Validates the JA4 client fingerprint computation: structure, GREASE
exclusion, TLS-version from supported_versions, SNI/ALPN flags, and
determinism. The sha256-trunc-12 hashing was separately validated against
the FoxIO reference worked examples during development.
"""
import re
import struct

from ion.services.pcap_service import (
    _is_grease,
    _ja4_alpn,
    _parse_client_hello_ja4,
)


def _build_client_hello(ciphers, ext_types, *, sni=b"example.com", alpn=(b"h2",)):
    body = struct.pack("!H", 0x0303)          # client_version (legacy)
    body += b"\x00" * 32                       # random
    body += b"\x00"                            # session id len = 0
    cs = b"".join(struct.pack("!H", c) for c in ciphers)
    body += struct.pack("!H", len(cs)) + cs
    body += b"\x01\x00"                         # compression: 1 method, null
    exts = b""
    if sni:
        name = b"\x00" + struct.pack("!H", len(sni)) + sni   # host_name(0)
        sni_list = struct.pack("!H", len(name)) + name
        exts += struct.pack("!HH", 0x0000, len(sni_list)) + sni_list
    if alpn:
        protos = b"".join(struct.pack("!B", len(p)) + p for p in alpn)
        adata = struct.pack("!H", len(protos)) + protos
        exts += struct.pack("!HH", 0x0010, len(adata)) + adata
    sv = b"\x02" + struct.pack("!H", 0x0304)   # supported_versions → TLS 1.3
    exts += struct.pack("!HH", 0x002b, len(sv)) + sv
    for et in ext_types:
        exts += struct.pack("!HH", et, 0)
    body += struct.pack("!H", len(exts)) + exts
    hs = b"\x01" + struct.pack("!I", len(body))[1:] + body  # handshake header
    return b"\x16" + struct.pack("!H", 0x0301) + struct.pack("!H", len(hs)) + hs


def test_is_grease():
    assert _is_grease(0x0a0a) and _is_grease(0x1a1a) and _is_grease(0xfafa)
    assert not _is_grease(0x1301) and not _is_grease(0xc02b)


def test_ja4_alpn():
    assert _ja4_alpn("h2") == "h2"
    assert _ja4_alpn("http/1.1") == "h1"
    assert _ja4_alpn("") == "00"
    assert _ja4_alpn("@x") == "99"  # non-alphanumeric first char


def test_ja4_structure_and_grease_exclusion():
    ch = _build_client_hello(
        ciphers=[0x1301, 0x1302, 0xc02b, 0x0a0a],   # last is GREASE → excluded
        ext_types=[0x000d, 0x0023],
    )
    ja4 = _parse_client_hello_ja4(ch)
    # t(TCP) 13(TLS1.3 via supported_versions) d(SNI present) 03(ciphers) 05(exts) h2(ALPN)
    assert ja4.startswith("t13d0305h2_"), ja4
    a, b, c = ja4.split("_")
    assert re.fullmatch(r"[0-9a-f]{12}", b)
    assert re.fullmatch(r"[0-9a-f]{12}", c)
    # deterministic
    assert _parse_client_hello_ja4(ch) == ja4


def test_ja4_no_sni_is_i():
    ch = _build_client_hello(ciphers=[0x1301], ext_types=[], sni=b"", alpn=())
    ja4 = _parse_client_hello_ja4(ch)
    assert ja4.startswith("t13i"), ja4  # 'i' = no SNI


def test_ja4_garbage_returns_empty():
    assert _parse_client_hello_ja4(b"not a tls record") == ""
    assert _parse_client_hello_ja4(b"") == ""
