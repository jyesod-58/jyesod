#!/usr/bin/env python3
"""Offline, bounded Burp HTTP history response normalizer.

Usage: python normalize_burp.py input.xml output.xml
Never contacts a target site and never changes request elements or the input file.
gzip/deflate use the standard library; Brotli requires the optional ``brotli`` package.
"""

from __future__ import annotations

import argparse
import base64
import binascii
from collections import Counter
import importlib
from pathlib import Path
import re
import sys
import xml.etree.ElementTree as ET
import zlib


MAX_XML_BYTES = 25 * 1024 * 1024
MAX_RESPONSE_BYTES = 8 * 1024 * 1024
MAX_HEADER_BYTES = 64 * 1024
ERROR_CODES = {
    "missing_response", "invalid_base64", "response_limit", "invalid_http",
    "header_limit", "invalid_headers", "unsupported_encoding", "invalid_chunked",
    "invalid_compression", "missing_brotli", "invalid_encoding_chain",
}


class NormalizationError(Exception):
    """A fixed, non-sensitive reason code; response contents never enter logs."""

    def __init__(self, code: str):
        if code not in ERROR_CODES:
            raise ValueError("Unknown fixed error code")
        self.code = code
        super().__init__(code)


def _bounded(data: bytes, limit: int) -> bytes:
    if len(data) > limit:
        raise NormalizationError("response_limit")
    return data


def _inflate(data: bytes, wbits: int, limit: int, *, concatenate=False) -> bytes:
    """Verify compression checksums and cap output before appending it."""
    output = bytearray()
    rest = data
    while True:
        decoder = zlib.decompressobj(wbits)
        try:
            chunk = decoder.decompress(rest, limit - len(output) + 1)
        except zlib.error:
            raise NormalizationError("invalid_compression") from None
        if len(output) + len(chunk) > limit or decoder.unconsumed_tail:
            raise NormalizationError("response_limit")
        output.extend(chunk)
        if not decoder.eof:
            raise NormalizationError("invalid_compression")
        rest = decoder.unused_data
        if not rest:
            return bytes(output)
        if not concatenate:
            raise NormalizationError("invalid_compression")


def _brotli(data: bytes, limit: int) -> bytes:
    try:
        module = importlib.import_module("brotli")
    except ImportError:
        raise NormalizationError("missing_brotli") from None
    output = bytearray()
    try:
        decoder = module.Decompressor()
        # Small input slices bound retained output; a codec may still allocate a block internally.
        for offset in range(0, len(data), 64):
            chunk = decoder.process(data[offset:offset + 64])
            if len(output) + len(chunk) > limit:
                raise NormalizationError("response_limit")
            output.extend(chunk)
        if not decoder.is_finished():
            raise NormalizationError("invalid_compression")
    except NormalizationError:
        raise
    except Exception:
        raise NormalizationError("invalid_compression") from None
    return bytes(output)


def decode_coding(data: bytes, coding: str, limit: int) -> bytes:
    if coding == "identity":
        return _bounded(data, limit)
    if coding in ("gzip", "x-gzip"):
        return _inflate(data, zlib.MAX_WBITS | 16, limit, concatenate=True)
    if coding == "deflate":
        try:
            return _inflate(data, zlib.MAX_WBITS, limit)
        except NormalizationError as exc:
            if exc.code != "invalid_compression":
                raise
            return _inflate(data, -zlib.MAX_WBITS, limit)
    if coding == "br":
        return _brotli(data, limit)
    raise NormalizationError("unsupported_encoding")


def dechunk(data: bytes, limit: int) -> bytes:
    output = bytearray()
    cursor = 0
    while True:
        line_end = data.find(b"\r\n", cursor)
        if line_end < 0 or line_end - cursor > 1024:
            raise NormalizationError("invalid_chunked")
        line = data[cursor:line_end]
        size_text, sep, extension = line.partition(b";")
        if not re.fullmatch(rb"[0-9A-Fa-f]{1,16}", size_text):
            raise NormalizationError("invalid_chunked")
        if sep and (not extension or any(c < 32 or c == 127 for c in extension)):
            raise NormalizationError("invalid_chunked")
        size = int(size_text, 16)
        cursor = line_end + 2
        if size == 0:
            # Trailer fields are permitted, but malformed terminators or trailing data are not.
            trailer_start = cursor
            while True:
                line_end = data.find(b"\r\n", cursor)
                if line_end < 0 or line_end - trailer_start > MAX_HEADER_BYTES:
                    raise NormalizationError("invalid_chunked")
                trailer = data[cursor:line_end]
                cursor = line_end + 2
                if not trailer:
                    if cursor != len(data):
                        raise NormalizationError("invalid_chunked")
                    return bytes(output)
                if not re.fullmatch(rb"[!#$%&'*+.^_`|~0-9A-Za-z-]+:[\t\x20-\x7e\x80-\xff]*", trailer):
                    raise NormalizationError("invalid_chunked")
        if size > limit - len(output):
            raise NormalizationError("response_limit")
        if cursor + size + 2 > len(data) or data[cursor + size:cursor + size + 2] != b"\r\n":
            raise NormalizationError("invalid_chunked")
        output.extend(data[cursor:cursor + size])
        cursor += size + 2


def normalize_response(raw: bytes, limit=MAX_RESPONSE_BYTES) -> tuple[bytes, list[str]]:
    if len(raw) > limit:
        raise NormalizationError("response_limit")
    marker = raw.find(b"\r\n\r\n")
    separator = b"\r\n"
    if marker < 0:
        marker = raw.find(b"\n\n")
        separator = b"\n"
    if marker < 0:
        raise NormalizationError("invalid_http")
    if marker > MAX_HEADER_BYTES:
        raise NormalizationError("header_limit")
    head = raw[:marker].split(separator)
    if not head or not re.fullmatch(rb"HTTP/[^\s]+ [1-5][0-9]{2}(?: [^\r\n]*)?", head[0]):
        raise NormalizationError("invalid_http")
    headers = []
    encodings = {b"content-encoding": [], b"transfer-encoding": []}
    for line in head[1:]:
        if not re.fullmatch(rb"[!#$%&'*+.^_`|~0-9A-Za-z-]+:[\t\x20-\x7e\x80-\xff]*", line):
            raise NormalizationError("invalid_headers")
        name, value = line.split(b":", 1)
        lowered = name.lower()
        headers.append((lowered, line))
        if lowered in encodings:
            tokens = value.strip().lower().split(b",")
            if any(not re.fullmatch(rb"[a-z0-9-]+", token.strip()) for token in tokens):
                raise NormalizationError("invalid_encoding_chain")
            encodings[lowered].extend(token.strip().decode("ascii") for token in tokens)
    body = raw[marker + len(separator) * 2:]
    transfer = encodings[b"transfer-encoding"]
    content = encodings[b"content-encoding"]
    if transfer and (transfer[-1] != "chunked" or transfer.count("chunked") != 1):
        raise NormalizationError("invalid_encoding_chain")
    if "chunked" in content:
        raise NormalizationError("invalid_encoding_chain")
    methods = []
    for coding in reversed(transfer):
        body = dechunk(body, limit) if coding == "chunked" else decode_coding(body, coding, limit)
        methods.append("transfer:" + coding)
    for coding in reversed(content):
        body = decode_coding(body, coding, limit)
        methods.append("content:" + coding)
    kept = [line for key, line in headers if key not in (b"content-encoding", b"transfer-encoding", b"content-length", b"trailer")]
    # The normalized response is a separate representation; the exact input is preserved in XML.
    new_head = b"\r\n".join([head[0], *kept, b"Content-Length: " + str(len(body)).encode("ascii")])
    return _bounded(new_head + b"\r\n\r\n" + body, limit), methods


def response_bytes(node: ET.Element) -> bytes:
    value = node.text or ""
    if node.get("base64", "false").lower() == "true":
        try:
            return base64.b64decode("".join(value.split()), validate=True)
        except (binascii.Error, ValueError, UnicodeEncodeError):
            raise NormalizationError("invalid_base64") from None
    return value.encode("utf-8")


def normalize_document(data: bytes) -> tuple[bytes, dict]:
    if len(data) > MAX_XML_BYTES:
        raise ValueError("input_xml_limit")
    # Standard Burp exports include an internal ELEMENT/ATTLIST DTD. Permit that
    # schema, but prohibit custom entities. UTF-16/32 is rejected so NUL bytes
    # cannot hide an entity declaration from this preflight check.
    if b"\0" in data:
        raise ValueError("xml_null_encoding_not_supported")
    if re.search(br"<!ENTITY\b", data, re.I):
        raise ValueError("xml_entities_not_supported")
    try:
        root = ET.fromstring(data)
    except ET.ParseError:
        raise ValueError("invalid_xml") from None
    if root.tag != "items":
        raise ValueError("burp_items_required")
    stats = {"total": 0, "normalized": 0, "failed": 0, "errors": Counter(), "failures": []}
    for item in root:
        if item.tag != "item":
            continue
        stats["total"] += 1
        response = item.find("response")
        for prior in list(item):
            if prior.tag in ("normalizationError", "normalization"):
                item.remove(prior)
        try:
            if response is None:
                raise NormalizationError("missing_response")
            raw = response_bytes(response)
            normalized, methods = normalize_response(raw)
        except NormalizationError as exc:
            ET.SubElement(item, "normalizationError").text = exc.code
            stats["failed"] += 1
            stats["errors"][exc.code] += 1
            stats["failures"].append((stats["total"], exc.code))
            continue
        original = item.find("originalResponse")
        if original is None:
            original = ET.SubElement(item, "originalResponse", {"base64": "true"})
            original.text = base64.b64encode(raw).decode("ascii")
        response.set("base64", "true")
        response.text = base64.b64encode(normalized).decode("ascii")
        ET.SubElement(item, "normalization").text = "; ".join(methods) if methods else "identity; HTTP header normalization"
        stats["normalized"] += 1
    if not stats["total"]:
        raise ValueError("no_burp_items")
    return ET.tostring(root, encoding="utf-8", xml_declaration=True), stats


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("input", type=Path)
    parser.add_argument("output", type=Path)
    args = parser.parse_args(argv)
    try:
        if args.input.resolve() == args.output.resolve():
            raise ValueError("input_output_must_differ")
        if args.output.exists():
            raise ValueError("output_already_exists")
        with args.input.open("rb") as handle:
            data = handle.read(MAX_XML_BYTES + 1)
        output, stats = normalize_document(data)
        # Exclusive creation prevents accidental replacement, including a concurrent writer.
        with args.output.open("xb") as handle:
            handle.write(output)
    except (ValueError, OSError) as exc:
        reason = str(exc) if isinstance(exc, ValueError) else "file_io_error"
        print("normalization_failed=" + reason, file=sys.stderr)
        return 1
    print("total={total} normalized={normalized} failed={failed}".format(**stats))
    for ordinal, reason in stats["failures"]:
        print("item=" + str(ordinal) + " error=" + reason)
    for reason, count in sorted(stats["errors"].items()):
        print("error=" + reason + " count=" + str(count))
    if len(output) > MAX_XML_BYTES:
        print("warning=output_exceeds_25MiB_split_history_export_for_browser_import")
    return 2 if stats["failed"] else 0


if __name__ == "__main__":
    raise SystemExit(main())
