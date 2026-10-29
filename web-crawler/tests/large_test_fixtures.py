"""Stream-write synthetic Burp XML fixtures with exact sizes and bounded memory.

No live traffic or personal information is used. Large fixtures are generated on
demand, never committed. ``padded`` measures input-size handling, whereas
``records`` also exercises decoding/scanning many substantial response bodies.
"""
from __future__ import annotations

import base64
import hashlib
import json
from pathlib import Path
from typing import BinaryIO, Iterable

MIB = 1024 * 1024
BLOCK = 64 * 1024
PROLOG = b'<?xml version="1.0" encoding="UTF-8"?>\n<items>\n'
EPILOG = b'\n</items>\n'


class CountingWriter:
    def __init__(self, stream: BinaryIO):
        self.stream = stream
        self.count = 0
        self.digest = hashlib.sha256()

    def write(self, data: bytes):
        self.stream.write(data)
        self.count += len(data)
        self.digest.update(data)


def repeated_bytes(length: int, value: bytes = b'A') -> Iterable[bytes]:
    if len(value) != 1 or length < 0:
        raise ValueError('A nonnegative length and one-byte value are required')
    block = value * BLOCK
    while length:
        n = min(length, BLOCK)
        yield block[:n]
        length -= n


def write_base64(writer: CountingWriter, chunks: Iterable[bytes]):
    carry = b''
    for chunk in chunks:
        data = carry + chunk
        n = len(data) - len(data) % 3
        if n:
            writer.write(base64.b64encode(data[:n]))
        carry = data[n:]
    if carry:
        writer.write(base64.b64encode(carry))


def body_parts(index: int, body_bytes: int):
    prefix = ('{"synthetic":true,"record":' + str(index)
              + ',"user_nm":"가상회원","email":"member' + str(index)
              + '@example.test","phone":"+82-10-0000-0000","note":"').encode('utf-8')
    suffix = b'"}'
    padding = body_bytes - len(prefix) - len(suffix)
    if padding < 0:
        raise ValueError('Response body must be at least 256 bytes')
    return prefix, padding, suffix


def item_plan(index: int, body_bytes: int):
    # Only the body padding is a long no-@ run. This catches unbounded email
    # regexes without inserting actual email addresses or production traffic.
    prefix, padding, suffix = body_parts(index, body_bytes)
    head = (f'HTTP/1.1 200 Synthetic\r\nContent-Type: application/json; charset=utf-8\r\n'
            f'Content-Length: {body_bytes}\r\n\r\n').encode('ascii')
    request = base64.b64encode(f'GET /record/{index} HTTP/1.1\r\nHost: agency.example.test\r\n\r\n'.encode())
    opening = (f'<item><url>https://agency.example.test/record/{index}?synthetic=1</url>'
               f'<method>GET</method><status>200</status><time>synthetic</time>'
               f'<request base64="true">').encode() + request + b'</request><response base64="true">'
    closing = b'</response></item>\n'
    encoded_size = 4 * ((len(head) + body_bytes + 2) // 3)
    return opening, head, prefix, padding, suffix, closing, len(opening) + encoded_size + len(closing)


def write_item(writer: CountingWriter, index: int, body_bytes: int):
    opening, head, prefix, padding, suffix, closing, size = item_plan(index, body_bytes)
    writer.write(opening)
    def chunks():
        yield head
        yield prefix
        yield from repeated_bytes(padding)
        yield suffix
    write_base64(writer, chunks())
    writer.write(closing)
    return size


def write_padding(writer: CountingWriter, length: int, kind='comment'):
    if length < 0:
        raise ValueError('Target smaller than fixture data')
    if kind == 'comment' and length >= 7:
        writer.write(b'<!--')
        for chunk in repeated_bytes(length - 7, b'P'):
            writer.write(chunk)
        writer.write(b'-->')
    else:
        for chunk in repeated_bytes(length, b' '):
            writer.write(chunk)


def cdata_item():
    body = json.dumps({'synthetic': True, 'email': 'cdata@example.test',
                       'note': 'literal </item> and <item> plus ]]> and <!-- not markup -->'},
                      ensure_ascii=False, separators=(',', ':'))
    response = f'HTTP/1.1 200 Synthetic\r\nContent-Type: application/json; charset=utf-8\r\n\r\n{body}'
    escaped = response.replace(']]>', ']]]]><![CDATA[>')
    item = ('<item><url>https://agency.example.test/cdata</url><method>GET</method><status>200</status>'
            '<response base64="false"><![CDATA[' + escaped + ']]></response></item>\n').encode()
    return item, response


def write_fixture(destination, *, size_bytes: int, mode='padded', body_bytes=MIB,
                  padding='comment', cdata_boundary=BLOCK):
    """Return a manifest including exact bytes, SHA-256, and expected item count.

    ``cdata`` positions a CDATA close delimiter across ``cdata_boundary`` when
    possible. Literal ``</item>`` text inside CDATA must never split a record.
    """
    if mode not in {'padded', 'records', 'cdata'}:
        raise ValueError('mode must be padded, records, or cdata')
    if padding not in {'comment', 'whitespace'}:
        raise ValueError('padding must be comment or whitespace')
    if not isinstance(size_bytes, int) or size_bytes < 1024:
        raise ValueError('size_bytes must be an integer >= 1024')
    if not isinstance(body_bytes, int) or body_bytes < 256:
        raise ValueError('body_bytes must be an integer >= 256')
    path = Path(destination)
    path.parent.mkdir(parents=True, exist_ok=True)
    item_count = 0
    response_bytes = 0
    cdata_close_offset = None
    # Exclusive creation avoids accidentally overwriting a user capture.
    with path.open('xb') as stream:
        writer = CountingWriter(stream)
        writer.write(PROLOG)
        if mode == 'cdata':
            item, raw = cdata_item()
            close_in_item = item.index(b']]]]><![CDATA[>') + 2
            before = max(0, cdata_boundary - 1 - len(PROLOG) - close_in_item)
            if writer.count + before + len(item) + len(EPILOG) > size_bytes:
                before = 0
            for chunk in repeated_bytes(before, b' '):
                writer.write(chunk)
            cdata_close_offset = writer.count + close_in_item
            writer.write(item)
            item_count = 1
            response_bytes = len(raw.encode())
        else:
            chosen_body = 512 if mode == 'padded' else body_bytes
            while True:
                planned = item_plan(item_count + 1, chosen_body)[-1]
                if writer.count + planned + len(EPILOG) > size_bytes:
                    break
                item_count += 1
                write_item(writer, item_count, chosen_body)
                response_bytes += chosen_body
                if mode == 'padded':
                    break
        if not item_count:
            raise ValueError('Target too small to hold one response with selected body_bytes')
        write_padding(writer, size_bytes - writer.count - len(EPILOG), padding)
        writer.write(EPILOG)
        if writer.count != size_bytes:
            raise AssertionError('Fixture size mismatch')
        manifest = {'format': 'synthetic-burp-fixture-v1', 'path': str(path), 'mode': mode,
                    'bytes': writer.count, 'mib': writer.count / MIB, 'sha256': writer.digest.hexdigest(),
                    'expected_items': item_count, 'expected_email_findings_at_least': item_count,
                    'response_body_bytes_total': response_bytes,
                    'response_body_bytes_each': chosen_body if mode != 'cdata' else None,
                    'padding': padding, 'cdata_close_offset': cdata_close_offset,
                    'cdata_boundary': cdata_boundary if mode == 'cdata' else None,
                    'warning': 'Synthetic fixture only; no production traffic or real personal data.'}
    return manifest
