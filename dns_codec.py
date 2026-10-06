"""DNS message encoder/decoder (standard library only).

Currently implements the 12-byte DNS header (RFC 1035 section 4.1.1):

    0  1  2  3  4  5  6  7  8  9  0  1  2  3  4  5
    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    |                      ID                       |
    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    |QR|   Opcode  |AA|TC|RD|RA|   Z    |   RCODE   |
    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    |                    QDCOUNT                    |
    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    |                    ANCOUNT                    |
    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    |                    NSCOUNT                    |
    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    |                    ARCOUNT                    |
    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+

Also implements domain name encoding/decoding (RFC 1035 section 4.1.4),
including compression pointers on decode.

Public API: encode_header, decode_header, encode_name, decode_name,
DNSArgumentError, DNSMessageError.
"""

import argparse
import json
import struct
import sys
from collections.abc import Mapping

__all__ = [
    "encode_header",
    "decode_header",
    "encode_name",
    "decode_name",
    "DNSArgumentError",
    "DNSMessageError",
]

# Fixed field order, used for validation, decoding and JSON output.
HEADER_FIELDS = (
    "id",
    "qr",
    "opcode",
    "aa",
    "tc",
    "rd",
    "ra",
    "z",
    "rcode",
    "qdcount",
    "ancount",
    "nscount",
    "arcount",
)

_FLAG_FIELDS = frozenset(("qr", "aa", "tc", "rd", "ra"))
_4BIT_FIELDS = frozenset(("opcode", "rcode"))
_HEADER_STRUCT = struct.Struct("!HBBHHHH")
HEADER_SIZE = 12
_INPUT_LIMIT = 4096
_HEX_DIGITS = frozenset("0123456789abcdefABCDEF")


class DNSArgumentError(ValueError):
    """The caller supplied an invalid argument (types, ranges, shapes)."""


class DNSMessageError(ValueError):
    """The wire input is malformed (wrong length, bad layout, ...)."""


def _check_bool(value, name):
    # int is deliberately rejected: flags must be real bool values.
    if not isinstance(value, bool):
        raise DNSArgumentError("field '%s' must be a bool" % name)


def _check_uint(value, name, bits):
    # bool is a subclass of int but is never accepted for integer fields.
    if isinstance(value, bool) or not isinstance(value, int):
        raise DNSArgumentError("field '%s' must be an integer" % name)
    if value < 0 or value >= (1 << bits):
        raise DNSArgumentError(
            "field '%s' out of range for a %d-bit unsigned integer" % (name, bits)
        )


def encode_header(header):
    """Encode a header mapping into the 12-byte DNS header (network order).

    Validation is completed before any result is produced; the caller's
    object is never mutated. Raises DNSArgumentError for any invalid input.
    """
    if not isinstance(header, Mapping):
        raise DNSArgumentError("header must be a mapping")

    for name in HEADER_FIELDS:
        if name not in header:
            raise DNSArgumentError("missing field: %s" % name)

    for key in header:
        if key not in _FIELD_SET:
            raise DNSArgumentError("unknown field: %s" % key)

    values = [header[name] for name in HEADER_FIELDS]
    id_, qr, opcode, aa, tc, rd, ra, z, rcode, qd, an, ns, ar = values

    _check_uint(id_, "id", 16)
    _check_bool(qr, "qr")
    _check_uint(opcode, "opcode", 4)
    _check_bool(aa, "aa")
    _check_bool(tc, "tc")
    _check_bool(rd, "rd")
    _check_bool(ra, "ra")
    _check_uint(z, "z", 3)
    _check_uint(rcode, "rcode", 4)
    _check_uint(qd, "qdcount", 16)
    _check_uint(an, "ancount", 16)
    _check_uint(ns, "nscount", 16)
    _check_uint(ar, "arcount", 16)

    byte2 = (int(qr) << 7) | (opcode << 3) | (int(aa) << 2) | (int(tc) << 1) | int(rd)
    byte3 = (int(ra) << 7) | (z << 4) | rcode

    return _HEADER_STRUCT.pack(id_, byte2, byte3, qd, an, ns, ar)


_FIELD_SET = frozenset(HEADER_FIELDS)

_MAX_LABEL_LENGTH = 63
_MAX_NAME_WIRE = 255
_MAX_MESSAGE_SIZE = 65535
_MAX_POINTER_JUMPS = 128


def encode_name(name):
    """Encode an ASCII absolute domain name into uncompressed wire form.

    ``name`` must be a string: "." for the root, otherwise a dot-separated
    sequence of labels ending with a dot. Label case is preserved. Returns
    the wire bytes (length-prefixed labels plus the zero terminator).

    Raises DNSArgumentError for a wrong argument type, non-ASCII characters,
    a missing trailing dot, an empty intermediate label, a label longer
    than 63 bytes, or a wire form longer than 255 bytes. Validation is
    completed before any result is produced; the input is never mutated.
    """
    if not isinstance(name, str):
        raise DNSArgumentError("name must be a string")
    if name == ".":
        return b"\x00"
    if not name.endswith("."):
        raise DNSArgumentError("name must be absolute (end with '.')")
    try:
        ascii_name = name.encode("ascii")
    except UnicodeEncodeError:
        raise DNSArgumentError("name must contain only ASCII characters")

    parts = []
    wire_length = 1  # the terminating zero byte
    for label in ascii_name[:-1].split(b"."):
        if not label:
            raise DNSArgumentError("name contains an empty label")
        if len(label) > _MAX_LABEL_LENGTH:
            raise DNSArgumentError(
                "label exceeds %d bytes" % _MAX_LABEL_LENGTH
            )
        wire_length += 1 + len(label)
        if wire_length > _MAX_NAME_WIRE:
            raise DNSArgumentError("name exceeds %d wire bytes" % _MAX_NAME_WIRE)
        parts.append(bytes((len(label),)) + label)
    parts.append(b"\x00")
    return b"".join(parts)


def decode_name(message, offset=0):
    """Decode one domain name from ``message`` starting at ``offset``.

    Returns a tuple ``(name, next_offset)`` where ``name`` is the absolute
    domain name as a string with a trailing dot ("." for the root) and
    ``next_offset`` is the first offset after the name at its original
    position (past the two-byte pointer when compression is used).
    Compression pointers are followed (at most 128 per name); each pointer
    must target an earlier offset holding a valid label start. Label case
    is preserved; labels must be ASCII.

    Raises DNSArgumentError when ``message`` is not bytes or exceeds 65535
    bytes, or when ``offset`` is not a non-bool integer within the message.
    Raises DNSMessageError for malformed wire data: truncated labels or
    pointers, reserved length prefixes, an overlong name, out-of-range or
    non-backward pointers, and pointer loops. No partial name is returned
    and no external state is changed on failure.
    """
    if not isinstance(message, bytes):
        raise DNSArgumentError("message must be bytes")
    if len(message) > _MAX_MESSAGE_SIZE:
        raise DNSArgumentError(
            "message exceeds %d bytes" % _MAX_MESSAGE_SIZE
        )
    if isinstance(offset, bool) or not isinstance(offset, int):
        raise DNSArgumentError("offset must be an integer")
    if offset < 0 or offset >= len(message):
        raise DNSArgumentError("offset out of range for the message")

    labels = []
    wire_length = 0
    jumps = 0
    pos = offset
    next_offset = None
    while True:
        length = message[pos]
        tag = length & 0xC0
        if tag == 0xC0:
            # Compression pointer: two bytes, 14-bit target offset.
            if pos + 1 >= len(message):
                raise DNSMessageError("truncated compression pointer")
            target = ((length & 0x3F) << 8) | message[pos + 1]
            if next_offset is None:
                next_offset = pos + 2
            jumps += 1
            if jumps > _MAX_POINTER_JUMPS:
                raise DNSMessageError("too many compression pointers")
            # target < pos also guarantees target is inside the message.
            if target >= pos:
                raise DNSMessageError(
                    "compression pointer does not point backward"
                )
            pos = target
            continue
        if tag != 0:
            raise DNSMessageError("reserved label length prefix")
        if length == 0:
            if next_offset is None:
                next_offset = pos + 1
            wire_length += 1
            break
        if pos + 1 + length > len(message):
            raise DNSMessageError("truncated label")
        wire_length += 1 + length
        if wire_length > _MAX_NAME_WIRE:
            raise DNSMessageError("name exceeds %d wire bytes" % _MAX_NAME_WIRE)
        try:
            label = message[pos + 1 : pos + 1 + length].decode("ascii")
        except UnicodeDecodeError:
            raise DNSMessageError("label is not ASCII")
        labels.append(label)
        pos += 1 + length

    if not labels:
        return ".", next_offset
    return ".".join(labels) + ".", next_offset


def decode_header(data):
    """Decode exactly 12 wire bytes into a plain dict in HEADER_FIELDS order.

    Raises DNSArgumentError when ``data`` is not bytes and DNSMessageError
    when it is not exactly 12 bytes long. The Z field is returned as-is.
    """
    if not isinstance(data, bytes):
        raise DNSArgumentError("wire data must be bytes")
    if len(data) != HEADER_SIZE:
        raise DNSMessageError(
            "DNS header must be exactly %d bytes, got %d" % (HEADER_SIZE, len(data))
        )

    id_, byte2, byte3, qd, an, ns, ar = _HEADER_STRUCT.unpack(data)

    return {
        "id": id_,
        "qr": bool(byte2 & 0x80),
        "opcode": (byte2 >> 3) & 0x0F,
        "aa": bool(byte2 & 0x04),
        "tc": bool(byte2 & 0x02),
        "rd": bool(byte2 & 0x01),
        "ra": bool(byte3 & 0x80),
        "z": (byte3 >> 4) & 0x07,
        "rcode": byte3 & 0x0F,
        "qdcount": qd,
        "ancount": an,
        "nscount": ns,
        "arcount": ar,
    }


def _read_limited_input():
    # Read at most one byte past the limit so oversize input is detected
    # without buffering an unbounded stream.
    data = sys.stdin.buffer.read(_INPUT_LIMIT + 1)
    if len(data) > _INPUT_LIMIT:
        raise DNSArgumentError("input exceeds %d bytes" % _INPUT_LIMIT)
    return data


def _decode_hex(data):
    try:
        text = data.decode("ascii")
    except UnicodeDecodeError:
        raise DNSArgumentError("hexadecimal input must be ASCII")
    text = text.strip()
    # Strict form: an even number of hex digits, whitespace only at the edges.
    if len(text) % 2 != 0 or any(ch not in _HEX_DIGITS for ch in text):
        raise DNSArgumentError("input is not valid hexadecimal")
    return bytes.fromhex(text)


def _write_error(exc):
    if isinstance(exc, DNSMessageError):
        kind = "message"
        code = 3
    else:
        kind = "argument"
        code = 2
    message = str(exc) or kind
    payload = json.dumps(
        {"error": kind, "message": message}, separators=(",", ":"), ensure_ascii=True
    )
    sys.stderr.write(payload + "\n")
    return code


def _cmd_encode_header():
    data = _read_limited_input()
    try:
        text = data.decode("utf-8")
    except UnicodeDecodeError:
        raise DNSArgumentError("input is not valid UTF-8")
    try:
        obj = json.loads(text)
    except json.JSONDecodeError:
        raise DNSArgumentError("input is not valid JSON")
    if not isinstance(obj, dict):
        raise DNSArgumentError("JSON input must be an object")
    wire = encode_header(obj)
    output = json.dumps({"wire": wire.hex()}, separators=(",", ":"))
    sys.stdout.write(output + "\n")
    return 0


def _cmd_decode_header():
    data = _read_limited_input()
    wire = _decode_hex(data)
    header = decode_header(wire)
    output = json.dumps(header, separators=(",", ":"))
    sys.stdout.write(output + "\n")
    return 0


def main(argv=None):
    parser = argparse.ArgumentParser(
        prog="dns_codec", description="DNS message encoder/decoder."
    )
    subparsers = parser.add_subparsers(dest="command", required=True)
    subparsers.add_parser(
        "encode-header",
        help="read a UTF-8 JSON header object from stdin and print its hex wire form",
    )
    subparsers.add_parser(
        "decode-header",
        help="read hexadecimal wire bytes from stdin and print the header as JSON",
    )
    args = parser.parse_args(argv)

    try:
        if args.command == "encode-header":
            return _cmd_encode_header()
        return _cmd_decode_header()
    except (DNSArgumentError, DNSMessageError) as exc:
        return _write_error(exc)


if __name__ == "__main__":
    sys.exit(main())
