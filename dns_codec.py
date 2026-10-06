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

Domain names use the uncompressed label wire format (RFC 1035 section 3.1);
decode_name also accepts backward compression pointers (section 4.1.4).

A question entry (RFC 1035 section 4.1.2) is a domain name followed by the
QTYPE and QCLASS unsigned 16-bit values in network byte order.

A resource record (RFC 1035 section 4.1.3) is a domain name followed by
TYPE, CLASS, TTL, RDLENGTH and RDATA; only A records (TYPE 1, four-octet
IPv4 RDATA) are supported here.

Public API: encode_header, decode_header, encode_name, decode_name,
encode_question, decode_question, encode_resource_record,
decode_resource_record, DNSArgumentError, DNSMessageError.
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
    "encode_question",
    "decode_question",
    "encode_resource_record",
    "decode_resource_record",
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

QUESTION_FIELDS = ("name", "qtype", "qclass")

RECORD_FIELDS = ("name", "type", "class", "ttl", "address")

_FLAG_FIELDS = frozenset(("qr", "aa", "tc", "rd", "ra"))
_4BIT_FIELDS = frozenset(("opcode", "rcode"))
_HEADER_STRUCT = struct.Struct("!HBBHHHH")
_QUESTION_STRUCT = struct.Struct("!HH")
_RECORD_FIXED_STRUCT = struct.Struct("!HHIH")
_TYPE_A = 1
_A_RDATA_LENGTH = 4
HEADER_SIZE = 12
_INPUT_LIMIT = 4096
_HEX_DIGITS = frozenset("0123456789abcdefABCDEF")

MAX_LABEL_LENGTH = 63
MAX_NAME_LENGTH = 255
MAX_MESSAGE_LENGTH = 65535
MAX_COMPRESSION_POINTERS = 128
_POINTER_BITS = 0xC0


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


def encode_name(name):
    """Encode an ASCII absolute domain name into uncompressed wire bytes.

    The root is written as ``"."``; every other name must end with a dot.
    Labels keep their original case. Raises DNSArgumentError for any invalid
    input; the argument is never mutated.
    """
    if not isinstance(name, str):
        raise DNSArgumentError("name must be a string")
    if not name.endswith("."):
        raise DNSArgumentError("name must be absolute and end with '.'")

    # Drop the single trailing dot; the root (".") then yields no labels.
    body = name[:-1]
    labels = body.split(".") if body else []

    pieces = []
    total = 1  # the terminating zero length octet
    for label in labels:
        if label == "":
            raise DNSArgumentError("empty label in name")
        try:
            encoded = label.encode("ascii")
        except UnicodeEncodeError:
            raise DNSArgumentError("name must contain ASCII characters only")
        if len(encoded) > MAX_LABEL_LENGTH:
            raise DNSArgumentError(
                "label exceeds %d bytes: %r" % (MAX_LABEL_LENGTH, label)
            )
        total += 1 + len(encoded)
        if total > MAX_NAME_LENGTH:
            raise DNSArgumentError(
                "wire name exceeds %d bytes" % MAX_NAME_LENGTH
            )
        pieces.append(bytes((len(encoded),)) + encoded)

    return b"".join(pieces) + b"\x00"


def decode_name(message, offset=0):
    """Read a domain name from ``message`` starting at ``offset``.

    Returns an ``(absolute_name, next_offset)`` tuple where ``next_offset``
    is the first byte after the name at its original location (a two-byte
    compression pointer is skipped as a whole). Raises DNSArgumentError for
    invalid arguments and DNSMessageError for malformed wire data.
    """
    if not isinstance(message, bytes):
        raise DNSArgumentError("message must be bytes")
    if isinstance(offset, bool) or not isinstance(offset, int):
        raise DNSArgumentError("offset must be an integer")
    if len(message) > MAX_MESSAGE_LENGTH:
        raise DNSArgumentError(
            "message exceeds %d bytes" % MAX_MESSAGE_LENGTH
        )
    if offset < 0 or offset >= len(message):
        # offset == len(message) is still out of bounds: a name always
        # occupies at least one byte.
        raise DNSArgumentError("offset out of bounds")

    labels = []
    name_bytes = 0
    position = offset
    pointer_follows = 0
    # The offset to return: advanced only through labels at the original
    # position; it jumps over the first pointer's two bytes and then stops.
    next_offset = None

    while True:
        if position >= len(message):
            raise DNSMessageError("truncated name: missing length octet")
        length = message[position]

        if length == 0:
            if next_offset is None:
                next_offset = position + 1
            break

        if (length & _POINTER_BITS) == _POINTER_BITS:
            # A pointer occupies two octets; the second must be present.
            if position + 1 >= len(message):
                raise DNSMessageError("truncated compression pointer")
            if pointer_follows >= MAX_COMPRESSION_POINTERS:
                raise DNSMessageError(
                    "too many compression pointers (limit %d)"
                    % MAX_COMPRESSION_POINTERS
                )
            target = ((length & 0x3F) << 8) | message[position + 1]
            if target >= position:
                raise DNSMessageError("compression pointer does not point back")
            if next_offset is None:
                next_offset = position + 2
            pointer_follows += 1
            position = target
            continue

        if length & _POINTER_BITS:
            # 01 and 10 prefixes are reserved (RFC 1035 section 4.1.4).
            raise DNSMessageError("reserved label type prefix: %#04x" % length)

        start = position + 1
        end = start + length
        if end > len(message):
            raise DNSMessageError("truncated label")
        label_bytes = message[start:end]
        try:
            label = label_bytes.decode("ascii")
        except UnicodeDecodeError:
            raise DNSMessageError("label is not ASCII")

        name_bytes += 1 + length
        if name_bytes > MAX_NAME_LENGTH - 1:
            raise DNSMessageError(
                "expanded name exceeds %d bytes" % MAX_NAME_LENGTH
            )
        labels.append(label)
        position = end

    return ".".join(labels) + ".", next_offset


_QUESTION_FIELD_SET = frozenset(QUESTION_FIELDS)


def encode_question(question):
    """Encode a ``name``/``qtype``/``qclass`` mapping into question wire bytes.

    The name is written uncompressed followed by QTYPE and QCLASS as two
    network-order unsigned 16-bit values. Validation is completed before any
    result is produced; the caller's object is never mutated and header
    counters are never touched. Raises DNSArgumentError for any invalid input.
    """
    if not isinstance(question, Mapping):
        raise DNSArgumentError("question must be a mapping")

    for name in QUESTION_FIELDS:
        if name not in question:
            raise DNSArgumentError("missing field: %s" % name)

    for key in question:
        if key not in _QUESTION_FIELD_SET:
            raise DNSArgumentError("unknown field: %s" % key)

    name = question["name"]
    qtype = question["qtype"]
    qclass = question["qclass"]

    # Validate all inputs before producing any output.
    encoded_name = encode_name(name)
    _check_uint(qtype, "qtype", 16)
    _check_uint(qclass, "qclass", 16)

    return encoded_name + _QUESTION_STRUCT.pack(qtype, qclass)


def decode_question(message, offset=0):
    """Read one question entry from ``message`` starting at ``offset``.

    Returns a ``(question, next_offset)`` tuple: ``question`` is a plain
    dict with keys in the fixed order name, qtype, qclass, and
    ``next_offset`` is the first byte after the entry in the original
    message. The name follows the same compression-pointer rules as
    decode_name; the four trailing bytes are QTYPE and QCLASS. Raises
    DNSArgumentError for invalid arguments and DNSMessageError for
    malformed wire data.
    """
    if not isinstance(message, bytes):
        raise DNSArgumentError("message must be bytes")
    if isinstance(offset, bool) or not isinstance(offset, int):
        raise DNSArgumentError("offset must be an integer")
    if len(message) > MAX_MESSAGE_LENGTH:
        raise DNSArgumentError(
            "message exceeds %d bytes" % MAX_MESSAGE_LENGTH
        )
    if offset < 0 or offset >= len(message):
        raise DNSArgumentError("offset out of bounds")

    name, position = decode_name(message, offset)

    end = position + _QUESTION_STRUCT.size
    if end > len(message):
        raise DNSMessageError(
            "question record must contain four trailing bytes (qtype, qclass)"
        )

    qtype, qclass = _QUESTION_STRUCT.unpack(message[position:end])

    return {"name": name, "qtype": qtype, "qclass": qclass}, end


_RECORD_FIELD_SET = frozenset(RECORD_FIELDS)


def _parse_ipv4(address):
    # Strict dotted decimal: exactly four segments of 0-255, no leading
    # zeros except for the single digit "0" itself.
    if not isinstance(address, str):
        raise DNSArgumentError("field 'address' must be a string")
    segments = address.split(".")
    if len(segments) != 4:
        raise DNSArgumentError("field 'address' must have four decimal segments")
    octets = []
    for segment in segments:
        if not segment or not segment.isascii() or not segment.isdigit():
            raise DNSArgumentError(
                "field 'address' segments must be decimal digits"
            )
        if len(segment) > 1 and segment[0] == "0":
            raise DNSArgumentError(
                "field 'address' segments must not have leading zeros"
            )
        value = int(segment)
        if value > 255:
            raise DNSArgumentError(
                "field 'address' segment out of range: %s" % segment
            )
        octets.append(value)
    return octets


def encode_resource_record(record):
    """Encode one A resource record mapping into wire bytes.

    The mapping must contain exactly the keys name, type, class, ttl and
    address (in any order). The name is written uncompressed; ``type`` must
    be the integer 1 (A), ``class`` a 16-bit and ``ttl`` a 32-bit unsigned
    integer (bools are never accepted), and ``address`` a dotted-decimal
    IPv4 string without leading zeros. RDLENGTH is fixed to 4. Validation
    is completed before any result is produced; the caller's object is
    never mutated. Raises DNSArgumentError for any invalid input.
    """
    if not isinstance(record, Mapping):
        raise DNSArgumentError("record must be a mapping")

    for name in RECORD_FIELDS:
        if name not in record:
            raise DNSArgumentError("missing field: %s" % name)

    for key in record:
        if key not in _RECORD_FIELD_SET:
            raise DNSArgumentError("unknown field: %s" % key)

    name = record["name"]
    rtype = record["type"]
    rclass = record["class"]
    ttl = record["ttl"]
    address = record["address"]

    # Validate all inputs before producing any output.
    encoded_name = encode_name(name)
    _check_uint(rtype, "type", 16)
    if rtype != _TYPE_A:
        raise DNSArgumentError("field 'type' must be 1 (A)")
    _check_uint(rclass, "class", 16)
    _check_uint(ttl, "ttl", 32)
    octets = _parse_ipv4(address)

    return (
        encoded_name
        + _RECORD_FIXED_STRUCT.pack(rtype, rclass, ttl, _A_RDATA_LENGTH)
        + bytes(octets)
    )


def decode_resource_record(message, offset=0):
    """Read one A resource record from ``message`` starting at ``offset``.

    Returns a ``(record, next_offset)`` tuple: ``record`` is a plain dict
    with keys in the fixed order name, type, class, ttl, address, and
    ``next_offset`` is the first byte after the record in the original
    message. The owner name follows the same compression-pointer rules as
    decode_name; the address is rendered in canonical dotted decimal
    without leading zeros. Raises DNSArgumentError for invalid arguments
    and DNSMessageError for malformed wire data (truncated name, fixed
    fields or RDATA, a non-A TYPE, or an RDLENGTH other than 4); no
    partial result is returned on failure.
    """
    if not isinstance(message, bytes):
        raise DNSArgumentError("message must be bytes")
    if isinstance(offset, bool) or not isinstance(offset, int):
        raise DNSArgumentError("offset must be an integer")
    if len(message) > MAX_MESSAGE_LENGTH:
        raise DNSArgumentError(
            "message exceeds %d bytes" % MAX_MESSAGE_LENGTH
        )
    if offset < 0 or offset >= len(message):
        raise DNSArgumentError("offset out of bounds")

    name, position = decode_name(message, offset)

    fixed_end = position + _RECORD_FIXED_STRUCT.size
    if fixed_end > len(message):
        raise DNSMessageError(
            "resource record must contain ten trailing bytes"
            " (type, class, ttl, rdlength)"
        )
    rtype, rclass, ttl, rdlength = _RECORD_FIXED_STRUCT.unpack(
        message[position:fixed_end]
    )

    if rtype != _TYPE_A:
        raise DNSMessageError("unsupported record type: %d (only A is supported)" % rtype)
    if rdlength != _A_RDATA_LENGTH:
        raise DNSMessageError(
            "A record RDLENGTH must be %d, got %d" % (_A_RDATA_LENGTH, rdlength)
        )

    rdata_end = fixed_end + rdlength
    if rdata_end > len(message):
        raise DNSMessageError("truncated RDATA")

    address = ".".join(str(octet) for octet in message[fixed_end:rdata_end])

    return {
        "name": name,
        "type": rtype,
        "class": rclass,
        "ttl": ttl,
        "address": address,
    }, rdata_end


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


def _cmd_encode_question():
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
    wire = encode_question(obj)
    output = json.dumps({"wire": wire.hex()}, separators=(",", ":"))
    sys.stdout.write(output + "\n")
    return 0


def _cmd_decode_question():
    data = _read_limited_input()
    wire = _decode_hex(data)
    if not wire:
        # The default offset is valid call-site input; an empty message is
        # simply a truncated question, hence a message error (exit code 3).
        raise DNSMessageError("truncated question: empty input")
    question, next_offset = decode_question(wire)
    if next_offset != len(wire):
        raise DNSMessageError(
            "trailing bytes after question: %d byte(s)" % (len(wire) - next_offset)
        )
    output = json.dumps(question, separators=(",", ":"))
    sys.stdout.write(output + "\n")
    return 0


def _cmd_encode_record():
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
    wire = encode_resource_record(obj)
    output = json.dumps({"wire": wire.hex()}, separators=(",", ":"))
    sys.stdout.write(output + "\n")
    return 0


def _cmd_decode_record():
    data = _read_limited_input()
    wire = _decode_hex(data)
    if not wire:
        # The default offset is valid call-site input; an empty message is
        # simply a truncated record, hence a message error (exit code 3).
        raise DNSMessageError("truncated resource record: empty input")
    record, next_offset = decode_resource_record(wire)
    if next_offset != len(wire):
        raise DNSMessageError(
            "trailing bytes after resource record: %d byte(s)"
            % (len(wire) - next_offset)
        )
    output = json.dumps(record, separators=(",", ":"))
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
    subparsers.add_parser(
        "encode-question",
        help="read a UTF-8 JSON question object from stdin and print its hex wire form",
    )
    subparsers.add_parser(
        "decode-question",
        help="read hexadecimal wire bytes from stdin and print the question as JSON",
    )
    subparsers.add_parser(
        "encode-record",
        help="read a UTF-8 JSON A record object from stdin and print its hex wire form",
    )
    subparsers.add_parser(
        "decode-record",
        help="read hexadecimal wire bytes from stdin and print the A record as JSON",
    )
    args = parser.parse_args(argv)

    try:
        if args.command == "encode-header":
            return _cmd_encode_header()
        if args.command == "decode-header":
            return _cmd_decode_header()
        if args.command == "encode-question":
            return _cmd_encode_question()
        if args.command == "decode-question":
            return _cmd_decode_question()
        if args.command == "encode-record":
            return _cmd_encode_record()
        return _cmd_decode_record()
    except (DNSArgumentError, DNSMessageError) as exc:
        return _write_error(exc)


if __name__ == "__main__":
    sys.exit(main())
