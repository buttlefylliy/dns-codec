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
IPv4 RDATA), AAAA records (TYPE 28, sixteen-octet IPv6 RDATA, RFC 3596),
CNAME records (TYPE 5, a single domain name as RDATA, RFC 1035
section 3.3.1), NS records (TYPE 2, a single domain name as RDATA,
RFC 1035 section 3.3.11) and TXT records (TYPE 16, a sequence of
character-strings, RFC 1035 section 3.3.14) are supported here.

A full message (RFC 1035 section 4.1) is the header followed by the
question, answer, authority and additional sections; encode_message and
decode_message convert between the wire form and a mapping with the keys
header, questions, answers, authorities and additionals.

Public API: encode_header, decode_header, encode_name, decode_name,
encode_question, decode_question, encode_resource_record,
decode_resource_record, encode_message, decode_message,
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
    "encode_question",
    "decode_question",
    "encode_resource_record",
    "decode_resource_record",
    "encode_message",
    "decode_message",
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

CNAME_RECORD_FIELDS = ("name", "type", "class", "ttl", "target")

NS_RECORD_FIELDS = ("name", "type", "class", "ttl", "target")

TXT_RECORD_FIELDS = ("name", "type", "class", "ttl", "strings")

_FLAG_FIELDS = frozenset(("qr", "aa", "tc", "rd", "ra"))
_4BIT_FIELDS = frozenset(("opcode", "rcode"))
_HEADER_STRUCT = struct.Struct("!HBBHHHH")
_QUESTION_STRUCT = struct.Struct("!HH")
_RECORD_FIXED_STRUCT = struct.Struct("!HHIH")
_AAAA_STRUCT = struct.Struct("!8H")
_TYPE_A = 1
_TYPE_NS = 2
_TYPE_CNAME = 5
_TYPE_TXT = 16
_TYPE_AAAA = 28
_A_RDATA_LENGTH = 4
_AAAA_RDATA_LENGTH = 16
_MAX_CHARACTER_STRING_LENGTH = 255
_MAX_TXT_RDATA_LENGTH = 65535
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


_RECORD_BASE_FIELDS = ("name", "type", "class", "ttl")
_RECORD_FIELD_SET = frozenset(
    RECORD_FIELDS + CNAME_RECORD_FIELDS + NS_RECORD_FIELDS + TXT_RECORD_FIELDS
)


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


def _parse_ipv6_groups(tokens, allow_ipv4_last):
    # Each token is one to four hex digits; the final token of the whole
    # address may instead be a dotted-decimal IPv4 part (two groups).
    values = []
    for index, text in enumerate(tokens):
        if "." in text:
            if not allow_ipv4_last or index != len(tokens) - 1:
                raise DNSArgumentError(
                    "field 'address' IPv4 part must be the last group"
                )
            octets = _parse_ipv4(text)
            values.append((octets[0] << 8) | octets[1])
            values.append((octets[2] << 8) | octets[3])
            continue
        if not 1 <= len(text) <= 4 or any(ch not in _HEX_DIGITS for ch in text):
            raise DNSArgumentError(
                "field 'address' has an invalid group: %r" % text
            )
        values.append(int(text, 16))
    return values


def _parse_ipv6(address):
    # Strict textual form: no surrounding whitespace, no zone identifier,
    # no prefix length; hexadecimal groups in either case, at most one
    # "::" compression and an optional trailing IPv4-embedded part.
    if not isinstance(address, str):
        raise DNSArgumentError("field 'address' must be a string")
    if not address or not address.isascii():
        raise DNSArgumentError("field 'address' must be non-empty ASCII")
    if any(ch.isspace() for ch in address):
        raise DNSArgumentError("field 'address' must not contain whitespace")
    if "%" in address:
        raise DNSArgumentError("field 'address' must not contain a zone identifier")
    if "/" in address:
        raise DNSArgumentError("field 'address' must not contain a prefix length")
    if address.count("::") > 1:
        raise DNSArgumentError("field 'address' has more than one '::'")

    if "::" in address:
        left, right = address.split("::")
        left_tokens = left.split(":") if left else []
        right_tokens = right.split(":") if right else []
        # The IPv4-embedded part belongs at the very end of the address,
        # which is never inside the left half of a compressed form.
        left_values = _parse_ipv6_groups(left_tokens, allow_ipv4_last=False)
        right_values = _parse_ipv6_groups(right_tokens, allow_ipv4_last=True)
        missing = 8 - len(left_values) - len(right_values)
        if missing < 1:
            raise DNSArgumentError(
                "field 'address' has too many groups for '::' compression"
            )
        values = left_values + [0] * missing + right_values
    else:
        values = _parse_ipv6_groups(address.split(":"), allow_ipv4_last=True)
        if len(values) != 8:
            raise DNSArgumentError("field 'address' must have eight groups")

    return struct.pack("!8H", *values)


def _format_ipv6(groups):
    # Canonical form: lowercase hex without leading zeros; the longest run
    # of at least two zero groups is compressed (leftmost run on a tie).
    best_start = -1
    best_length = 0
    index = 0
    while index < len(groups):
        if groups[index] != 0:
            index += 1
            continue
        end = index
        while end < len(groups) and groups[end] == 0:
            end += 1
        if end - index > best_length:
            best_start = index
            best_length = end - index
        index = end

    if best_length < 2:
        return ":".join(format(group, "x") for group in groups)
    left = ":".join(format(group, "x") for group in groups[:best_start])
    right = ":".join(format(group, "x") for group in groups[best_start + best_length:])
    return left + "::" + right


def _parse_txt_strings(strings):
    # Each element is an even-length hexadecimal string (either case)
    # representing zero to 255 raw bytes; the empty string is a zero-length
    # character-string. The sequence itself must be a non-empty list/tuple.
    if not isinstance(strings, (list, tuple)):
        raise DNSArgumentError("field 'strings' must be a sequence")
    if len(strings) == 0:
        raise DNSArgumentError("field 'strings' must not be empty")
    chunks = []
    rdata_length = 0
    for index, text in enumerate(strings):
        if not isinstance(text, str):
            raise DNSArgumentError(
                "field 'strings' element %d must be a string" % index
            )
        if len(text) % 2 != 0 or any(ch not in _HEX_DIGITS for ch in text):
            raise DNSArgumentError(
                "field 'strings' element %d must be an even-length"
                " hexadecimal string" % index
            )
        chunk = bytes.fromhex(text)
        if len(chunk) > _MAX_CHARACTER_STRING_LENGTH:
            raise DNSArgumentError(
                "field 'strings' element %d exceeds %d bytes"
                % (index, _MAX_CHARACTER_STRING_LENGTH)
            )
        rdata_length += 1 + len(chunk)
        if rdata_length > _MAX_TXT_RDATA_LENGTH:
            raise DNSArgumentError(
                "TXT RDATA exceeds %d bytes" % _MAX_TXT_RDATA_LENGTH
            )
        chunks.append(chunk)
    return b"".join(
        bytes((len(chunk),)) + chunk for chunk in chunks
    )


def encode_resource_record(record):
    """Encode one A, AAAA, CNAME, NS or TXT resource record mapping.

    The mapping must contain exactly the keys name, type, class, ttl and
    address (A and AAAA), name, type, class, ttl and target (CNAME and
    NS), or name, type, class, ttl and strings (TXT), in any order. The
    name is written uncompressed; ``type`` must be the integer 1 (A),
    2 (NS), 5 (CNAME), 16 (TXT) or 28 (AAAA), ``class`` a 16-bit and
    ``ttl`` a 32-bit unsigned integer (bools are never accepted). For
    type 1 ``address`` is a dotted-decimal IPv4 string without leading
    zeros, for type 28 an IPv6 text form (either hex case, leading zeros,
    "::" compression and IPv4-embedded forms accepted; no whitespace, zone
    identifier or prefix length); RDLENGTH is then fixed to 4 or 16 and
    RDATA is the address in network byte order, so different legal
    spellings of the same address produce identical bytes. For types 2
    and 5 ``target`` follows the same absolute ASCII domain name rules as
    ``name`` (the root ``"."`` included) and RDATA is the target name in
    uncompressed wire form, with RDLENGTH set to its actual length. For
    type 16 ``strings`` must be a non-empty list or tuple of even-length
    hexadecimal strings (either case); each element represents one
    character-string of zero (the empty string) to 255 raw bytes and is
    written as a single length octet followed by those bytes, RDLENGTH
    being the sum of all length and content octets (at most 65535).
    Validation is completed before any result is produced; the caller's
    object is never mutated. Raises DNSArgumentError for any invalid input.
    """
    if not isinstance(record, Mapping):
        raise DNSArgumentError("record must be a mapping")

    for name in _RECORD_BASE_FIELDS:
        if name not in record:
            raise DNSArgumentError("missing field: %s" % name)

    for key in record:
        if key not in _RECORD_FIELD_SET:
            raise DNSArgumentError("unknown field: %s" % key)

    name = record["name"]
    rtype = record["type"]
    rclass = record["class"]
    ttl = record["ttl"]

    # Validate all inputs before producing any output.
    encoded_name = encode_name(name)
    _check_uint(rtype, "type", 16)
    if rtype == _TYPE_A or rtype == _TYPE_AAAA:
        if "target" in record:
            raise DNSArgumentError("unknown field: target")
        if "strings" in record:
            raise DNSArgumentError("unknown field: strings")
        if "address" not in record:
            raise DNSArgumentError("missing field: address")
        if rtype == _TYPE_A:
            rdata = bytes(_parse_ipv4(record["address"]))
        else:
            rdata = _parse_ipv6(record["address"])
    elif rtype == _TYPE_CNAME or rtype == _TYPE_NS:
        if "address" in record:
            raise DNSArgumentError("unknown field: address")
        if "strings" in record:
            raise DNSArgumentError("unknown field: strings")
        if "target" not in record:
            raise DNSArgumentError("missing field: target")
        rdata = encode_name(record["target"])
    elif rtype == _TYPE_TXT:
        if "address" in record:
            raise DNSArgumentError("unknown field: address")
        if "target" in record:
            raise DNSArgumentError("unknown field: target")
        if "strings" not in record:
            raise DNSArgumentError("missing field: strings")
        rdata = _parse_txt_strings(record["strings"])
    else:
        raise DNSArgumentError(
            "field 'type' must be 1 (A), 2 (NS), 5 (CNAME), 16 (TXT) or 28 (AAAA)"
        )
    _check_uint(rclass, "class", 16)
    _check_uint(ttl, "ttl", 32)

    return (
        encoded_name
        + _RECORD_FIXED_STRUCT.pack(rtype, rclass, ttl, len(rdata))
        + rdata
    )


def decode_resource_record(message, offset=0):
    """Read one A, AAAA, CNAME, NS or TXT resource record from ``message``.

    Returns a ``(record, next_offset)`` tuple: ``record`` is a plain dict
    with keys in the fixed order name, type, class, ttl, address (A and
    AAAA), name, type, class, ttl, target (CNAME and NS), or name, type,
    class, ttl, strings (TXT), and ``next_offset`` is the first byte after
    the record's declared RDATA in the original message, regardless of any
    compression pointers inside it. The owner name follows the same
    compression-pointer rules as decode_name; an A address is rendered in
    canonical dotted decimal without leading zeros, an AAAA address in
    canonical IPv6 text form (lowercase hex, no leading zeros, the longest
    run of at least two zero groups compressed, leftmost run on a tie;
    IPv4-embedded addresses are rendered in the same hexadecimal form).
    CNAME and NS targets are decoded as a complete domain name inside the
    declared RDATA (backward compression pointers accepted as for
    decode_name, label case preserved) and the declared RDATA region must
    hold exactly that one name. A TXT RDATA is read strictly inside the
    declared region as a sequence of character-strings: each is one length
    octet followed by that many raw bytes, rendered as a lowercase
    even-length hexadecimal string (the empty string denotes a zero-length
    fragment); order is preserved, no compression interpretation is
    applied to TXT data, and the region must decompose into exactly zero
    trailing bytes of whole fragments. Raises DNSArgumentError for invalid
    arguments and DNSMessageError for malformed wire data (truncated name,
    fixed fields or RDATA, a TYPE other than A, AAAA, CNAME, NS and TXT,
    an RDLENGTH other than 4 for A or 16 for AAAA, a zero CNAME or NS
    RDLENGTH, a CNAME or NS RDATA region that does not contain exactly one
    domain name, a zero TXT RDLENGTH, a TXT fragment crossing the declared
    region or the message end, or a TXT region not made up of whole
    fragments); no partial result is returned on failure.
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

    if rtype == _TYPE_A:
        expected_rdlength = _A_RDATA_LENGTH
    elif rtype == _TYPE_AAAA:
        expected_rdlength = _AAAA_RDATA_LENGTH
    elif rtype == _TYPE_CNAME or rtype == _TYPE_NS:
        expected_rdlength = None
    elif rtype == _TYPE_TXT:
        expected_rdlength = None
    else:
        raise DNSMessageError(
            "unsupported record type: %d (only A, AAAA, CNAME, NS and TXT"
            " are supported)" % rtype
        )

    rdata_end = fixed_end + rdlength
    if rtype == _TYPE_CNAME or rtype == _TYPE_NS:
        type_label = "CNAME" if rtype == _TYPE_CNAME else "NS"
        if rdlength == 0:
            raise DNSMessageError(
                "%s record RDLENGTH must not be zero" % type_label
            )
        if rdata_end > len(message):
            raise DNSMessageError("truncated RDATA")
        # The declared region must hold exactly one complete domain name;
        # decode_name's next_offset already accounts for pointer jumps.
        target, target_end = decode_name(message, fixed_end)
        if target_end != rdata_end:
            raise DNSMessageError(
                "%s RDATA must contain exactly one domain name" % type_label
            )
        return {
            "name": name,
            "type": rtype,
            "class": rclass,
            "ttl": ttl,
            "target": target,
        }, rdata_end

    if rtype == _TYPE_TXT:
        if rdlength == 0:
            raise DNSMessageError("TXT record RDLENGTH must not be zero")
        if rdata_end > len(message):
            raise DNSMessageError("truncated RDATA")
        strings = []
        cursor = fixed_end
        while cursor < rdata_end:
            fragment_length = message[cursor]
            fragment_start = cursor + 1
            fragment_end = fragment_start + fragment_length
            # The declared region is a hard bound: a fragment may not
            # cross it, and the message end cannot truncate it either.
            if fragment_end > rdata_end:
                raise DNSMessageError(
                    "TXT character-string crosses the declared RDATA region"
                )
            strings.append(message[fragment_start:fragment_end].hex())
            cursor = fragment_end
        return {
            "name": name,
            "type": rtype,
            "class": rclass,
            "ttl": ttl,
            "strings": strings,
        }, rdata_end

    if rdlength != expected_rdlength:
        raise DNSMessageError(
            "%s record RDLENGTH must be %d, got %d"
            % ("A" if rtype == _TYPE_A else "AAAA", expected_rdlength, rdlength)
        )

    if rdata_end > len(message):
        raise DNSMessageError("truncated RDATA")

    if rtype == _TYPE_A:
        address = ".".join(str(octet) for octet in message[fixed_end:rdata_end])
    else:
        address = _format_ipv6(_AAAA_STRUCT.unpack(message[fixed_end:rdata_end]))

    return {
        "name": name,
        "type": rtype,
        "class": rclass,
        "ttl": ttl,
        "address": address,
    }, rdata_end


# Fixed top-level key order of a full message mapping, used for
# validation, decoding and JSON output.
MESSAGE_FIELDS = ("header", "questions", "answers", "authorities", "additionals")

_MESSAGE_FIELD_SET = frozenset(MESSAGE_FIELDS)

# Header count field paired with the message section it must match.
_COUNT_FIELDS = (
    ("qdcount", "questions"),
    ("ancount", "answers"),
    ("nscount", "authorities"),
    ("arcount", "additionals"),
)


def encode_message(message):
    """Encode a full DNS message mapping into wire bytes.

    The mapping must contain exactly the keys header, questions, answers,
    authorities and additionals (in any order): ``header`` follows the
    encode_header rules and each of the other four is a sequence of
    question mappings (questions) or resource record mappings (answers,
    authorities, additionals). The header counts qdcount, ancount,
    nscount and arcount must equal the actual number of entries in their
    section. Validation is completed before any result is produced; the
    caller's object is never mutated. On success the header, question,
    answer, authority and additional sections are concatenated in that
    order with names in the existing uncompressed form, and the result
    never exceeds 65535 bytes. Raises DNSArgumentError for any invalid
    input.
    """
    if not isinstance(message, Mapping):
        raise DNSArgumentError("message must be a mapping")

    for name in MESSAGE_FIELDS:
        if name not in message:
            raise DNSArgumentError("missing field: %s" % name)

    for key in message:
        if key not in _MESSAGE_FIELD_SET:
            raise DNSArgumentError("unknown field: %s" % key)

    header = message["header"]
    sections = {}
    for name in MESSAGE_FIELDS[1:]:
        entries = message[name]
        if not isinstance(entries, (list, tuple)):
            raise DNSArgumentError("field '%s' must be a sequence" % name)
        sections[name] = entries

    # Validate the header (and every entry) before producing any output.
    header_wire = encode_header(header)

    for count_field, section_name in _COUNT_FIELDS:
        actual = len(sections[section_name])
        if header[count_field] != actual:
            raise DNSArgumentError(
                "header field '%s' must equal the number of entries in '%s' (%d)"
                % (count_field, section_name, actual)
            )

    parts = [header_wire]
    for question in sections["questions"]:
        parts.append(encode_question(question))
    for section_name in ("answers", "authorities", "additionals"):
        for record in sections[section_name]:
            parts.append(encode_resource_record(record))

    wire = b"".join(parts)
    if len(wire) > MAX_MESSAGE_LENGTH:
        raise DNSArgumentError(
            "encoded message exceeds %d bytes" % MAX_MESSAGE_LENGTH
        )
    return wire


def decode_message(data):
    """Decode a complete DNS message from ``data``.

    Returns a plain dict with keys in the fixed order header, questions,
    answers, authorities, additionals; each entry keeps the key order of
    decode_header, decode_question and decode_resource_record. The header
    is read first, then exactly qdcount questions and ancount, nscount
    and arcount resource records (A, AAAA, CNAME, NS and TXT only) are
    read from the same bytes; names may use the legal backward compression
    pointers accepted by decode_name. Raises DNSArgumentError when
    ``data`` is not bytes or exceeds 65535 bytes, and DNSMessageError
    when the header or any counted entry is truncated, a name or record
    is malformed, a record type is unsupported, or bytes remain after
    the last section; no partial result is returned on failure.
    """
    if not isinstance(data, bytes):
        raise DNSArgumentError("wire data must be bytes")
    if len(data) > MAX_MESSAGE_LENGTH:
        raise DNSArgumentError(
            "message exceeds %d bytes" % MAX_MESSAGE_LENGTH
        )
    if len(data) < HEADER_SIZE:
        raise DNSMessageError(
            "truncated header: need %d bytes, got %d" % (HEADER_SIZE, len(data))
        )

    header = decode_header(data[:HEADER_SIZE])
    position = HEADER_SIZE

    questions = []
    for _ in range(header["qdcount"]):
        if position >= len(data):
            raise DNSMessageError("truncated question section")
        question, position = decode_question(data, position)
        questions.append(question)

    sections = {}
    for count_field, section_name in _COUNT_FIELDS[1:]:
        records = []
        for _ in range(header[count_field]):
            if position >= len(data):
                raise DNSMessageError("truncated %s section" % section_name)
            record, position = decode_resource_record(data, position)
            records.append(record)
        sections[section_name] = records

    if position != len(data):
        raise DNSMessageError(
            "trailing bytes after message: %d byte(s)" % (len(data) - position)
        )

    return {
        "header": header,
        "questions": questions,
        "answers": sections["answers"],
        "authorities": sections["authorities"],
        "additionals": sections["additionals"],
    }


def _read_json_object():
    # Shared input path for the encode commands: a bounded stdin read
    # that must yield one UTF-8 JSON object.
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
    return obj


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


def _cmd_encode_message():
    obj = _read_json_object()
    wire = encode_message(obj)
    output = json.dumps({"wire": wire.hex()}, separators=(",", ":"))
    sys.stdout.write(output + "\n")
    return 0


def _cmd_decode_message():
    data = _read_limited_input()
    wire = _decode_hex(data)
    message = decode_message(wire)
    output = json.dumps(message, separators=(",", ":"))
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
        help="read a UTF-8 JSON A/AAAA/CNAME/NS/TXT record object from stdin and print its hex wire form",
    )
    subparsers.add_parser(
        "decode-record",
        help="read hexadecimal wire bytes from stdin and print the A/AAAA/CNAME/NS/TXT record as JSON",
    )
    subparsers.add_parser(
        "encode-message",
        help="read a UTF-8 JSON message object from stdin and print its hex wire form",
    )
    subparsers.add_parser(
        "decode-message",
        help="read hexadecimal wire bytes from stdin and print the full message as JSON",
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
        if args.command == "decode-record":
            return _cmd_decode_record()
        if args.command == "encode-message":
            return _cmd_encode_message()
        return _cmd_decode_message()
    except (DNSArgumentError, DNSMessageError) as exc:
        return _write_error(exc)


if __name__ == "__main__":
    sys.exit(main())
