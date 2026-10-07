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
RFC 1035 section 3.3.11), DNAME records (TYPE 39, a single domain
name as RDATA, RFC 6672; no query rewriting or CNAME synthesis is
performed here), SOA records (TYPE 6, two domain names
followed by five 32-bit unsigned values, RFC 1035 section 3.3.13),
MX records (TYPE 15, a 16-bit preference followed by a domain name
as RDATA, RFC 1035 section 3.3.9),
TXT records (TYPE 16, one or more length-prefixed character-strings as
RDATA, RFC 1035 section 3.3.14) and SRV records (TYPE 33, three 16-bit
unsigned values priority, weight and port followed by a domain name as
RDATA, RFC 2782) are supported here.

A full message (RFC 1035 section 4.1) is the header followed by the
question, answer, authority and additional sections; encode_message and
decode_message convert between the wire form and a mapping with the keys
header, questions, answers, authorities and additionals.

synthesize_dname_cname (RFC 6672 section 3) is the standalone DNAME
CNAME synthesis entry point: given a query name, a DNAME record mapping
and the delegation cuts between them, it decides whether a CNAME may be
synthesized and builds it without ever mutating its inputs.

age_cached_records ages a cache snapshot of resource records by an
explicitly supplied pair of timestamps: records whose TTL outlives the
elapsed time are kept with the remaining TTL, the rest expire. No clock
is read and no hidden state is involved.

lookup_cache answers a DNS question against such a snapshot: after the
same full validation and uniform aging it returns the still-live
records whose owner name, type and class match the question, with
names compared label by label using ASCII case folding.

update_cache builds a new cache snapshot from an old one and a batch
of incoming records: the old snapshot is aged to the current event
time and every RRset supplied by the incoming batch replaces the
matching aged records, all without hidden state or a wall clock.

select_referral extracts a delegation referral from the authority and
additional sections of a response: the closest enclosing NS RRset for
the query name becomes the delegation cut and the matching in-bailiwick
A and AAAA records become the glue, with names compared label by label
using ASCII case folding.

plan_truncation_retry turns the TC flag of one response header into a
transport retry decision: given the query header, the response header
and the transport of the current exchange it decides deterministically
whether the response is accepted, the query is retried over TCP, the
response does not belong to the query, or truncation persists over TCP
and automatic retries stop. Only the two fixed-size headers and the
transport name are consulted; no body, clock or network is read.

Public API: encode_header, decode_header, encode_name, decode_name,
encode_question, decode_question, encode_resource_record,
decode_resource_record, encode_message, decode_message,
synthesize_dname_cname, age_cached_records, lookup_cache, update_cache,
select_referral, plan_truncation_retry, DNSArgumentError,
DNSMessageError.
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
    "synthesize_dname_cname",
    "age_cached_records",
    "lookup_cache",
    "update_cache",
    "select_referral",
    "plan_truncation_retry",
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

DNAME_RECORD_FIELDS = ("name", "type", "class", "ttl", "target")

SOA_RECORD_FIELDS = (
    "name",
    "type",
    "class",
    "ttl",
    "mname",
    "rname",
    "serial",
    "refresh",
    "retry",
    "expire",
    "minimum",
)

TXT_RECORD_FIELDS = ("name", "type", "class", "ttl", "strings")

MX_RECORD_FIELDS = ("name", "type", "class", "ttl", "preference", "exchange")

SRV_RECORD_FIELDS = (
    "name",
    "type",
    "class",
    "ttl",
    "priority",
    "weight",
    "port",
    "target",
)

_FLAG_FIELDS = frozenset(("qr", "aa", "tc", "rd", "ra"))
_4BIT_FIELDS = frozenset(("opcode", "rcode"))
_HEADER_STRUCT = struct.Struct("!HBBHHHH")
_QUESTION_STRUCT = struct.Struct("!HH")
_RECORD_FIXED_STRUCT = struct.Struct("!HHIH")
_AAAA_STRUCT = struct.Struct("!8H")
_SOA_TIMERS_STRUCT = struct.Struct("!5I")
_MX_PREFERENCE_STRUCT = struct.Struct("!H")
_SRV_PARAMS_STRUCT = struct.Struct("!3H")
_TYPE_A = 1
_TYPE_NS = 2
_TYPE_CNAME = 5
_TYPE_SOA = 6
_TYPE_MX = 15
_TYPE_TXT = 16
_TYPE_AAAA = 28
_TYPE_SRV = 33
_TYPE_DNAME = 39
_SUPPORTED_RECORD_TYPES = frozenset(
    (
        _TYPE_A,
        _TYPE_NS,
        _TYPE_CNAME,
        _TYPE_SOA,
        _TYPE_MX,
        _TYPE_TXT,
        _TYPE_AAAA,
        _TYPE_SRV,
        _TYPE_DNAME,
    )
)
_A_RDATA_LENGTH = 4
_AAAA_RDATA_LENGTH = 16
_SOA_TIMERS_LENGTH = _SOA_TIMERS_STRUCT.size
_MX_PREFERENCE_LENGTH = _MX_PREFERENCE_STRUCT.size
_SRV_PARAMS_LENGTH = _SRV_PARAMS_STRUCT.size
HEADER_SIZE = 12
_INPUT_LIMIT = 4096
_HEX_DIGITS = frozenset("0123456789abcdefABCDEF")

MAX_LABEL_LENGTH = 63
MAX_NAME_LENGTH = 255
MAX_MESSAGE_LENGTH = 65535
MAX_COMPRESSION_POINTERS = 128
MAX_DELEGATION_CUTS = 128
MAX_CACHED_RECORDS = 128
MAX_REFERRAL_RECORDS = 128
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
    RECORD_FIELDS
    + CNAME_RECORD_FIELDS
    + NS_RECORD_FIELDS
    + DNAME_RECORD_FIELDS
    + SOA_RECORD_FIELDS
    + TXT_RECORD_FIELDS
    + MX_RECORD_FIELDS
    + SRV_RECORD_FIELDS
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


def _encode_soa_rdata(record):
    # RDATA is mname and rname in uncompressed wire form, followed by
    # serial, refresh, retry, expire and minimum as five network-order
    # 32-bit unsigned integers.
    soa_fields = ("mname", "rname", "serial", "refresh", "retry",
                  "expire", "minimum")
    for field_name in soa_fields:
        if field_name not in record:
            raise DNSArgumentError("missing field: %s" % field_name)
    mname = encode_name(record["mname"])
    rname = encode_name(record["rname"])
    timers = []
    for field_name in ("serial", "refresh", "retry", "expire", "minimum"):
        value = record[field_name]
        _check_uint(value, field_name, 32)
        timers.append(value)
    return mname + rname + _SOA_TIMERS_STRUCT.pack(*timers)


def _reject_soa_fields(record):
    for field_name in (
        "mname",
        "rname",
        "serial",
        "refresh",
        "retry",
        "expire",
        "minimum",
    ):
        if field_name in record:
            raise DNSArgumentError("unknown field: %s" % field_name)


def _reject_mx_fields(record):
    for field_name in ("preference", "exchange"):
        if field_name in record:
            raise DNSArgumentError("unknown field: %s" % field_name)


def _reject_srv_fields(record):
    # ``target`` is shared with CNAME/NS/DNAME and is handled separately
    # by each branch; only the SRV-specific numeric fields are rejected here.
    for field_name in ("priority", "weight", "port"):
        if field_name in record:
            raise DNSArgumentError("unknown field: %s" % field_name)


def _encode_txt_strings(strings):
    # Each element is an even-length hexadecimal string (either letter
    # case) standing for zero to 255 raw bytes; the wire form is a
    # one-octet length followed by the bytes themselves.
    if not isinstance(strings, (list, tuple)):
        raise DNSArgumentError("field 'strings' must be a sequence")
    if not strings:
        raise DNSArgumentError("field 'strings' must not be empty")
    parts = []
    total = 0
    for item in strings:
        if not isinstance(item, str):
            raise DNSArgumentError("field 'strings' elements must be strings")
        if len(item) % 2 != 0 or any(ch not in _HEX_DIGITS for ch in item):
            raise DNSArgumentError(
                "field 'strings' elements must be even-length hexadecimal"
            )
        data = bytes.fromhex(item)
        if len(data) > 255:
            raise DNSArgumentError(
                "field 'strings' element exceeds 255 bytes"
            )
        total += 1 + len(data)
        if total > MAX_MESSAGE_LENGTH:
            raise DNSArgumentError(
                "TXT RDATA exceeds %d bytes" % MAX_MESSAGE_LENGTH
            )
        parts.append(bytes((len(data),)) + data)
    return b"".join(parts)


def encode_resource_record(record):
    """Encode one A, AAAA, CNAME, NS, DNAME, SOA, MX, TXT or SRV resource record mapping into wire bytes.

    The mapping must contain exactly the keys name, type, class, ttl and
    address (A and AAAA), name, type, class, ttl and target (CNAME, NS
    and DNAME), name, type, class, ttl, mname, rname, serial, refresh,
    retry, expire and minimum (SOA), name, type, class, ttl, preference
    and exchange (MX), name, type, class, ttl and strings (TXT) or
    name, type, class, ttl, priority, weight, port and target (SRV), in
    any order. The name is written uncompressed;
    ``type`` must be the integer 1 (A), 2 (NS), 5 (CNAME), 6 (SOA), 15
    (MX), 16
    (TXT), 28 (AAAA), 33 (SRV) or 39 (DNAME), ``class`` a 16-bit and
    ``ttl`` a
    32-bit unsigned integer (bools are never accepted). For type 1
    ``address`` is a dotted-decimal IPv4 string without leading zeros,
    for type 28 an IPv6 text form (either hex case, leading zeros,
    "::" compression and IPv4-embedded forms accepted; no whitespace,
    zone identifier or prefix length); RDLENGTH is then fixed to 4 or
    16 and RDATA is the address in network byte order, so different
    legal spellings of the same address produce identical bytes. For
    types 2, 5 and 39 ``target`` follows the same absolute ASCII
    domain name rules as ``name`` (the root ``"."`` included) and
    RDATA is the target name in uncompressed wire form, with RDLENGTH
    set to its actual length; no DNAME query rewriting or CNAME
    synthesis is performed. For type 6 ``mname`` and ``rname`` follow
    the same absolute ASCII domain name rules as ``name`` (the root
    ``"."`` included) and RDATA is the mname, the rname and serial,
    refresh, retry, expire and minimum as five network-order 32-bit
    unsigned integers, concatenated in that order; RDLENGTH is the
    actual total length. For type 15 ``preference`` is a 16-bit
    unsigned integer (bools are never accepted) and ``exchange``
    follows the same absolute ASCII domain name rules as ``name``
    (the root ``"."`` included); RDATA is the preference in network
    byte order followed by the exchange name in uncompressed wire
    form, and RDLENGTH is the actual total length. For type 16
    ``strings`` is a non-empty list
    or tuple of even-length hexadecimal strings (either letter case,
    ``""`` for a zero-length segment), each standing for zero to 255
    raw bytes; RDATA is each segment as a one-octet length followed by
    the raw bytes, in order, and RDLENGTH is the total (never above
    65535 bytes). For type 33 ``priority``, ``weight`` and ``port``
    are 16-bit unsigned integers (bools are never accepted) and
    ``target`` follows the same absolute ASCII domain name rules as
    ``name`` (the root ``"."`` included); RDATA is the three values in
    network byte order followed by the target name in uncompressed
    wire form, and RDLENGTH is the actual total length. Validation is
    completed before any result is
    produced; the caller's object is never mutated. Raises
    DNSArgumentError for any invalid input.
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
        _reject_soa_fields(record)
        _reject_mx_fields(record)
        _reject_srv_fields(record)
        if "address" not in record:
            raise DNSArgumentError("missing field: address")
        if rtype == _TYPE_A:
            rdata = bytes(_parse_ipv4(record["address"]))
        else:
            rdata = _parse_ipv6(record["address"])
    elif rtype == _TYPE_CNAME or rtype == _TYPE_NS or rtype == _TYPE_DNAME:
        if "address" in record:
            raise DNSArgumentError("unknown field: address")
        if "strings" in record:
            raise DNSArgumentError("unknown field: strings")
        _reject_soa_fields(record)
        _reject_mx_fields(record)
        _reject_srv_fields(record)
        if "target" not in record:
            raise DNSArgumentError("missing field: target")
        rdata = encode_name(record["target"])
    elif rtype == _TYPE_SOA:
        if "address" in record:
            raise DNSArgumentError("unknown field: address")
        if "target" in record:
            raise DNSArgumentError("unknown field: target")
        if "strings" in record:
            raise DNSArgumentError("unknown field: strings")
        _reject_mx_fields(record)
        _reject_srv_fields(record)
        rdata = _encode_soa_rdata(record)
    elif rtype == _TYPE_TXT:
        if "address" in record:
            raise DNSArgumentError("unknown field: address")
        if "target" in record:
            raise DNSArgumentError("unknown field: target")
        _reject_soa_fields(record)
        _reject_mx_fields(record)
        _reject_srv_fields(record)
        if "strings" not in record:
            raise DNSArgumentError("missing field: strings")
        rdata = _encode_txt_strings(record["strings"])
    elif rtype == _TYPE_MX:
        if "address" in record:
            raise DNSArgumentError("unknown field: address")
        if "target" in record:
            raise DNSArgumentError("unknown field: target")
        if "strings" in record:
            raise DNSArgumentError("unknown field: strings")
        _reject_soa_fields(record)
        _reject_srv_fields(record)
        if "preference" not in record:
            raise DNSArgumentError("missing field: preference")
        if "exchange" not in record:
            raise DNSArgumentError("missing field: exchange")
        preference = record["preference"]
        _check_uint(preference, "preference", 16)
        rdata = _MX_PREFERENCE_STRUCT.pack(preference) + encode_name(
            record["exchange"]
        )
    elif rtype == _TYPE_SRV:
        if "address" in record:
            raise DNSArgumentError("unknown field: address")
        if "strings" in record:
            raise DNSArgumentError("unknown field: strings")
        _reject_soa_fields(record)
        _reject_mx_fields(record)
        for field_name in ("priority", "weight", "port", "target"):
            if field_name not in record:
                raise DNSArgumentError("missing field: %s" % field_name)
        priority = record["priority"]
        weight = record["weight"]
        port = record["port"]
        _check_uint(priority, "priority", 16)
        _check_uint(weight, "weight", 16)
        _check_uint(port, "port", 16)
        rdata = _SRV_PARAMS_STRUCT.pack(priority, weight, port) + encode_name(
            record["target"]
        )
    else:
        raise DNSArgumentError(
            "field 'type' must be 1 (A), 2 (NS), 5 (CNAME), 6 (SOA),"
            " 15 (MX), 16 (TXT), 28 (AAAA), 33 (SRV) or 39 (DNAME)"
        )
    _check_uint(rclass, "class", 16)
    _check_uint(ttl, "ttl", 32)

    return (
        encoded_name
        + _RECORD_FIXED_STRUCT.pack(rtype, rclass, ttl, len(rdata))
        + rdata
    )


def decode_resource_record(message, offset=0):
    """Read one A, AAAA, CNAME, NS, DNAME, SOA, MX, TXT or SRV resource record from ``message``.

    Returns a ``(record, next_offset)`` tuple: ``record`` is a plain dict
    with keys in the fixed order name, type, class, ttl, address (A and
    AAAA), name, type, class, ttl, target (CNAME, NS and DNAME), name,
    type, class, ttl, mname, rname, serial, refresh, retry, expire,
    minimum (SOA), name, type, class, ttl, preference, exchange (MX),
    name, type, class, ttl, strings (TXT) or name, type, class, ttl,
    priority, weight, port, target (SRV), and
    ``next_offset`` is the first byte after the record's declared RDATA
    in the original message, regardless of any compression pointers
    inside it. The owner name follows the same compression-pointer
    rules as decode_name; an A address is rendered in canonical dotted
    decimal without leading zeros, an AAAA address in canonical IPv6
    text form (lowercase hex, no leading zeros, the longest run of at
    least two zero groups compressed, leftmost run on a tie; IPv4-
    embedded addresses are rendered in the same hexadecimal form).
    CNAME, NS and DNAME targets are decoded as a complete domain name
    inside the declared RDATA (backward compression pointers accepted
    as for decode_name, label case preserved) and the declared RDATA
    region must hold exactly that one name. SOA RDATA is read strictly
    inside the declared RDLENGTH as mname and rname, each decoded as
    for CNAME targets (backward compression pointers accepted, label
    case preserved, their raw encoding kept inside the declared
    region), followed by exactly serial, refresh, retry, expire and
    minimum as five network-order 32-bit unsigned integers;
    next_offset still points at the end of the declared RDATA. MX
    RDATA is read strictly inside the declared RDLENGTH as the
    preference, one network-order 16-bit unsigned integer, followed by
    the exchange decoded as a complete domain name (backward
    compression pointers accepted as for decode_name, label case
    preserved, its raw encoding kept inside the declared region), and
    the parse must end exactly at the end of the declared region. TXT
    RDATA is read strictly inside the declared RDLENGTH as a sequence
    of length-prefixed character-strings (name compression is never
    interpreted there); ``strings`` keeps the segment order and
    renders each segment as lowercase hexadecimal (``""`` for a
    zero-length segment). SRV RDATA is read strictly inside the
    declared RDLENGTH as priority, weight and port, three network-order
    16-bit unsigned integers, followed by the target decoded as a
    complete domain name (backward compression pointers accepted as
    for decode_name, label case preserved, its raw encoding kept
    inside the declared region), and the parse must end exactly at
    the end of the declared region. Raises DNSArgumentError for invalid
    arguments and DNSMessageError for malformed wire data (truncated
    name, fixed fields or RDATA, a TYPE other than A, AAAA, CNAME,
    NS, DNAME, SOA, MX, TXT or SRV, an RDLENGTH other than 4 for A or
    16 for AAAA, a zero CNAME, NS, DNAME, SOA or TXT RDLENGTH, an MX
    RDLENGTH below 2, an SRV RDLENGTH below 6, a CNAME, NS
    or DNAME RDATA region that does not contain exactly one domain
    name, an SOA RDATA region that does not contain exactly mname,
    rname and five 32-bit integers, an MX RDATA region that does not
    contain exactly the preference and one domain name, a TXT RDATA
    region that does not decompose exactly into complete
    character-strings, an SRV RDATA region that does not contain
    exactly the three 16-bit integers and one domain name, or a
    malformed
    name or compression pointer); no partial result is returned on
    failure.
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
    elif (
        rtype == _TYPE_CNAME
        or rtype == _TYPE_NS
        or rtype == _TYPE_DNAME
        or rtype == _TYPE_SOA
        or rtype == _TYPE_MX
        or rtype == _TYPE_TXT
        or rtype == _TYPE_SRV
    ):
        expected_rdlength = None
    else:
        raise DNSMessageError(
            "unsupported record type: %d"
            " (only A, AAAA, CNAME, NS, DNAME, SOA, MX, TXT and SRV"
            " are supported)"
            % rtype
        )

    rdata_end = fixed_end + rdlength
    if rtype == _TYPE_TXT:
        if rdlength == 0:
            raise DNSMessageError("TXT record RDLENGTH must not be zero")
        if rdata_end > len(message):
            raise DNSMessageError("truncated RDATA")
        # The declared region must decompose exactly into length-prefixed
        # character-strings; no name compression is interpreted here.
        strings = []
        cursor = fixed_end
        while cursor < rdata_end:
            segment_end = cursor + 1 + message[cursor]
            if segment_end > rdata_end:
                raise DNSMessageError(
                    "TXT character-string extends beyond the declared RDATA"
                )
            strings.append(message[cursor + 1 : segment_end].hex())
            cursor = segment_end
        return {
            "name": name,
            "type": rtype,
            "class": rclass,
            "ttl": ttl,
            "strings": strings,
        }, rdata_end

    if rtype == _TYPE_CNAME or rtype == _TYPE_NS or rtype == _TYPE_DNAME:
        if rtype == _TYPE_CNAME:
            type_label = "CNAME"
        elif rtype == _TYPE_NS:
            type_label = "NS"
        else:
            type_label = "DNAME"
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

    if rtype == _TYPE_SOA:
        if rdlength == 0:
            raise DNSMessageError("SOA record RDLENGTH must not be zero")
        if rdata_end > len(message):
            raise DNSMessageError("truncated RDATA")
        # The declared region holds mname, rname and exactly five
        # network-order 32-bit integers in that order; each name's raw
        # encoding (a compression pointer included) must stay inside it.
        mname, mname_end = decode_name(message, fixed_end)
        if mname_end >= rdata_end:
            raise DNSMessageError(
                "SOA RDATA must contain mname, rname and exactly five"
                " 32-bit unsigned integers"
            )
        rname, rname_end = decode_name(message, mname_end)
        if rname_end > rdata_end:
            raise DNSMessageError("SOA rname extends beyond the declared RDATA")
        if rname_end + _SOA_TIMERS_LENGTH != rdata_end:
            raise DNSMessageError(
                "SOA RDATA must contain mname, rname and exactly five"
                " 32-bit unsigned integers"
            )
        serial, refresh, retry, expire, minimum = _SOA_TIMERS_STRUCT.unpack(
            message[rname_end:rdata_end]
        )
        return {
            "name": name,
            "type": rtype,
            "class": rclass,
            "ttl": ttl,
            "mname": mname,
            "rname": rname,
            "serial": serial,
            "refresh": refresh,
            "retry": retry,
            "expire": expire,
            "minimum": minimum,
        }, rdata_end

    if rtype == _TYPE_MX:
        if rdlength < _MX_PREFERENCE_LENGTH:
            raise DNSMessageError(
                "MX record RDLENGTH must be at least %d" % _MX_PREFERENCE_LENGTH
            )
        if rdata_end > len(message):
            raise DNSMessageError("truncated RDATA")
        # The declared region holds the preference as one network-order
        # 16-bit unsigned integer followed by exactly one complete domain
        # name; the name's raw encoding must stay inside the region.
        (preference,) = _MX_PREFERENCE_STRUCT.unpack(
            message[fixed_end : fixed_end + _MX_PREFERENCE_LENGTH]
        )
        exchange_offset = fixed_end + _MX_PREFERENCE_LENGTH
        if exchange_offset >= rdata_end:
            raise DNSMessageError(
                "MX RDATA must contain exactly the preference and one domain name"
            )
        exchange, exchange_end = decode_name(message, exchange_offset)
        if exchange_end != rdata_end:
            raise DNSMessageError(
                "MX RDATA must contain exactly the preference and one domain name"
            )
        return {
            "name": name,
            "type": rtype,
            "class": rclass,
            "ttl": ttl,
            "preference": preference,
            "exchange": exchange,
        }, rdata_end

    if rtype == _TYPE_SRV:
        if rdlength < _SRV_PARAMS_LENGTH:
            raise DNSMessageError(
                "SRV record RDLENGTH must be at least %d" % _SRV_PARAMS_LENGTH
            )
        if rdata_end > len(message):
            raise DNSMessageError("truncated RDATA")
        # The declared region holds priority, weight and port as three
        # network-order 16-bit unsigned integers followed by exactly one
        # complete domain name; the name's raw encoding must stay inside
        # the region.
        priority, weight, port = _SRV_PARAMS_STRUCT.unpack(
            message[fixed_end : fixed_end + _SRV_PARAMS_LENGTH]
        )
        target_offset = fixed_end + _SRV_PARAMS_LENGTH
        if target_offset >= rdata_end:
            raise DNSMessageError(
                "SRV RDATA must contain exactly priority, weight, port"
                " and one domain name"
            )
        target, target_end = decode_name(message, target_offset)
        if target_end != rdata_end:
            raise DNSMessageError(
                "SRV RDATA must contain exactly priority, weight, port"
                " and one domain name"
            )
        return {
            "name": name,
            "type": rtype,
            "class": rclass,
            "ttl": ttl,
            "priority": priority,
            "weight": weight,
            "port": port,
            "target": target,
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
    and arcount resource records (A, AAAA, CNAME, NS, DNAME, SOA, MX,
    TXT and SRV only) are read
    from the same bytes; names may use the legal backward compression
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


_DNAME_FIELD_SET = frozenset(DNAME_RECORD_FIELDS)


def _split_labels(name):
    # ``name`` is a validated absolute name; the root (".") yields no labels.
    body = name[:-1]
    return body.split(".") if body else []


def synthesize_dname_cname(qname, dname, delegation_cuts):
    """Synthesize the CNAME record implied by a DNAME record (RFC 6672).

    ``qname`` is the query name as an absolute ASCII domain name,
    ``dname`` a mapping with exactly the keys name, type, class, ttl and
    target of a DNAME record (``type`` must be the integer 39) and
    ``delegation_cuts`` a sequence of at most 128 absolute ASCII domain
    names. Names are matched label by label with ASCII case-insensitive
    comparison, never as plain string suffixes. Returns a mapping with
    the fixed key order status, cname: ``status`` is "synthesized" when
    ``qname`` lies strictly below the DNAME owner name and no delegation
    cut lies on the label path from the owner name to ``qname`` (both
    endpoints included), "name-too-long" when synthesis applies but the
    synthesized target would exceed 255 wire bytes, and "not-applicable"
    otherwise (``qname`` equal to the owner name or on a different
    branch, or a delegation cut on the path). Only "synthesized" comes
    with a ``cname`` mapping (fixed key order name, type, class, ttl,
    target: the original ``qname``, the integer 5, and the class, ttl
    and target of the DNAME record with the ``qname`` prefix labels
    substituted for the owner name, each side keeping its original
    case); the other statuses map ``cname`` to None. All validation is
    completed before any result is produced and the inputs are never
    mutated. Raises DNSArgumentError for any invalid input.
    """
    # Validate everything before producing any result.
    encode_name(qname)

    if not isinstance(dname, Mapping):
        raise DNSArgumentError("dname must be a mapping")
    for field_name in DNAME_RECORD_FIELDS:
        if field_name not in dname:
            raise DNSArgumentError("missing field: %s" % field_name)
    for key in dname:
        if key not in _DNAME_FIELD_SET:
            raise DNSArgumentError("unknown field: %s" % key)
    encode_name(dname["name"])
    rtype = dname["type"]
    _check_uint(rtype, "type", 16)
    if rtype != _TYPE_DNAME:
        raise DNSArgumentError("field 'type' must be 39 (DNAME)")
    _check_uint(dname["class"], "class", 16)
    _check_uint(dname["ttl"], "ttl", 32)
    encode_name(dname["target"])

    if not isinstance(delegation_cuts, (list, tuple)):
        raise DNSArgumentError("delegation_cuts must be a sequence")
    if len(delegation_cuts) > MAX_DELEGATION_CUTS:
        raise DNSArgumentError(
            "delegation_cuts exceeds %d entries" % MAX_DELEGATION_CUTS
        )
    cut_labels = []
    for cut in delegation_cuts:
        encode_name(cut)
        cut_labels.append([label.lower() for label in _split_labels(cut)])

    qname_labels = _split_labels(qname)
    owner_labels = _split_labels(dname["name"])
    target_labels = _split_labels(dname["target"])
    lower_qname = [label.lower() for label in qname_labels]
    lower_owner = [label.lower() for label in owner_labels]

    result = {"status": "not-applicable", "cname": None}

    prefix_length = len(qname_labels) - len(owner_labels)
    if prefix_length <= 0 or lower_qname[prefix_length:] != lower_owner:
        # qname is the owner name itself or belongs to another branch.
        return result

    # A cut on the label path from the owner name to qname (endpoints
    # included) is a suffix of qname of len(owner)..len(qname) labels.
    for cut in cut_labels:
        depth = len(cut)
        if len(owner_labels) <= depth <= len(qname_labels) and cut == lower_qname[
            len(qname_labels) - depth :
        ]:
            return result

    synthesized = qname_labels[:prefix_length] + target_labels
    wire_length = 1  # the terminating zero length octet
    for label in synthesized:
        wire_length += 1 + len(label.encode("ascii"))
    if wire_length > MAX_NAME_LENGTH:
        result["status"] = "name-too-long"
        return result

    result["status"] = "synthesized"
    result["cname"] = {
        "name": qname,
        "type": _TYPE_CNAME,
        "class": dname["class"],
        "ttl": dname["ttl"],
        "target": ".".join(synthesized) + ".",
    }
    return result


# Fixed key order of an aged record, by record type.
_AGE_RECORD_FIELDS = {
    _TYPE_A: RECORD_FIELDS,
    _TYPE_AAAA: RECORD_FIELDS,
    _TYPE_NS: NS_RECORD_FIELDS,
    _TYPE_CNAME: CNAME_RECORD_FIELDS,
    _TYPE_DNAME: DNAME_RECORD_FIELDS,
    _TYPE_SOA: SOA_RECORD_FIELDS,
    _TYPE_MX: MX_RECORD_FIELDS,
    _TYPE_TXT: TXT_RECORD_FIELDS,
    _TYPE_SRV: SRV_RECORD_FIELDS,
}


def _validate_cached_records(records, name="records"):
    # Shared snapshot validation for age_cached_records/lookup_cache:
    # shape, count and every record's public rules are checked here.
    if not isinstance(records, (list, tuple)):
        raise DNSArgumentError("%s must be a sequence" % name)
    if len(records) > MAX_CACHED_RECORDS:
        raise DNSArgumentError(
            "%s exceeds %d entries" % (name, MAX_CACHED_RECORDS)
        )
    for record in records:
        encode_resource_record(record)


def _check_cache_timestamps(stored_at, now):
    _check_uint(stored_at, "stored_at", 64)
    _check_uint(now, "now", 64)
    if now < stored_at:
        raise DNSArgumentError("now must not be earlier than stored_at")


def _age_validated_records(records, elapsed):
    # Shared aging pass over already-validated records. Returns
    # (aged_records, expired_count); each surviving record is a new
    # mapping sharing no container with the caller's record.
    aged = []
    expired = 0
    for record in records:
        ttl = record["ttl"]
        if ttl <= elapsed:
            expired += 1
            continue
        fresh = {}
        for field_name in _AGE_RECORD_FIELDS[record["type"]]:
            if field_name == "ttl":
                fresh["ttl"] = ttl - elapsed
            elif field_name == "strings":
                # A fresh list so the result shares no container with
                # the caller's record.
                fresh["strings"] = list(record["strings"])
            else:
                fresh[field_name] = record[field_name]
        aged.append(fresh)
    return aged, expired


def age_cached_records(records, stored_at, now):
    """Age a cache snapshot of resource records by an explicit time pair.

    ``records`` is a list or tuple of at most 128 resource record
    mappings, each following the encode_resource_record rules (A, AAAA,
    CNAME, NS, DNAME, SOA, MX, TXT or SRV); ``stored_at`` and ``now`` are
    non-negative 64-bit integer timestamps in seconds (bools are never
    accepted) and ``now`` must not be earlier than ``stored_at``. No
    clock is read: the elapsed time is exactly ``now - stored_at``.
    Every record is fully validated before any result is produced.
    Records whose original TTL is greater than the elapsed time are kept
    in input order with the TTL replaced by the remaining lifetime;
    records whose TTL is less than or equal to the elapsed time expire
    and do not appear in the result (a zero TTL therefore expires even
    when ``now`` equals ``stored_at``). Returns a new mapping with the
    fixed key order records, expired: ``records`` holds one new mapping
    per surviving record in the fixed key order of its type, every
    field except ``ttl`` copied unchanged, and ``expired`` is the
    number of dropped records. The input records and containers are
    never mutated and identical inputs produce identical results.
    Raises DNSArgumentError for any invalid input.
    """
    _validate_cached_records(records)
    _check_cache_timestamps(stored_at, now)

    aged, expired = _age_validated_records(records, now - stored_at)

    return {"records": aged, "expired": expired}


def lookup_cache(records, stored_at, now, qname, qtype, qclass):
    """Answer a DNS question against an aged cache snapshot.

    ``records`` is a list or tuple of at most 128 resource record
    mappings following the encode_resource_record rules (A, AAAA,
    CNAME, NS, DNAME, SOA, MX, TXT or SRV); ``stored_at`` and ``now``
    are
    non-negative 64-bit integer timestamps in seconds (bools are never
    accepted) and ``now`` must not be earlier than ``stored_at``.
    ``qname`` is an absolute ASCII domain name, ``qtype`` one of the
    supported record types 1 (A), 2 (NS), 5 (CNAME), 6 (SOA), 15 (MX),
    16 (TXT), 28 (AAAA), 33 (SRV) or 39 (DNAME) and ``qclass`` a 16-bit
    unsigned
    integer (bools are never accepted). The whole snapshot is fully
    validated first and the timestamps are checked before the question
    is validated; no partial result is ever produced. Every record is
    then aged uniformly by ``now - stored_at`` exactly as in
    age_cached_records (a TTL less than or equal to the elapsed time
    expires, so a zero TTL expires even when ``now`` equals
    ``stored_at``). Among the surviving records those whose owner name,
    type and class all match the question are selected: names are
    compared label by label with ASCII case-insensitive matching,
    never as plain string prefixes or suffixes, while type and class
    are exact integer matches. Returns a new mapping with the fixed
    key order status, records, expired: ``status`` is "hit" when at
    least one record matches and "miss" otherwise (an empty snapshot
    is a deterministic miss), ``records`` holds the matching aged
    records in input order with each type's fixed key order, the
    original name case and every field value except the remaining
    TTL preserved, and ``expired`` is the number of records that
    expired across the whole snapshot during this aging pass. The
    input containers, records and TXT strings are never mutated and
    identical inputs produce identical results. Raises
    DNSArgumentError for any invalid input.
    """
    # Validate the whole snapshot before the question, as contracted.
    _validate_cached_records(records)
    _check_cache_timestamps(stored_at, now)

    encode_name(qname)
    _check_uint(qtype, "qtype", 16)
    if qtype not in _SUPPORTED_RECORD_TYPES:
        raise DNSArgumentError(
            "field 'qtype' must be 1 (A), 2 (NS), 5 (CNAME), 6 (SOA),"
            " 15 (MX), 16 (TXT), 28 (AAAA), 33 (SRV) or 39 (DNAME)"
        )
    _check_uint(qclass, "qclass", 16)

    aged, expired = _age_validated_records(records, now - stored_at)

    wanted_labels = [label.lower() for label in _split_labels(qname)]
    matches = []
    for record in aged:
        if record["type"] != qtype or record["class"] != qclass:
            continue
        owner_labels = [label.lower() for label in _split_labels(record["name"])]
        if owner_labels != wanted_labels:
            continue
        matches.append(record)

    return {
        "status": "hit" if matches else "miss",
        "records": matches,
        "expired": expired,
    }


def _rrset_key(record):
    # Identity of an RRset for cache replacement: the owner name as
    # lowercase DNS labels, the exact type and the exact class.
    return tuple(label.lower() for label in _split_labels(record["name"])), record[
        "type"
    ], record["class"]


def _copy_cached_record(record):
    # Rebuild a validated record in its type's fixed key order so the
    # result shares no container (TXT strings included) with the caller.
    fresh = {}
    for field_name in _AGE_RECORD_FIELDS[record["type"]]:
        if field_name == "strings":
            fresh["strings"] = list(record["strings"])
        else:
            fresh[field_name] = record[field_name]
    return fresh


def update_cache(records, stored_at, now, incoming):
    """Build an updated cache snapshot from an old one and new records.

    ``records`` and ``incoming`` are each a list or tuple of at most 128
    resource record mappings following the encode_resource_record rules
    (A, AAAA, CNAME, NS, DNAME, SOA, MX, TXT or SRV); ``stored_at`` and
    ``now`` are non-negative 64-bit integer timestamps in seconds (bools
    are never accepted) and ``now`` must not be earlier than
    ``stored_at``. Every input is fully validated before any result is
    produced and no clock is read. The old snapshot is aged to ``now``
    exactly as in age_cached_records: a TTL less than or equal to the
    elapsed time expires, so a zero TTL expires even when ``now`` equals
    ``stored_at``. Each RRset appearing in ``incoming`` then replaces
    every still-live aged record with the same owner name, type and
    class: owner names are compared label by label with ASCII
    case-insensitive matching while type and class are exact integer
    matches; an RRset whose incoming records all carry a zero TTL still
    removes the matching aged records. Surviving aged records that no
    incoming RRset replaces keep their original relative order and
    remaining TTL; afterwards the positive-TTL incoming records (the
    incoming TTL is taken as the new remaining lifetime) are appended in
    input order, while zero-TTL incoming records never enter the
    snapshot. Returns a new mapping with the fixed key order records,
    stored_at, expired, replaced: ``stored_at`` equals ``now``,
    ``expired`` counts only the records dropped by aging and ``replaced``
    counts only the live aged records removed by RRset replacement; each
    record keeps its type's fixed key order. When the merged snapshot
    would hold more than 128 records DNSArgumentError is raised and no
    partial result is returned. The input containers, records and TXT
    strings are never mutated and identical inputs produce identical
    results. Raises DNSArgumentError for any invalid input.
    """
    # Validate the old snapshot, the timestamps and then the incoming
    # batch before producing any result.
    _validate_cached_records(records)
    _check_cache_timestamps(stored_at, now)
    _validate_cached_records(incoming, "incoming")

    aged, expired = _age_validated_records(records, now - stored_at)

    # The set of RRset identities present among the incoming records;
    # every such identity replaces the matching aged records.
    incoming_keys = {_rrset_key(record) for record in incoming}

    survivors = []
    replaced = 0
    for record in aged:
        if _rrset_key(record) in incoming_keys:
            replaced += 1
            continue
        survivors.append(record)

    # Positive-TTL incoming records are appended in input order; a zero
    # TTL only deletes and never enters the snapshot.
    additions = [
        _copy_cached_record(record)
        for record in incoming
        if record["ttl"] > 0
    ]

    merged = survivors + additions
    if len(merged) > MAX_CACHED_RECORDS:
        raise DNSArgumentError(
            "merged cache exceeds %d records" % MAX_CACHED_RECORDS
        )

    return {
        "records": merged,
        "stored_at": now,
        "expired": expired,
        "replaced": replaced,
    }


def _validate_referral_records(records, name):
    # Shared section validation for select_referral: shape, count and
    # every record's public rules are checked here, including records
    # that the selection will later ignore.
    if not isinstance(records, (list, tuple)):
        raise DNSArgumentError("%s must be a sequence" % name)
    if len(records) > MAX_REFERRAL_RECORDS:
        raise DNSArgumentError(
            "%s exceeds %d entries" % (name, MAX_REFERRAL_RECORDS)
        )
    for record in records:
        encode_resource_record(record)


def _labels_at_or_below(name_labels, ancestor_labels):
    # True when the already-lowercased ``name_labels`` equal
    # ``ancestor_labels`` or lie below them in the DNS tree.
    depth = len(ancestor_labels)
    return (
        len(name_labels) >= depth
        and name_labels[len(name_labels) - depth :] == ancestor_labels
    )


def select_referral(qname, qclass, authorities, additionals):
    """Extract a delegation referral from authority and additional data.

    ``qname`` is the query name as an absolute ASCII domain name and
    ``qclass`` a 16-bit unsigned integer (bools are never accepted).
    ``authorities`` and ``additionals`` are each a list or tuple of at
    most 128 resource record mappings following the
    encode_resource_record rules (A, AAAA, CNAME, NS, DNAME, SOA, MX,
    TXT or SRV); every record is fully validated before any result is
    produced, including records the selection will ignore. Names are
    matched label by label with ASCII case-insensitive comparison,
    never as plain string prefixes or suffixes.

    The delegation cut is the owner name of the NS records in
    ``authorities`` whose class equals ``qclass`` and whose owner name
    lies on the label ancestor path of ``qname`` (``qname`` itself
    included), choosing the owner with the most labels. Every NS record
    of that class and owner name enters ``nameservers`` in input order
    and ``cut`` keeps the owner name of the first such record with its
    original case. The glue is built from ``additionals``: the A and
    AAAA records of that class whose owner name matches the target of
    a selected nameserver and lies at or below the cut, in input order;
    address records outside the cut, records of other types and
    unrelated records are ignored. Returns a new mapping with the fixed
    key order status, cut, nameservers, glue: ``status`` is "referral"
    when a cut was found and "no-referral" otherwise, in which case
    ``cut`` is None and both sequences are empty. Each returned record
    is a new mapping in its type's fixed key order with the original
    field values; the input containers, records and TXT strings are
    never mutated and identical inputs produce identical results.
    Raises DNSArgumentError for any invalid input.
    """
    # Validate everything before producing any result.
    encode_name(qname)
    _check_uint(qclass, "qclass", 16)
    _validate_referral_records(authorities, "authorities")
    _validate_referral_records(additionals, "additionals")

    qname_labels = [label.lower() for label in _split_labels(qname)]

    # The closest enclosing NS owner name wins the cut.
    cut_labels = None
    for record in authorities:
        if record["type"] != _TYPE_NS or record["class"] != qclass:
            continue
        owner_labels = [label.lower() for label in _split_labels(record["name"])]
        if not _labels_at_or_below(qname_labels, owner_labels):
            continue
        if cut_labels is None or len(owner_labels) > len(cut_labels):
            cut_labels = owner_labels

    if cut_labels is None:
        return {"status": "no-referral", "cut": None, "nameservers": [], "glue": []}

    cut = None
    nameservers = []
    for record in authorities:
        if record["type"] != _TYPE_NS or record["class"] != qclass:
            continue
        owner_labels = [label.lower() for label in _split_labels(record["name"])]
        if owner_labels != cut_labels:
            continue
        if cut is None:
            cut = record["name"]
        nameservers.append(_copy_cached_record(record))

    targets = set()
    for record in nameservers:
        targets.add(tuple(label.lower() for label in _split_labels(record["target"])))

    glue = []
    for record in additionals:
        if record["type"] != _TYPE_A and record["type"] != _TYPE_AAAA:
            continue
        if record["class"] != qclass:
            continue
        owner_labels = [label.lower() for label in _split_labels(record["name"])]
        if tuple(owner_labels) not in targets:
            continue
        if not _labels_at_or_below(owner_labels, cut_labels):
            continue
        glue.append(_copy_cached_record(record))

    return {
        "status": "referral",
        "cut": cut,
        "nameservers": nameservers,
        "glue": glue,
    }


_TRANSPORTS = frozenset(("udp", "tcp"))


def plan_truncation_retry(query_header, response_header, transport):
    """Decide whether a truncated response triggers a retry over TCP.

    ``query_header`` and ``response_header`` are header mappings
    following the encode_header rules (exactly the HEADER_FIELDS keys
    with their usual types and ranges); the query header's ``qr`` must
    be False and the response header's ``qr`` must be True.
    ``transport`` is the string "udp" or "tcp", the transport of the
    exchange that produced ``response_header``. Both headers are fully
    validated before any result is produced and the inputs are never
    mutated. Only the two fixed-size headers and the transport name are
    consulted: no message body, clock or network is read and no hidden
    state is kept, so identical inputs produce identical results.

    Returns a new mapping with the fixed key order status,
    next_transport: when the two headers differ in ``id`` or ``opcode``
    the response does not belong to the query and the result is
    "unmatched" with ``next_transport`` None; when they match and the
    response ``tc`` is False the response is usable as-is and the
    result is "accept" with ``next_transport`` None, regardless of the
    transport and ``rcode``; when they match, ``tc`` is True and
    ``transport`` is "udp" the result is "retry" with ``next_transport``
    "tcp"; when the same truncation flag arrives over "tcp" the result
    is "truncated" with ``next_transport`` None, ending automatic
    retries. Raises DNSArgumentError for any invalid input.
    """
    # Validate both headers completely before any role or transport
    # check; encode_header performs the full field validation without
    # mutating its argument and its wire result is discarded here.
    encode_header(query_header)
    encode_header(response_header)

    if not isinstance(transport, str) or transport not in _TRANSPORTS:
        raise DNSArgumentError("transport must be 'udp' or 'tcp'")

    if query_header["qr"] is not False:
        raise DNSArgumentError("query header field 'qr' must be false")
    if response_header["qr"] is not True:
        raise DNSArgumentError("response header field 'qr' must be true")

    result = {"status": None, "next_transport": None}

    if (
        query_header["id"] != response_header["id"]
        or query_header["opcode"] != response_header["opcode"]
    ):
        result["status"] = "unmatched"
        return result

    if not response_header["tc"]:
        result["status"] = "accept"
        return result

    if transport == "udp":
        result["status"] = "retry"
        result["next_transport"] = "tcp"
        return result

    result["status"] = "truncated"
    return result


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


_SYNTHESIZE_FIELDS = ("qname", "dname", "delegation_cuts")
_SYNTHESIZE_FIELD_SET = frozenset(_SYNTHESIZE_FIELDS)


def _cmd_synthesize_dname():
    obj = _read_json_object()
    for field_name in _SYNTHESIZE_FIELDS:
        if field_name not in obj:
            raise DNSArgumentError("missing field: %s" % field_name)
    for key in obj:
        if key not in _SYNTHESIZE_FIELD_SET:
            raise DNSArgumentError("unknown field: %s" % key)
    result = synthesize_dname_cname(
        obj["qname"], obj["dname"], obj["delegation_cuts"]
    )
    output = json.dumps(result, separators=(",", ":"))
    sys.stdout.write(output + "\n")
    return 0


_AGE_CACHE_FIELDS = ("records", "stored_at", "now")
_AGE_CACHE_FIELD_SET = frozenset(_AGE_CACHE_FIELDS)


def _cmd_age_cache():
    obj = _read_json_object()
    for field_name in _AGE_CACHE_FIELDS:
        if field_name not in obj:
            raise DNSArgumentError("missing field: %s" % field_name)
    for key in obj:
        if key not in _AGE_CACHE_FIELD_SET:
            raise DNSArgumentError("unknown field: %s" % key)
    result = age_cached_records(obj["records"], obj["stored_at"], obj["now"])
    output = json.dumps(result, separators=(",", ":"))
    sys.stdout.write(output + "\n")
    return 0


_LOOKUP_CACHE_FIELDS = ("records", "stored_at", "now", "qname", "qtype", "qclass")
_LOOKUP_CACHE_FIELD_SET = frozenset(_LOOKUP_CACHE_FIELDS)


def _cmd_lookup_cache():
    obj = _read_json_object()
    for field_name in _LOOKUP_CACHE_FIELDS:
        if field_name not in obj:
            raise DNSArgumentError("missing field: %s" % field_name)
    for key in obj:
        if key not in _LOOKUP_CACHE_FIELD_SET:
            raise DNSArgumentError("unknown field: %s" % key)
    result = lookup_cache(
        obj["records"],
        obj["stored_at"],
        obj["now"],
        obj["qname"],
        obj["qtype"],
        obj["qclass"],
    )
    output = json.dumps(result, separators=(",", ":"))
    sys.stdout.write(output + "\n")
    return 0


_UPDATE_CACHE_FIELDS = ("records", "stored_at", "now", "incoming")
_UPDATE_CACHE_FIELD_SET = frozenset(_UPDATE_CACHE_FIELDS)


def _cmd_update_cache():
    obj = _read_json_object()
    for field_name in _UPDATE_CACHE_FIELDS:
        if field_name not in obj:
            raise DNSArgumentError("missing field: %s" % field_name)
    for key in obj:
        if key not in _UPDATE_CACHE_FIELD_SET:
            raise DNSArgumentError("unknown field: %s" % key)
    result = update_cache(
        obj["records"],
        obj["stored_at"],
        obj["now"],
        obj["incoming"],
    )
    output = json.dumps(result, separators=(",", ":"))
    sys.stdout.write(output + "\n")
    return 0


_SELECT_REFERRAL_FIELDS = ("qname", "qclass", "authorities", "additionals")
_SELECT_REFERRAL_FIELD_SET = frozenset(_SELECT_REFERRAL_FIELDS)


def _cmd_select_referral():
    obj = _read_json_object()
    for field_name in _SELECT_REFERRAL_FIELDS:
        if field_name not in obj:
            raise DNSArgumentError("missing field: %s" % field_name)
    for key in obj:
        if key not in _SELECT_REFERRAL_FIELD_SET:
            raise DNSArgumentError("unknown field: %s" % key)
    result = select_referral(
        obj["qname"],
        obj["qclass"],
        obj["authorities"],
        obj["additionals"],
    )
    output = json.dumps(result, separators=(",", ":"))
    sys.stdout.write(output + "\n")
    return 0


_PLAN_TRUNCATION_FIELDS = ("query_header", "response_header", "transport")
_PLAN_TRUNCATION_FIELD_SET = frozenset(_PLAN_TRUNCATION_FIELDS)


def _cmd_plan_truncation_retry():
    obj = _read_json_object()
    for field_name in _PLAN_TRUNCATION_FIELDS:
        if field_name not in obj:
            raise DNSArgumentError("missing field: %s" % field_name)
    for key in obj:
        if key not in _PLAN_TRUNCATION_FIELD_SET:
            raise DNSArgumentError("unknown field: %s" % key)
    result = plan_truncation_retry(
        obj["query_header"],
        obj["response_header"],
        obj["transport"],
    )
    output = json.dumps(result, separators=(",", ":"))
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
        help="read a UTF-8 JSON A/AAAA/CNAME/NS/DNAME/SOA/MX/TXT/SRV record object from stdin and print its hex wire form",
    )
    subparsers.add_parser(
        "decode-record",
        help="read hexadecimal wire bytes from stdin and print the A/AAAA/CNAME/NS/DNAME/SOA/MX/TXT/SRV record as JSON",
    )
    subparsers.add_parser(
        "encode-message",
        help="read a UTF-8 JSON message object from stdin and print its hex wire form",
    )
    subparsers.add_parser(
        "decode-message",
        help="read hexadecimal wire bytes from stdin and print the full message as JSON",
    )
    subparsers.add_parser(
        "synthesize-dname",
        help="read a UTF-8 JSON object with qname, dname and delegation_cuts from stdin and print the synthesis result as JSON",
    )
    subparsers.add_parser(
        "age-cache",
        help="read a UTF-8 JSON object with records, stored_at and now from stdin and print the aged cache snapshot as JSON",
    )
    subparsers.add_parser(
        "lookup-cache",
        help="read a UTF-8 JSON object with records, stored_at, now, qname, qtype and qclass from stdin and print the cache lookup result as JSON",
    )
    subparsers.add_parser(
        "update-cache",
        help="read a UTF-8 JSON object with records, stored_at, now and incoming from stdin and print the updated cache snapshot as JSON",
    )
    subparsers.add_parser(
        "select-referral",
        help="read a UTF-8 JSON object with qname, qclass, authorities and additionals from stdin and print the referral selection as JSON",
    )
    subparsers.add_parser(
        "plan-truncation-retry",
        help="read a UTF-8 JSON object with query_header, response_header and transport from stdin and print the truncation retry decision as JSON",
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
        if args.command == "decode-message":
            return _cmd_decode_message()
        if args.command == "synthesize-dname":
            return _cmd_synthesize_dname()
        if args.command == "age-cache":
            return _cmd_age_cache()
        if args.command == "lookup-cache":
            return _cmd_lookup_cache()
        if args.command == "update-cache":
            return _cmd_update_cache()
        if args.command == "select-referral":
            return _cmd_select_referral()
        return _cmd_plan_truncation_retry()
    except (DNSArgumentError, DNSMessageError) as exc:
        return _write_error(exc)


if __name__ == "__main__":
    sys.exit(main())
