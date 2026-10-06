"""DNS message header encoder/decoder.

Public API:
    encode_header(fields) -> bytes
    decode_header(data) -> dict
    DNSArgumentError
    DNSMessageError

Only the Python standard library is used. Importing this module performs no
file I/O, network access, or clock reads.
"""

import argparse
import json
import struct
import sys
from collections.abc import Mapping

__all__ = [
    "encode_header",
    "decode_header",
    "DNSArgumentError",
    "DNSMessageError",
]

# Fixed field order, used for validation, encoding, decoding, and JSON output.
FIELD_NAMES = (
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
_FIELD_SET = frozenset(FIELD_NAMES)

# The five single-bit flags only accept bool.
_FLAG_FIELDS = frozenset(("qr", "aa", "tc", "rd", "ra"))

# Bit width of each unsigned integer field.
_INT_BITS = {
    "id": 16,
    "opcode": 4,
    "z": 3,
    "rcode": 4,
    "qdcount": 16,
    "ancount": 16,
    "nscount": 16,
    "arcount": 16,
}

HEADER_LENGTH = 12
_MAX_INPUT_BYTES = 4096


class DNSArgumentError(ValueError):
    """A caller-supplied argument is missing, unknown, mistyped, or invalid."""


class DNSMessageError(ValueError):
    """Wire data is malformed (wrong length or otherwise undecodable)."""


def _check_flag(value, name):
    if not isinstance(value, bool):
        raise DNSArgumentError("field %r must be a bool" % name)


def _check_uint(value, name, bits):
    # bool is a subclass of int but is never accepted as an integer.
    if isinstance(value, bool) or not isinstance(value, int):
        raise DNSArgumentError("field %r must be an unsigned integer" % name)
    if not 0 <= value < (1 << bits):
        raise DNSArgumentError(
            "field %r must fit in %d unsigned bits" % (name, bits)
        )


def encode_header(fields):
    """Encode a mapping of header fields into a 12-byte DNS header.

    All validation completes before any result is produced; the caller's
    object is never modified.
    """
    if not isinstance(fields, Mapping):
        raise DNSArgumentError("header fields must be a mapping")
    if set(fields) != _FIELD_SET:
        raise DNSArgumentError("header fields must match the defined field set")

    # Validate in fixed order so repeated identical input behaves identically.
    for name in FIELD_NAMES:
        value = fields[name]
        if name in _FLAG_FIELDS:
            _check_flag(value, name)
        else:
            _check_uint(value, name, _INT_BITS[name])

    byte2 = (
        (int(fields["qr"]) << 7)
        | (fields["opcode"] << 3)
        | (int(fields["aa"]) << 2)
        | (int(fields["tc"]) << 1)
        | int(fields["rd"])
    )
    byte3 = (int(fields["ra"]) << 7) | (fields["z"] << 4) | fields["rcode"]
    flags = (byte2 << 8) | byte3

    return struct.pack(
        "!HHHHHH",
        fields["id"],
        flags,
        fields["qdcount"],
        fields["ancount"],
        fields["nscount"],
        fields["arcount"],
    )


def decode_header(data):
    """Decode exactly 12 wire bytes into an ordered dict of header fields."""
    if not isinstance(data, bytes):
        raise DNSArgumentError("wire data must be bytes")
    if len(data) != HEADER_LENGTH:
        raise DNSMessageError("header must be exactly 12 bytes")

    (
        identifier,
        flags,
        qdcount,
        ancount,
        nscount,
        arcount,
    ) = struct.unpack("!HHHHHH", data)

    byte2 = (flags >> 8) & 0xFF
    byte3 = flags & 0xFF

    return {
        "id": identifier,
        "qr": bool((byte2 >> 7) & 1),
        "opcode": (byte2 >> 3) & 0x0F,
        "aa": bool((byte2 >> 2) & 1),
        "tc": bool((byte2 >> 1) & 1),
        "rd": bool(byte2 & 1),
        "ra": bool((byte3 >> 7) & 1),
        "z": (byte3 >> 4) & 0x07,
        "rcode": byte3 & 0x0F,
        "qdcount": qdcount,
        "ancount": ancount,
        "nscount": nscount,
        "arcount": arcount,
    }


# --------------------------------------------------------------------------- #
# Command line interface
# --------------------------------------------------------------------------- #


def _fail(kind, message, exit_code):
    sys.stderr.write(
        json.dumps(
            {"error": kind, "message": message},
            separators=(",", ":"),
        )
        + "\n"
    )
    raise SystemExit(exit_code)


def _read_stdin():
    # Reading at most limit+1 bytes bounds memory use regardless of stream size.
    data = sys.stdin.buffer.read(_MAX_INPUT_BYTES + 1)
    if len(data) > _MAX_INPUT_BYTES:
        _fail("argument", "input exceeds 4096 bytes", 2)
    return data


def _read_utf8():
    try:
        return _read_stdin().decode("utf-8")
    except UnicodeDecodeError:
        _fail("argument", "input is not valid UTF-8", 2)


def _write_success(payload):
    sys.stdout.write(json.dumps(payload, separators=(",", ":")) + "\n")


def _cmd_encode_header():
    text = _read_utf8().strip()
    try:
        obj, end = json.JSONDecoder().raw_decode(text)
    except ValueError:
        _fail("argument", "input is not valid JSON", 2)
    if text[end:].strip():
        _fail("argument", "unexpected content after JSON object", 2)
    if not isinstance(obj, dict):
        _fail("argument", "JSON input must be an object", 2)
    try:
        wire = encode_header(obj)
    except DNSArgumentError:
        _fail("argument", "invalid header fields", 2)
    _write_success({"wire": wire.hex()})


def _cmd_decode_header():
    text = _read_utf8().strip()
    # Strict hexadecimal: even number of hex digits, nothing else.
    if len(text) % 2 or any(ch not in "0123456789abcdefABCDEF" for ch in text):
        _fail("argument", "input is not valid hexadecimal", 2)
    data = bytes.fromhex(text)
    try:
        header = decode_header(data)
    except DNSMessageError:
        _fail("message", "header must be exactly 12 bytes", 3)
    _write_success(header)


def main(argv=None):
    parser = argparse.ArgumentParser(
        prog="dns_codec",
        description="DNS message header encoder/decoder.",
    )
    subparsers = parser.add_subparsers(dest="command", required=True)
    subparsers.add_parser(
        "encode-header",
        help="read a JSON header object from stdin, print its wire hexadecimal",
    )
    subparsers.add_parser(
        "decode-header",
        help="read header hexadecimal from stdin, print its JSON fields",
    )
    args = parser.parse_args(argv)

    if args.command == "encode-header":
        _cmd_encode_header()
    elif args.command == "decode-header":
        _cmd_decode_header()


if __name__ == "__main__":
    main()
