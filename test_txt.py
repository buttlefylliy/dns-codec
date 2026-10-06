import copy
import json
import subprocess
import sys

import dns_codec as d

ARG = d.DNSArgumentError
MSG = d.DNSMessageError


def expect(exc, fn, *args, **kw):
    try:
        fn(*args, **kw)
    except exc:
        return
    except Exception as e:  # noqa
        raise AssertionError("wrong exception: %r" % (e,))
    raise AssertionError("expected %s" % exc.__name__)


def roundtrip(record):
    wire = d.encode_resource_record(record)
    decoded, nxt = d.decode_resource_record(wire)
    assert nxt == len(wire), (nxt, len(wire))
    return wire, decoded


# ---------- basic encode/decode ----------
rec = {"name": "example.", "type": 16, "class": 1, "ttl": 300,
       "strings": ["68656c6c6f"]}
wire, dec = roundtrip(rec)
assert dec == {"name": "example.", "type": 16, "class": 1, "ttl": 300,
               "strings": ["68656c6c6f"]}, dec
assert list(dec.keys()) == ["name", "type", "class", "ttl", "strings"]
# wire: name (example. = 07 example 00 -> 9 bytes) + 0010 0001 0000012c 0006 + 05 hello
assert wire == b"\x07example\x00\x00\x10\x00\x01\x00\x00\x01\x2c\x00\x06\x05hello", wire.hex()

# uppercase hex input accepted; decode normalizes to lowercase
rec2 = dict(rec, strings=["48454C4C4F", "ABcdEF"])
wire2, dec2 = roundtrip(rec2)
assert dec2["strings"] == ["48454c4c4f", "abcdef"], dec2
# wire form deterministic from raw bytes
assert wire2.endswith(b"\x05HELLO\x03\xab\xcd\xef"), wire2.hex()

# empty fragment (zero-length character-string)
wire3, dec3 = roundtrip({"name": ".", "type": 16, "class": 1, "ttl": 0,
                         "strings": [""]})
assert wire3 == b"\x00\x00\x10\x00\x01\x00\x00\x00\x00\x00\x01\x00", wire3.hex()
assert dec3["strings"] == [""], dec3

# multiple strings incl. empty in middle, order preserved, binary bytes
wire4, dec4 = roundtrip({"name": "a.b.", "type": 16, "class": 65535,
                         "ttl": 4294967295,
                         "strings": ["", "00", "ff01", "414243"]})
assert dec4["strings"] == ["", "00", "ff01", "414243"], dec4
assert dec4["class"] == 65535 and dec4["ttl"] == 4294967295

# 255-byte fragment, length octet 0xff
big = "ab" * 255
w, dd = roundtrip({"name": "x.", "type": 16, "class": 1, "ttl": 0,
                   "strings": [big]})
assert dd["strings"] == [big]
# RDLENGTH sits at name(3) + 8 into the fixed fields; rdata = 1 + 255 bytes.
assert len(w) == 3 + 10 + 256
assert int.from_bytes(w[11:13], "big") == 256
assert w[13] == 255

# tuple accepted as strings container
wt = d.encode_resource_record({"name": "x.", "type": 16, "class": 1,
                               "ttl": 0, "strings": ("41", "42")})
assert wt.endswith(b"\x01A\x01B")

# ---------- encode argument errors ----------
base = {"name": "x.", "type": 16, "class": 1, "ttl": 0}
expect(ARG, d.encode_resource_record, dict(base))  # strings missing
expect(ARG, d.encode_resource_record, dict(base, strings="41"))  # not list/tuple
expect(ARG, d.encode_resource_record, dict(base, strings=[]))  # empty
expect(ARG, d.encode_resource_record, dict(base, strings=[b"41"]))  # non-str elem
expect(ARG, d.encode_resource_record, dict(base, strings=[1]))
expect(ARG, d.encode_resource_record, dict(base, strings=["4g"]))  # non-hex
expect(ARG, d.encode_resource_record, dict(base, strings=["abc"]))  # odd
expect(ARG, d.encode_resource_record, dict(base, strings=["ab cd"]))  # space
expect(ARG, d.encode_resource_record, dict(base, strings=["ab" * 256]))  # >255 bytes
# address/target/unknown keys with type 16
expect(ARG, d.encode_resource_record, dict(base, strings=[""], address="1.2.3.4"))
expect(ARG, d.encode_resource_record, dict(base, strings=[""], target="y."))
expect(ARG, d.encode_resource_record, dict(base, strings=[""], bogus=1))
# existing-type records must reject strings
expect(ARG, d.encode_resource_record,
       {"name": "x.", "type": 1, "class": 1, "ttl": 0,
        "address": "1.2.3.4", "strings": [""]})
expect(ARG, d.encode_resource_record,
       {"name": "x.", "type": 5, "class": 1, "ttl": 0,
        "target": "y.", "strings": [""]})
# unsupported type still an argument error
expect(ARG, d.encode_resource_record, dict(base, type=6, strings=[""]))
# bool rejected for class/ttl
expect(ARG, d.encode_resource_record, {**base, "class": True, "strings": [""]})

# RDATA > 65535: 256 fragments of 255 bytes each = 65536
many = ["ab" * 255] * 256
expect(ARG, d.encode_resource_record, dict(base, strings=many))
# 255 fragments of 255 + one of 240 -> 255*256+241 = 65521  OK; boundary:
ok = ["ab" * 255] * 255 + ["cd" * 120]  # 255*256 + 121 = 65401
d.encode_resource_record(dict(base, strings=ok))

# input object not mutated
src = {"name": "x.", "type": 16, "class": 1, "ttl": 0,
       "strings": ["AB", ""]}
snapshot = copy.deepcopy(src)
d.encode_resource_record(src)
assert src == snapshot and src["strings"] == ["AB", ""]

# ---------- decode message errors ----------
# craft a valid TXT wire then mutate
good = d.encode_resource_record(
    {"name": "x.", "type": 16, "class": 1, "ttl": 0, "strings": ["4142", ""]})
# rdlength offset: name 3 bytes, fixed 10 -> rdlength at bytes 11:13
assert int.from_bytes(good[11:13], "big") == 4

def with_rdlength(data, val):
    return data[:11] + val.to_bytes(2, "big") + data[13:]

# zero rdlength
expect(MSG, d.decode_resource_record, with_rdlength(good, 0))
# declared region past message end (truncated RDATA)
expect(MSG, d.decode_resource_record, with_rdlength(good, 6))
expect(MSG, d.decode_resource_record, good[:-1])  # truncated last fragment byte
# fragment length crosses declared region: region "02 41" (2 bytes) declared 2 fine;
# declare rdlength 2 over first two rdata bytes 04 41 -> fragment claims 4, region 2
bad = good[:13] + b"\x04\x41"
bad = bad[:11] + (2).to_bytes(2, "big") + bad[13:]
expect(MSG, d.decode_resource_record, bad)
# region not decomposable: rdlength 3 over 01 41 42 (one 1-byte fragment
# plus a lone trailing byte)
bad2 = good[:11] + (3).to_bytes(2, "big") + b"\x01\x41\x42"
expect(MSG, d.decode_resource_record, bad2)
# region 1 = just a length byte 00 -> actually decomposes as one empty fragment: valid
okempty = good[:11] + (1).to_bytes(2, "big") + b"\x00"
r0, n0 = d.decode_resource_record(okempty)
assert r0["strings"] == [""] and n0 == len(okempty)
# TXT data must not be interpreted as compression: bytes 0xc0.. are raw
ptrbytes = b"\x02\xc0\x00"  # would look like a pointer to 0
wptr = (b"\x01x\x00\x00\x10\x00\x01\x00\x00\x00\x00"
        + (3).to_bytes(2, "big") + ptrbytes)
rp, np_ = d.decode_resource_record(wptr)
assert rp["strings"] == ["c000"], rp
assert np_ == len(wptr)

# unsupported type on decode
unsup = b"\x01x\x00\x00\x06\x00\x01\x00\x00\x00\x00\x00\x00"
expect(MSG, d.decode_resource_record, unsup)

# no partial result: exception, nothing returned (by definition); next offset sanity
try:
    d.decode_resource_record(bad2)
    assert False
except MSG:
    pass

# ---------- determinism ----------
j1 = json.dumps(d.decode_resource_record(wire4)[0], separators=(",", ":"))
j2 = json.dumps(d.decode_resource_record(wire4)[0], separators=(",", ":"))
assert j1 == j2
assert d.encode_resource_record(
    {"name": "x.", "type": 16, "class": 1, "ttl": 0, "strings": ["FF"]}) == \
    d.encode_resource_record(
    {"name": "x.", "type": 16, "class": 1, "ttl": 0, "strings": ["ff"]})

# ---------- full messages with mixed records ----------
msg = {
    "header": {"id": 7, "qr": True, "opcode": 0, "aa": False, "tc": False,
               "rd": True, "ra": True, "z": 0, "rcode": 0,
               "qdcount": 1, "ancount": 3, "nscount": 1, "arcount": 2},
    "questions": [{"name": "example.", "qtype": 16, "qclass": 1}],
    "answers": [
        {"name": "example.", "type": 1, "class": 1, "ttl": 60,
         "address": "1.2.3.4"},
        {"name": "example.", "type": 16, "class": 1, "ttl": 60,
         "strings": ["6869", ""]},
        {"name": "example.", "type": 28, "class": 1, "ttl": 60,
         "address": "2001:db8::1"},
    ],
    "authorities": [
        {"name": "example.", "type": 16, "class": 1, "ttl": 0,
         "strings": ["763d646b696d"]},
    ],
    "additionals": [
        {"name": "example.", "type": 2, "class": 1, "ttl": 0,
         "target": "ns1.example."},
        {"name": "example.", "type": 16, "class": 1, "ttl": 0,
         "strings": [""]},
    ],
}
mw = d.encode_message(msg)
dm = d.decode_message(mw)
assert dm["answers"][1] == {"name": "example.", "type": 16, "class": 1,
                            "ttl": 60, "strings": ["6869", ""]}
assert dm["authorities"][0]["strings"] == ["763d646b696d"]
assert dm["additionals"][1]["strings"] == [""]
assert list(dm.keys()) == ["header", "questions", "answers",
                           "authorities", "additionals"]
assert d.encode_message(dm) == mw  # round-trip byte-identical

# count mismatch rejected
bad_msg = json.loads(json.dumps(msg))
bad_msg["header"]["ancount"] = 2
expect(ARG, d.encode_message, bad_msg)

# trailing bytes in full message rejected
expect(MSG, d.decode_message, mw + b"\x00")

# message too big (>65535): many TXT records via API
big_txt = {"name": "x.", "type": 16, "class": 1, "ttl": 0,
           "strings": ["61" * 255]}  # 256 rdata + 13 overhead = 269 each
n = 65535 // 269 + 1
huge = {
    "header": {"id": 0, "qr": True, "opcode": 0, "aa": False, "tc": False,
               "rd": False, "ra": False, "z": 0, "rcode": 0,
               "qdcount": 0, "ancount": n, "nscount": 0, "arcount": 0},
    "questions": [], "answers": [big_txt] * n,
    "authorities": [], "additionals": [],
}
expect(ARG, d.encode_message, huge)

print("API tests passed")

# ---------- CLI tests ----------
def cli(cmd, payload):
    p = subprocess.run([sys.executable, "dns_codec.py", cmd],
                       input=payload, capture_output=True)
    return p.returncode, p.stdout.decode(), p.stderr.decode()

inp = json.dumps({"name": "txt.example.", "type": 16, "class": 1,
                  "ttl": 3600, "strings": ["763D73706631", "00ff", ""]})
code, out, err = cli("encode-record", inp.encode())
assert code == 0 and err == "", (code, out, err)
wire_hex = json.loads(out)["wire"]
code, out, err = cli("decode-record", wire_hex.encode())
assert code == 0 and err == "", (code, out, err)
assert json.loads(out) == {"name": "txt.example.", "type": 16, "class": 1,
                           "ttl": 3600,
                           "strings": ["763d73706631", "00ff", ""]}
# compact JSON: no spaces
assert " " not in out.strip()

# encode-message / decode-message CLI
code, out, err = cli("encode-message", json.dumps(msg).encode())
assert code == 0, err
mhex = json.loads(out)["wire"]
code, out, err = cli("decode-message", mhex.encode())
assert code == 0, err
assert json.loads(out)["answers"][1]["strings"] == ["6869", ""]
# determinism
code, out2, _ = cli("decode-message", mhex.encode())
assert out == out2

# error classification on CLI: bad strings -> exit 2
code, out, err = cli("encode-record", json.dumps(
    {"name": "x.", "type": 16, "class": 1, "ttl": 0, "strings": ["zz"]}).encode())
assert code == 2 and json.loads(err)["error"] == "argument", (code, err)
# zero rdlength wire -> exit 3
zw = bytes.fromhex(wire_hex)
# name "txt.example." is 13 wire bytes; fixed fields start there with
# RDLENGTH at 21..22 and RDATA beginning at 23.
zw = zw[:21] + b"\x00\x00" + zw[23:]
code, out, err = cli("decode-record", zw.hex().encode())
assert code == 3 and json.loads(err)["error"] == "message", (code, err)

print("CLI tests passed")
