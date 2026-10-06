import json
import struct
import subprocess
import sys

import dns_codec as d

passed = 0
failed = 0


def check(cond, label):
    global passed, failed
    if cond:
        passed += 1
    else:
        failed += 1
        print("FAIL:", label)


def expect_arg(fn, label):
    try:
        fn()
    except d.DNSArgumentError:
        pass
    except Exception as e:  # noqa
        check(False, "%s (wrong exc %r)" % (label, e))
    else:
        check(False, "%s (no exc)" % label)


def expect_msg(fn, label):
    try:
        fn()
    except d.DNSMessageError:
        pass
    except Exception as e:  # noqa
        check(False, "%s (wrong exc %r)" % (label, e))
    else:
        check(False, "%s (no exc)" % label)


# ---------- A / AAAA unchanged ----------
a_wire = d.encode_resource_record(
    {"name": "Example.COM.", "type": 1, "class": 1, "ttl": 3600,
     "address": "192.0.2.1"}
)
a_rec, off = d.decode_resource_record(a_wire)
check(list(a_rec) == ["name", "type", "class", "ttl", "address"], "A key order")
check(a_rec == {"name": "Example.COM.", "type": 1, "class": 1, "ttl": 3600,
                "address": "192.0.2.1"}, "A roundtrip")
check(off == len(a_wire), "A offset")
# exact historical bytes: "Example.COM." is 13 wire bytes + 10 fixed + 4
check(a_wire == bytes([7]) + b"Example" + bytes([3]) + b"COM" + b"\x00"
      + struct.pack("!HHIH", 1, 1, 3600, 4) + bytes([192, 0, 2, 1]),
      "A exact wire")

aaaa_wire = d.encode_resource_record(
    {"name": "x.", "type": 28, "class": 3, "ttl": 0, "address": "2001:db8::1"})
aaaa_rec, off = d.decode_resource_record(aaaa_wire)
check(list(aaaa_rec) == ["name", "type", "class", "ttl", "address"],
      "AAAA key order")
check(aaaa_rec["address"] == "2001:db8::1", "AAAA canonical")
check(off == len(aaaa_wire), "AAAA offset")

# ---------- CNAME basic roundtrip ----------
wire = d.encode_resource_record(
    {"name": "www.Example.COM.", "type": 5, "class": 1, "ttl": 300,
     "target": "cdn.Example.COM."})
# owner "www.Example.COM." = 4+8+4+1 = 17; target "cdn.Example.COM." = 17
check(len(wire) == 17 + 10 + 17, "CNAME total length")
rtype, rclass, ttl, rdlength = struct.unpack("!HHIH", wire[17:27])
check((rtype, rclass, ttl, rdlength) == (5, 1, 300, 17), "CNAME fixed fields")
check(wire[27:] == bytes([3]) + b"cdn" + bytes([7]) + b"Example"
      + bytes([3]) + b"COM" + b"\x00", "CNAME rdata uncompressed")
rec, off = d.decode_resource_record(wire)
check(list(rec) == ["name", "type", "class", "ttl", "target"],
      "CNAME key order")
check(rec == {"name": "www.Example.COM.", "type": 5, "class": 1,
              "ttl": 300, "target": "cdn.Example.COM."}, "CNAME roundtrip")
check(off == len(wire), "CNAME offset")
# determinism
check(d.encode_resource_record(
    {"name": "www.Example.COM.", "type": 5, "class": 1, "ttl": 300,
     "target": "cdn.Example.COM."}) == wire, "CNAME deterministic")

# ---------- root target ----------
root_wire = d.encode_resource_record(
    {"name": "x.", "type": 5, "class": 1, "ttl": 0, "target": "."})
check(root_wire == b"\x01x\x00" + struct.pack("!HHIH", 5, 1, 0, 1) + b"\x00",
      "root target wire, rdlength=1")
root_rec, off = d.decode_resource_record(root_wire)
check(root_rec["target"] == "." and list(root_rec)[-1] == "target"
      and off == len(root_wire), "root target decode")

# ---------- case preservation ----------
mix = d.encode_resource_record(
    {"name": "a.", "type": 5, "class": 1, "ttl": 0, "target": "MiXeD.LaBeL."})
mrec, _ = d.decode_resource_record(mix)
check(mrec["target"] == "MiXeD.LaBeL.", "case preserved")

# ---------- compression pointer in RDATA target ----------
# message layout:
#  0: 3 w w w 0              (owner name "www." at offset 0, len 5)
#  5: fixed fields (10) type=5, class=1, ttl=0, rdlength=2
# 15: c0 00                  (pointer back to offset 0)
msg = b"\x03www\x00" + struct.pack("!HHIH", 5, 1, 0, 2) + b"\xc0\x00"
prec, poff = d.decode_resource_record(msg)
check(prec["target"] == "www.", "pointer target expanded")
check(poff == 17, "next_offset at declared RDATA end, not pointer target")
check(list(prec) == ["name", "type", "class", "ttl", "target"],
      "pointer record key order")

# pointer plus trailing byte inside declared RDATA -> error
bad = b"\x03www\x00" + struct.pack("!HHIH", 5, 1, 0, 3) + b"\xc0\x00\x00"
expect_msg(lambda: d.decode_resource_record(bad), "pointer plus trailing")

# ---------- decode error cases ----------
def w(rdlen, rdata):
    return b"\x01x\x00" + struct.pack("!HHIH", 5, 1, 0, rdlen) + rdata

_full_fixed = b"\x01x\x00" + struct.pack("!HHIH", 5, 1, 0, 2) + b"\xc0\x00"
expect_msg(lambda: d.decode_resource_record(_full_fixed[:-1]),
           "truncated fixed fields")
expect_msg(lambda: d.decode_resource_record(w(0, b"")), "zero rdlength")
expect_msg(lambda: d.decode_resource_record(w(6, b"\x03abc\x00\x00")),
           "declared region larger than name")
check(d.decode_resource_record(w(5, b"\x03abc\x00"))[0]["target"] == "abc.",
      "exact-fit name is valid")
expect_msg(lambda: d.decode_resource_record(w(2, b"\x03ab")),
           "declared region smaller than name (truncated)")
expect_msg(lambda: d.decode_resource_record(
    b"\x01x\x00" + struct.pack("!HHIH", 5, 1, 0, 4) + b"\x03ab\x00"),
    "rdlength mismatch exact")
expect_msg(lambda: d.decode_resource_record(w(1, b"\x02")),
    "truncated label in rdata")
expect_msg(lambda: d.decode_resource_record(w(1, b"\xc0")),
    "truncated pointer in rdata")
expect_msg(lambda: d.decode_resource_record(w(2, b"\xc0\x10")),
    "forward pointer rejected")
expect_msg(lambda: d.decode_resource_record(w(2, b"\xc0\x0f")),
    "pointer to itself rejected")
expect_msg(lambda: d.decode_resource_record(w(1, b"\x40")),
    "reserved prefix in rdata")
expect_msg(lambda: d.decode_resource_record(w(3, b"\x01\xff\x00")),
    "non-ascii label in rdata")
expect_msg(lambda: d.decode_resource_record(w(1, b"")), "rdlength truncated")
# unsupported type still DNSMessageError
uw = b"\x01x\x00" + struct.pack("!HHIH", 2, 1, 0, 0)
expect_msg(lambda: d.decode_resource_record(uw), "unsupported type 2")
# A/AAAA rdlength unchanged
expect_msg(lambda: d.decode_resource_record(
    b"\x01x\x00" + struct.pack("!HHIH", 1, 1, 0, 3) + b"\x00\x00\x00"),
    "A bad rdlength")
expect_msg(lambda: d.decode_resource_record(
    b"\x01x\x00" + struct.pack("!HHIH", 28, 1, 0, 15) + b"\x00" * 15),
    "AAAA bad rdlength")

# ---------- 128 pointer limit ----------
# Pointers are laid out BEFORE the record so every pointer can point back:
# offset 0 is the root, pointers at 1,3,5,... each point to the previous
# pointer. The RDATA entry pointer itself counts as the first jump, so a
# 127-pointer chain plus the entry totals 128 (accepted) and a 128-pointer
# chain totals 129 (rejected).
def build_chain_msg(count):
    chain = b"\x00"
    target = 0
    for i in range(count):
        chain += struct.pack("!H", 0xC000 | target)
        target = 1 + 2 * i  # offset of the pointer just appended
    return (
        chain
        + b"\x01x\x00"
        + struct.pack("!HHIH", 5, 1, 0, 2)
        + struct.pack("!H", 0xC000 | target)
    )

good_chain_msg = build_chain_msg(127)
grec, goff = d.decode_resource_record(good_chain_msg, 255)
check(grec["target"] == ".", "128-pointer chain accepted")
check(goff == len(good_chain_msg), "128-chain offset")

bad_chain_msg = build_chain_msg(128)
expect_msg(lambda: d.decode_resource_record(bad_chain_msg, 257),
           "pointer chain limit")

# ---------- encode error cases ----------
expect_arg(lambda: d.encode_resource_record(
    {"type": 5, "class": 1, "ttl": 0, "target": "a."}),
    "missing name")
expect_arg(lambda: d.encode_resource_record(
    {"name": "a.", "type": 5, "class": 1, "ttl": 0}), "missing target")
expect_arg(lambda: d.encode_resource_record(
    {"name": "a.", "type": 5, "class": 1, "ttl": 0}), "missing target 2")
expect_arg(lambda: d.encode_resource_record(
    {"name": "a.", "class": 1, "ttl": 0, "target": "b."}), "missing type")
expect_arg(lambda: d.encode_resource_record(
    {"name": "a.", "type": 5, "ttl": 0, "target": "b."}), "missing class")
expect_arg(lambda: d.encode_resource_record(
    {"name": "a.", "type": 5, "class": 1, "target": "b."}), "missing ttl")
expect_arg(lambda: d.encode_resource_record(
    {"name": "a.", "type": 5, "class": 1, "ttl": 0,
     "target": "b.", "address": "1.2.3.4"}), "unknown address on CNAME")
expect_arg(lambda: d.encode_resource_record(
    {"name": "a.", "type": 1, "class": 1, "ttl": 0,
     "address": "1.2.3.4", "target": "b."}), "unknown target on A")
expect_arg(lambda: d.encode_resource_record(
    {"name": "a.", "type": 5, "class": 1, "ttl": 0, "target": "rel"}),
    "relative target")
expect_arg(lambda: d.encode_resource_record(
    {"name": "a.", "type": 5, "class": 1, "ttl": 0, "target": "b.."}),
    "empty label target")
expect_arg(lambda: d.encode_resource_record(
    {"name": "a.", "type": 5, "class": 1, "ttl": 0, "target": 5}),
    "non-string target")
expect_arg(lambda: d.encode_resource_record(
    {"name": "rel", "type": 5, "class": 1, "ttl": 0, "target": "b."}),
    "relative owner")
expect_arg(lambda: d.encode_resource_record(
    {"name": "a.", "type": 2, "class": 1, "ttl": 0, "address": "1.2.3.4"}),
    "unsupported type")
expect_arg(lambda: d.encode_resource_record(
    {"name": "a.", "type": 65536, "class": 1, "ttl": 0, "target": "b."}),
    "type range")
expect_arg(lambda: d.encode_resource_record(
    {"name": "a.", "type": 5, "class": 65536, "ttl": 0, "target": "b."}),
    "class range")
expect_arg(lambda: d.encode_resource_record(
    {"name": "a.", "type": 5, "class": -1, "ttl": 0, "target": "b."}),
    "class negative")
expect_arg(lambda: d.encode_resource_record(
    {"name": "a.", "type": 5, "class": 1, "ttl": 2 ** 32, "target": "b."}),
    "ttl range")
expect_arg(lambda: d.encode_resource_record(
    {"name": "a.", "type": 5, "class": 1, "ttl": -1, "target": "b."}),
    "ttl negative")
expect_arg(lambda: d.encode_resource_record(
    {"name": "a.", "type": True, "class": 1, "ttl": 0, "target": "b."}),
    "bool type")
expect_arg(lambda: d.encode_resource_record(
    {"name": "a.", "type": 5, "class": True, "ttl": 0, "target": "b."}),
    "bool class")
expect_arg(lambda: d.encode_resource_record(
    {"name": "a.", "type": 5, "class": 1, "ttl": True, "target": "b."}),
    "bool ttl")
expect_arg(lambda: d.encode_resource_record("not a mapping"), "not mapping")
expect_arg(lambda: d.encode_resource_record(
    {"name": "a.", "type": 5, "class": 1, "ttl": 0, "target": "é."}),
    "non-ascii target")

# 255-octet expanded-name bound for target (255 ok, 256 -> arg error)
labels253 = ".".join(["a"] * 63 + ["b" * 63] * 3)  # wire: 4*64 = 256? compute
def wire_len(n):
    s = n
    return len(s) + s.count(".") + 1
longname = ".".join(["l" * 63] * 4)  # 4 labels => 4*64=256 wire bytes
expect_arg(lambda: d.encode_resource_record(
    {"name": "a.", "type": 5, "class": 1, "ttl": 0, "target": longname + "."}),
    "target over 255")
okname = ".".join(["l" * 63] * 3 + ["x" * 61])  # 3*64 + 62 + 1 zero = 255
okrec = d.encode_resource_record(
    {"name": "a.", "type": 5, "class": 1, "ttl": 0, "target": okname + "."})
check(len(okrec) == 3 + 10 + 255, "target exactly 255")

# input not mutated
src = {"name": "a.", "type": 5, "class": 1, "ttl": 0, "target": "b."}
import copy
snapshot = copy.deepcopy(src)
d.encode_resource_record(src)
check(src == snapshot, "input not mutated")

# decode with offset among other bytes
prefix = b"\xaa\xbb"
full = prefix + wire
r2, o2 = d.decode_resource_record(full, 2)
check(o2 == 2 + len(wire) and r2["target"] == "cdn.Example.COM.",
      "decode at offset")
check(d.decode_resource_record(full, 2)[1] == len(full), "offset end")

# argument errors for decode
expect_arg(lambda: d.decode_resource_record("x"), "decode non-bytes")
expect_arg(lambda: d.decode_resource_record(wire, True), "decode bool offset")
expect_arg(lambda: d.decode_resource_record(wire, -1), "decode neg offset")
expect_arg(lambda: d.decode_resource_record(wire, len(wire)),
           "decode offset==len")
big = b"\x00" * (65535 + 1)
expect_arg(lambda: d.decode_resource_record(big), "message too large")

# ---------- CLI ----------
def cli(args, payload):
    p = subprocess.run(
        [sys.executable, "dns_codec.py"] + args,
        input=payload, capture_output=True)
    return p.returncode, p.stdout, p.stderr

enc_in = json.dumps({"name": "www.Example.COM.", "type": 5, "class": 1,
                     "ttl": 300, "target": "cdn.Example.COM."})
rc, out, err = cli(["encode-record"], enc_in.encode())
check(rc == 0, "cli encode rc")
encoded = json.loads(out)
check(set(encoded) == {"wire"}, "cli encode only wire")
check(encoded["wire"] == wire.hex(), "cli encode bytes match api")

rc, out, err = cli(["decode-record"], wire.hex().encode())
check(rc == 0, "cli decode rc")
decoded = json.loads(out)
check(list(decoded) == ["name", "type", "class", "ttl", "target"],
      "cli decode key order")
check(decoded == {"name": "www.Example.COM.", "type": 5, "class": 1,
                  "ttl": 300, "target": "cdn.Example.COM."},
      "cli decode value")

# pointer CNAME via CLI
rc, out, err = cli(["decode-record"], msg.hex().encode())
check(rc == 0 and json.loads(out)["target"] == "www.", "cli pointer decode")

# trailing bytes -> message error, code 3
rc, out, err = cli(["decode-record"], (wire.hex() + "00").encode())
check(rc == 3, "cli trailing rc=3")
eobj = json.loads(err)
check(eobj["error"] == "message", "cli trailing error kind")

# truncated -> 3
rc, out, err = cli(["decode-record"], b"01")
check(rc == 3 and json.loads(err)["error"] == "message", "cli truncated rc=3")

# zero rdlength -> 3
zw = b"\x01x\x00" + struct.pack("!HHIH", 5, 1, 0, 0)
rc, out, err = cli(["decode-record"], zw.hex().encode())
check(rc == 3, "cli zero rdlength rc=3")

# bad JSON -> argument, code 2
rc, out, err = cli(["encode-record"], b"{not json")
check(rc == 2 and json.loads(err)["error"] == "argument", "cli bad json rc=2")

# unknown field -> 2
bad_json = json.dumps({"name": "a.", "type": 5, "class": 1, "ttl": 0,
                       "target": "b.", "x": 1})
rc, out, err = cli(["encode-record"], bad_json.encode())
check(rc == 2, "cli unknown field rc=2")

# missing target -> 2
bad_json = json.dumps({"name": "a.", "type": 5, "class": 1, "ttl": 0})
rc, out, err = cli(["encode-record"], bad_json.encode())
check(rc == 2, "cli missing target rc=2")

# bad target -> 2
bad_json = json.dumps({"name": "a.", "type": 5, "class": 1, "ttl": 0,
                       "target": "rel"})
rc, out, err = cli(["encode-record"], bad_json.encode())
check(rc == 2, "cli bad target rc=2")

# bool ttl -> 2
bad_json = json.dumps({"name": "a.", "type": 5, "class": 1, "ttl": True,
                       "target": "b."})
rc, out, err = cli(["encode-record"], bad_json.encode())
check(rc == 2, "cli bool ttl rc=2")

# root via CLI roundtrip
rc, out, err = cli(["encode-record"], json.dumps(
    {"name": ".", "type": 5, "class": 65535, "ttl": 4294967295,
     "target": "."}).encode())
check(rc == 0, "cli root/boundary encode")
wroot = bytes.fromhex(json.loads(out)["wire"])
rr, oo = d.decode_resource_record(wroot)
check(rr == {"name": ".", "type": 5, "class": 65535,
             "ttl": 4294967295, "target": "."}, "boundary values")

# A still works over CLI
rc, out, err = cli(["encode-record"], json.dumps(
    {"name": "a.", "type": 1, "class": 1, "ttl": 0,
     "address": "1.2.3.4"}).encode())
check(rc == 0, "cli A still works")

print("passed=%d failed=%d" % (passed, failed))
sys.exit(1 if failed else 0)
