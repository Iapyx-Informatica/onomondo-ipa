#!/usr/bin/env python3
"""
eim_json2ber.py -- convert an eIM configuration JSON into the BER-encoded
AddInitialEimRequest that onomondo-ipa consumes with its -f option.

Encodes ES10b.AddInitialEim per GSMA SGP.32 v1.2 section 5.9.4.

    BF57 -> A0 (eimConfigurationDataList) -> 30 (EimConfigurationData) -> fields

Input JSON (one eIM, or a list of them under "eimConfigurationDataList"):

    {
        "eimId": "g-eim.com.br",
        "eimIdType": 2,
        "counterValue": 0,
        "eimPublicKey": "<base64 SubjectPublicKeyInfo>",
        "trustedCertificateTls": "<base64 X.509 certificate>",
        "eimSupportedProtocol": 1,
        "indirectProfileDownload": true
    }

Every recognised field name from the SGP.32 EimConfigurationData ASN.1 is
accepted; see FIELD_HELP below.  Per 5.9.4, eimId, counterValue, and exactly
one of eimPublicKey / eimCertificate are mandatory -- the script fills
counterValue with 0 if absent (with a warning) and refuses to emit a file
that is missing eimId or a public key, unless --no-validate is given.

Usage:
    python3 eim_json2ber.py config.json -o g-eim.ber
    python3 eim_json2ber.py config.json            # writes config.ber
    python3 eim_json2ber.py config.json --stdout   # hex to stdout, no file
    cat config.json | python3 eim_json2ber.py -    # read JSON from stdin
    python3 eim_json2ber.py config.json --dump      # show the TLV tree
"""

import argparse
import base64
import json
import re
import sys

# --------------------------------------------------------------------------
# BER/DER primitives
# --------------------------------------------------------------------------


def enc_len(n: int) -> bytes:
    if n < 0x80:
        return bytes([n])
    if n < 0x100:
        return bytes([0x81, n])
    if n < 0x10000:
        return bytes([0x82, n >> 8, n & 0xFF])
    if n < 0x1000000:
        return bytes([0x83, n >> 16, (n >> 8) & 0xFF, n & 0xFF])
    raise ValueError("length too large: %d" % n)


def tlv(tag: bytes, val: bytes) -> bytes:
    return tag + enc_len(len(val)) + val


def enc_int(value: int) -> bytes:
    """Minimal two's-complement INTEGER contents (signed)."""
    if value == 0:
        return b"\x00"
    length = (value.bit_length() + 8) // 8 if value > 0 else \
        ((value + 1).bit_length() + 8) // 8
    while True:
        try:
            b = value.to_bytes(length, "big", signed=True)
            break
        except OverflowError:
            length += 1
    # strip redundant leading 0x00 / 0xFF while preserving sign
    while len(b) > 1 and (
            (b[0] == 0x00 and not (b[1] & 0x80)) or
            (b[0] == 0xFF and (b[1] & 0x80))):
        b = b[1:]
    return b


def content_of(der: bytes) -> bytes:
    off = 1
    if der[0] & 0x1F == 0x1F:
        while der[off] & 0x80:
            off += 1
        off += 1
    n = der[off]
    off += 1
    if n & 0x80:
        k = n & 0x7F
        n = int.from_bytes(der[off:off + k], "big")
        off += k
    return der[off:off + n]


def retag(der: bytes, new_tag: bytes) -> bytes:
    """IMPLICIT re-tag: keep content, replace the outer tag."""
    return tlv(new_tag, content_of(der))


def ber_walk(buf: bytes, off=0, end=None):
    if end is None:
        end = len(buf)
    while off < end:
        start = off
        t0 = buf[off]
        off += 1
        if t0 & 0x1F == 0x1F:
            while buf[off] & 0x80:
                off += 1
            off += 1
        tag = buf[start:off]
        n = buf[off]
        off += 1
        if n & 0x80:
            k = n & 0x7F
            n = int.from_bytes(buf[off:off + k], "big")
            off += k
        yield tag, bool(t0 & 0x20), off, n
        off += n


def ber_dump(buf: bytes, indent=0, out=sys.stdout):
    try:
        for tag, constructed, cstart, clen in ber_walk(buf):
            pad = "  " * indent
            if constructed:
                print("%s%s len=%d" % (pad, tag.hex().upper(), clen), file=out)
                ber_dump(buf[cstart:cstart + clen], indent + 1, out)
            else:
                v = buf[cstart:cstart + clen]
                s = v.hex().upper()
                if len(s) > 60:
                    s = s[:60] + "..."
                extra = ""
                if 0 < clen <= 32 and all(32 <= c < 127 for c in v):
                    extra = '  "%s"' % v.decode("ascii")
                print("%s%s len=%d %s%s" % (pad, tag.hex().upper(), clen, s, extra),
                      file=out)
    except (IndexError, ValueError):
        print("%s<malformed: %s>" % ("  " * indent, buf.hex().upper()), file=out)


# --------------------------------------------------------------------------
# field encoders (SGP.32 v1.2 EimConfigurationData)
# --------------------------------------------------------------------------

FIELD_HELP = {
    "eimId":                   "[0] UTF8String, 1..128 chars  (MANDATORY)",
    "eimFqdn":                 "[1] UTF8String",
    "eimIdType":               "[2] INTEGER 1=oid 2=fqdn 3=proprietary",
    "counterValue":            "[3] INTEGER, replay counter seed  (MANDATORY, use 0)",
    "associationToken":        "[4] INTEGER, set -1 to request calculation",
    "eimPublicKey":            "[5] eimPublicKey: base64 SubjectPublicKeyInfo",
    "eimCertificate":          "[5] eimCertificate: base64 X.509 cert",
    "trustedEimPkTls":         "[6] trustedEimPkTls: base64 SubjectPublicKeyInfo",
    "trustedCertificateTls":   "[6] trustedCertificateTls: base64 X.509 cert",
    "eimSupportedProtocol":    "[7] BIT STRING; int bitmask or list of bit names",
    "euiccCiPKId":             "[8] OCTET STRING, hex CI PKID (SubjectKeyIdentifier)",
    "indirectProfileDownload": "[9] NULL, boolean true to include",
}

# eimSupportedProtocol named bits (SGP.32 EimSupportedProtocol BIT STRING)
PROTOCOL_BITS = {
    "eimRetrieveHttps": 0,
    "eimRetrieveCoaps": 1,
    "eimInjectHttps":   2,
    "eimInjectCoaps":   3,
    "eimProprietary":   4,
}


class ConvError(Exception):
    pass


def _b64(name, value):
    try:
        return base64.b64decode(_strip_pem(value), validate=False)
    except Exception as exc:
        raise ConvError("%s: invalid base64 (%s)" % (name, exc))


def _strip_pem(s: str) -> str:
    """Tolerate PEM armor, whitespace and stray markdown link syntax."""
    s = re.sub(r"-----(BEGIN|END)[^-]*-----", "", s)
    return "".join(s.split())


def _clean_str(s: str) -> str:
    """Undo the '[text](url)' markdown mangling seen in copied JSON."""
    m = re.fullmatch(r"\[([^\]]+)\]\((?:https?://)?([^)]*)\)", s.strip())
    if m:
        # prefer the visible label, drop a trailing slash the linkifier adds
        return m.group(1).strip()
    return s.strip()


def enc_bitstring(value) -> bytes:
    """Encode eimSupportedProtocol from an int bitmask or a list of names."""
    if isinstance(value, str):
        value = [value]
    if isinstance(value, list):
        mask = 0
        for item in value:
            if item not in PROTOCOL_BITS:
                raise ConvError("eimSupportedProtocol: unknown bit '%s' "
                                "(known: %s)" % (item, ", ".join(PROTOCOL_BITS)))
            mask |= 1 << (7 - PROTOCOL_BITS[item])
        bit_positions = [PROTOCOL_BITS[i] for i in value]
    elif isinstance(value, int):
        # interpret the integer as a bitmask over bit indices 0..4
        mask = 0
        bit_positions = []
        for idx in range(8):
            if value & (1 << idx):
                mask |= 1 << (7 - idx)
                bit_positions.append(idx)
        if not bit_positions and value:
            raise ConvError("eimSupportedProtocol: %d sets no known bit" % value)
    else:
        raise ConvError("eimSupportedProtocol: expected int or list")
    # unused-bits octet: distance from the last set bit to the byte boundary
    highest = max(bit_positions) if bit_positions else 0
    unused = 7 - highest
    return bytes([unused, mask])


def build_entry(cfg: dict, validate=True, warn=print):
    """Encode one EimConfigurationData (the inner '30' SEQUENCE)."""
    if not isinstance(cfg, dict):
        raise ConvError("each eIM entry must be a JSON object")

    unknown = set(cfg) - set(FIELD_HELP)
    for u in sorted(unknown):
        warn("[warn] ignoring unknown field '%s'" % u)

    parts = []

    # [0] eimId --------------------------------------------------------------
    if "eimId" in cfg:
        eim_id = _clean_str(str(cfg["eimId"]))
        if cfg["eimId"] != eim_id:
            warn("[warn] eimId cleaned to '%s'" % eim_id)
        if not 1 <= len(eim_id.encode()) <= 128:
            raise ConvError("eimId must be 1..128 bytes, got %d"
                            % len(eim_id.encode()))
        parts.append((0, tlv(b"\x80", eim_id.encode())))
    elif validate:
        raise ConvError("eimId is mandatory (5.9.4)")

    # [1] eimFqdn ------------------------------------------------------------
    if "eimFqdn" in cfg:
        parts.append((1, tlv(b"\x81", _clean_str(str(cfg["eimFqdn"])).encode())))

    # [2] eimIdType ----------------------------------------------------------
    if "eimIdType" in cfg:
        parts.append((2, tlv(b"\x82", enc_int(int(cfg["eimIdType"])))))

    # [3] counterValue -------------------------------------------------------
    if "counterValue" in cfg:
        parts.append((3, tlv(b"\x83", enc_int(int(cfg["counterValue"])))))
    else:
        warn("[warn] counterValue absent -- inserting 0 (mandatory per 5.9.4)")
        parts.append((3, tlv(b"\x83", enc_int(0))))

    # [4] associationToken ---------------------------------------------------
    if "associationToken" in cfg:
        parts.append((4, tlv(b"\x84", enc_int(int(cfg["associationToken"])))))

    # [5] eimPublicKeyData CHOICE  (EXPLICIT [5] wrapping the alternative) ----
    has_pk = "eimPublicKey" in cfg
    has_cert = "eimCertificate" in cfg
    if has_pk and has_cert:
        raise ConvError("give either eimPublicKey or eimCertificate, not both")
    if has_pk:
        spki = _b64("eimPublicKey", cfg["eimPublicKey"])
        if spki[:1] != b"\x30":
            warn("[warn] eimPublicKey does not start with SEQUENCE (30); "
                 "is it really a SubjectPublicKeyInfo?")
        parts.append((5, tlv(b"\xA5", retag(spki, b"\xA0"))))   # alt 0
    elif has_cert:
        cert = _b64("eimCertificate", cfg["eimCertificate"])
        parts.append((5, tlv(b"\xA5", retag(cert, b"\xA1"))))   # alt 1
    elif validate:
        raise ConvError("either eimPublicKey or eimCertificate is mandatory (5.9.4)")

    # [6] trustedPublicKeyDataTls CHOICE -------------------------------------
    has_tpk = "trustedEimPkTls" in cfg
    has_tcert = "trustedCertificateTls" in cfg
    if has_tpk and has_tcert:
        raise ConvError("give either trustedEimPkTls or trustedCertificateTls, "
                        "not both")
    if has_tpk:
        spki = _b64("trustedEimPkTls", cfg["trustedEimPkTls"])
        parts.append((6, tlv(b"\xA6", retag(spki, b"\xA0"))))   # alt 0
    elif has_tcert:
        cert = _b64("trustedCertificateTls", cfg["trustedCertificateTls"])
        parts.append((6, tlv(b"\xA6", retag(cert, b"\xA1"))))   # alt 1

    # [7] eimSupportedProtocol ----------------------------------------------
    if "eimSupportedProtocol" in cfg:
        parts.append((7, tlv(b"\x87", enc_bitstring(cfg["eimSupportedProtocol"]))))

    # [8] euiccCiPKId --------------------------------------------------------
    if "euiccCiPKId" in cfg:
        h = cfg["euiccCiPKId"]
        if isinstance(h, str):
            h = re.sub(r"[^0-9a-fA-F]", "", h)
            try:
                pkid = bytes.fromhex(h)
            except ValueError:
                raise ConvError("euiccCiPKId: not valid hex")
        else:
            raise ConvError("euiccCiPKId must be a hex string")
        parts.append((8, tlv(b"\x88", pkid)))

    # [9] indirectProfileDownload -------------------------------------------
    if cfg.get("indirectProfileDownload"):
        parts.append((9, tlv(b"\x89", b"")))

    # ASN.1 field order follows the tag numbers
    parts.sort(key=lambda p: p[0])
    return tlv(b"\x30", b"".join(p[1] for p in parts))


def build_request(config, validate=True, warn=print) -> bytes:
    """Wrap one or more EimConfigurationData entries into AddInitialEimRequest."""
    if isinstance(config, dict) and "eimConfigurationDataList" in config:
        entries = config["eimConfigurationDataList"]
    elif isinstance(config, list):
        entries = config
    else:
        entries = [config]
    if not entries:
        raise ConvError("no eIM entries to encode")
    encoded = b"".join(build_entry(e, validate, warn) for e in entries)
    return tlv(b"\xBF\x57", tlv(b"\xA0", encoded))


# --------------------------------------------------------------------------
# CLI
# --------------------------------------------------------------------------


def main():
    ap = argparse.ArgumentParser(
        description=__doc__,
        formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("input", help="JSON file, or '-' for stdin")
    ap.add_argument("-o", "--output", help="output .ber path "
                    "(default: input with .ber extension)")
    ap.add_argument("--stdout", action="store_true",
                    help="print hex to stdout instead of writing a file")
    ap.add_argument("--dump", action="store_true",
                    help="also print the decoded TLV tree to stderr")
    ap.add_argument("--no-validate", action="store_true",
                    help="skip the 5.9.4 mandatory-field checks")
    ap.add_argument("--fields", action="store_true",
                    help="list recognised JSON field names and exit")
    args = ap.parse_args()

    if args.fields:
        print("Recognised EimConfigurationData fields:\n")
        for k, v in FIELD_HELP.items():
            print("  %-24s %s" % (k, v))
        print("\neimSupportedProtocol bit names: %s"
              % ", ".join(PROTOCOL_BITS))
        return 0

    if args.input == "-":
        raw = sys.stdin.read()
        default_out = "eim_cfg.ber"
    else:
        with open(args.input, "r", encoding="utf-8") as fh:
            raw = fh.read()
        default_out = re.sub(r"\.json$", "", args.input) + ".ber"

    try:
        config = json.loads(raw)
    except json.JSONDecodeError as exc:
        print("ERROR: input is not valid JSON: %s" % exc, file=sys.stderr)
        return 1

    warnings = []
    def warn(msg):
        warnings.append(msg)
        print(msg, file=sys.stderr)

    try:
        ber = build_request(config, validate=not args.no_validate, warn=warn)
    except ConvError as exc:
        print("ERROR: %s" % exc, file=sys.stderr)
        return 1

    print("[*] encoded AddInitialEimRequest: %d bytes" % len(ber), file=sys.stderr)

    if args.dump:
        ber_dump(ber, 0, out=sys.stderr)

    if args.stdout:
        print(ber.hex().upper())
    else:
        out_path = args.output or default_out
        with open(out_path, "wb") as fh:
            fh.write(ber)
        print("[*] wrote %s" % out_path, file=sys.stderr)
        print("    onomondo-ipa:  ipa -r 0 -f %s" % out_path, file=sys.stderr)

    return 0


if __name__ == "__main__":
    sys.exit(main())
