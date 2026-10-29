#!/usr/bin/env python3
"""
ChronoCert - TLS certificate toolkit.
Expiry checks, full audits, protocol and chain inspection, offline certificate
analysis and certificate-change detection.
Part of the CHRONO SUITE.
Dev: Chrono

For legal, defensive and educational use on hosts you own or are
authorized to test.
"""

import argparse
import concurrent.futures
import datetime as dt
import hashlib
import ipaddress
import json
import re
import socket
import ssl
import sys
import warnings
from pathlib import Path

from rich.console import Console
from rich.markup import escape
from rich.progress import Progress, SpinnerColumn, TextColumn
from rich.table import Table
from rich.text import Text

VERSION = "2.0.0"
DEV = "Chrono"
DISCLAIMER = "For legal, defensive and educational use on hosts you own or are authorized to test."
DEFAULT_WARN, DEFAULT_CRIT = 30, 7
SUBCOMMANDS = ("check", "audit", "inspect")
COLORS = {"OK": "green", "WARNING": "yellow", "CRITICAL": "red", "INVALID": "red",
          "EXPIRED": "red", "ERROR": "red", "CHANGED": "magenta"}
RANK = {"EXPIRED": 0, "ERROR": 1, "INVALID": 2, "CHANGED": 3, "CRITICAL": 4, "WARNING": 5, "OK": 6}
SEV_COLOR = {"CRIT": "red", "WARN": "yellow", "INFO": "cyan"}
PROTOCOLS = (("TLS 1.0", "TLSv1"), ("TLS 1.1", "TLSv1_1"), ("TLS 1.2", "TLSv1_2"), ("TLS 1.3", "TLSv1_3"))

console = Console()
err_console = Console(stderr=True)

# ------------------------------------------------------------- banner ----

STOPS = [(122, 92, 255), (58, 123, 255), (0, 180, 216), (46, 229, 157), (155, 224, 0), (255, 176, 0)]

# Logo: a certificate with a wax seal (this tool's mascot).
LOGO = [
    r" .------------------------------------. ",
    r" |  ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~  | ",
    r" |  ~~~~~~~~~~~~~~~~~~~~~~~~~~        | ",
    r" |  ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~     | ",
    r" |                                    | ",
    r" |  ~~~~~~~~~~~~~~~~~    .-~~~-.      | ",
    r" |  ~~~~~~~~~~~~~~      /  \|/  \     | ",
    r" |                      |  -*-  |     | ",
    r" |                      \  /|\  /     | ",
    r" '----------------------'-.___.-'-----' ",
    r"                           |  |         ",
    r"                          / /\ \        ",
    r"                         /_/  \_\       ",
]
NAME_TOP = [
    r"  _____   _                                     ",
    r" / ____| | |                                    ",
    r"| |      | |__    _ __    ___    _ __     ___   ",
    r"| |      | '_ \  | '__|  / _ \  | '_ \   / _ \  ",
    r"| |____  | | | | | |    | (_) | | | | | | (_) | ",
    r" \_____| |_| |_| |_|     \___/  |_| |_|  \___/  ",
]
NAME_BOTTOM = [
    r"  _____                _    ",
    r" / ____|              | |   ",
    r"| |       ___   _ __  | |_  ",
    r"| |      / _ \ | '__| | __| ",
    r"| |____ |  __/ | |    | |_  ",
    r" \_____| \___| |_|     \__| ",
]


def _grad(t):
    t = max(0.0, min(1.0, t))
    x = t * (len(STOPS) - 1)
    i = min(int(x), len(STOPS) - 2)
    f = x - i
    a, b = STOPS[i], STOPS[i + 1]
    return "#%02x%02x%02x" % tuple(round(a[k] + (b[k] - a[k]) * f) for k in range(3))


def _centered(msg, style):
    console.print(Text(" " * max(0, (console.width - len(msg)) // 2) + msg, style=style))


def show_banner():
    blocks = [LOGO, [""], NAME_TOP, NAME_BOTTOM]
    width = max(len(l) for b in blocks for l in b)
    if console.width < width + 2:
        console.print(Text(f"CHRONOCERT // TLS certificate toolkit // Dev: {DEV}", style="bold #00b4d8"))
        return
    total = sum(len(b) for b in blocks)
    margin = (console.width - width) // 2
    text = Text()
    r = 0
    for block in blocks:
        lead = (width - max(len(l) for l in block)) // 2 + margin
        for line in block:
            text.append(" " * lead)
            for c, ch in enumerate(line):
                if ch == " ":
                    text.append(ch)
                else:
                    t = 0.88 * r / max(total - 1, 1) + 0.12 * (c + lead - margin) / width
                    text.append(ch, style=f"bold {_grad(t)}")
            text.append("\n")
            r += 1
    console.print(text, end="")
    console.print()
    _centered(f"TLS certificate toolkit  //  CHRONO SUITE v{VERSION}", "bold white")
    _centered(f"[ Dev: {DEV} ]", "bold #ffb000")
    _centered("check  |  audit  |  inspect", "#00b4d8")
    console.print()
    console.print(Text(DISCLAIMER, style="dim"))


# ------------------------------------------------- X.509 (DER) parser ----
# A small ASN.1/DER reader, so key sizes, signature algorithms and fingerprints
# can be reported with no third-party crypto library (works on Termux as-is).

NAME_OIDS = {"2.5.4.3": "CN", "2.5.4.10": "O", "2.5.4.11": "OU", "2.5.4.6": "C",
             "2.5.4.8": "ST", "2.5.4.7": "L"}
SIG_OIDS = {
    "1.2.840.113549.1.1.4": "md5WithRSA", "1.2.840.113549.1.1.5": "sha1WithRSA",
    "1.2.840.113549.1.1.11": "sha256WithRSA", "1.2.840.113549.1.1.12": "sha384WithRSA",
    "1.2.840.113549.1.1.13": "sha512WithRSA", "1.2.840.113549.1.1.10": "RSASSA-PSS",
    "1.2.840.10045.4.1": "ecdsa-with-SHA1", "1.2.840.10045.4.3.2": "ecdsa-with-SHA256",
    "1.2.840.10045.4.3.3": "ecdsa-with-SHA384", "1.2.840.10045.4.3.4": "ecdsa-with-SHA512",
    "1.3.101.112": "Ed25519", "1.3.101.113": "Ed448"}
CURVES = {"1.2.840.10045.3.1.7": ("P-256", 256), "1.3.132.0.34": ("P-384", 384),
          "1.3.132.0.35": ("P-521", 521)}
EKU_NAMES = {"1.3.6.1.5.5.7.3.1": "serverAuth", "1.3.6.1.5.5.7.3.2": "clientAuth",
             "1.3.6.1.5.5.7.3.3": "codeSigning", "1.3.6.1.5.5.7.3.4": "emailProtection"}
OID_RSA, OID_EC = "1.2.840.113549.1.1.1", "1.2.840.10045.2.1"


def _tlv(buf, pos):
    """Read one DER element at pos -> (tag, value_start, value_end)."""
    tag, length = buf[pos], buf[pos + 1]
    pos += 2
    if length & 0x80:
        n = length & 0x7F
        length = int.from_bytes(buf[pos:pos + n], "big")
        pos += n
    return tag, pos, pos + length


def _items(buf, start, end):
    """Yield (tag, value_start, value_end, element_start) for each element in a range."""
    pos = start
    while pos < end:
        tag, vs, ve = _tlv(buf, pos)
        yield tag, vs, ve, pos
        pos = ve


def _oid(buf, vs, ve):
    arcs, val = [], 0
    for byte in buf[vs:ve]:
        val = (val << 7) | (byte & 0x7F)
        if not byte & 0x80:
            arcs.append(val)
            val = 0
    first = arcs[0]
    head = [first // 40, first % 40] if first < 80 else [2, first - 80]
    return ".".join(str(a) for a in head + arcs[1:])


def _text(buf, tag, vs, ve):
    raw = buf[vs:ve]
    if tag == 0x1E:
        return raw.decode("utf-16-be", "replace")
    return raw.decode("utf-8", "replace") if tag == 0x0C else raw.decode("latin-1")


def _name(buf, vs, ve):
    """Distinguished name -> [(short_name, value), ...]."""
    pairs = []
    for _, rs, re_, _ in _items(buf, vs, ve):
        for _, as_, ae, _ in _items(buf, rs, re_):
            kids = list(_items(buf, as_, ae))
            oid = _oid(buf, kids[0][1], kids[0][2])
            pairs.append((NAME_OIDS.get(oid, oid), _text(buf, kids[1][0], kids[1][1], kids[1][2])))
    return pairs


def _time(buf, tag, vs, ve):
    s = buf[vs:ve].decode("ascii")
    if tag == 0x17:  # UTCTime: two-digit year
        yy = int(s[:2])
        s = f"{2000 + yy if yy < 50 else 1900 + yy}{s[2:]}"
    return dt.datetime.strptime(s[:14], "%Y%m%d%H%M%S").replace(tzinfo=dt.timezone.utc)


def _pick(pairs, key):
    return next((v for k, v in pairs if k == key), None)


def _public_key(buf, spki):
    kids = list(_items(buf, spki[1], spki[2]))
    alg = list(_items(buf, kids[0][1], kids[0][2]))
    oid = _oid(buf, alg[0][1], alg[0][2])
    if oid == OID_RSA:
        body = buf[kids[1][1] + 1:kids[1][2]]  # skip the BIT STRING "unused bits" byte
        _, vs, ve = _tlv(body, 0)
        modulus = next(_items(body, vs, ve))
        bits = int.from_bytes(body[modulus[1]:modulus[2]], "big").bit_length()
        return {"key_type": "RSA", "key_bits": bits, "key_desc": f"RSA {bits}"}
    if oid == OID_EC and len(alg) > 1:
        curve = _oid(buf, alg[1][1], alg[1][2])
        name, bits = CURVES.get(curve, (curve, 0))
        return {"key_type": "EC", "key_bits": bits, "key_desc": f"EC {name}"}
    if oid in ("1.3.101.112", "1.3.101.113"):
        return {"key_type": "EdDSA", "key_bits": 256, "key_desc": SIG_OIDS[oid]}
    return {"key_type": oid, "key_bits": 0, "key_desc": oid}


def _extensions(buf, vs, ve):
    out = {"san": [], "has_san": False, "is_ca": False, "eku": []}
    _, es, ee = _tlv(buf, vs)
    for _, xs, xe, _ in _items(buf, es, ee):
        parts = list(_items(buf, xs, xe))
        oid = _oid(buf, parts[0][1], parts[0][2])
        os_ = parts[-1][1]  # OCTET STRING holding the extension's own DER
        if oid == "2.5.29.17":  # subjectAltName
            out["has_san"] = True
            _, ss, se = _tlv(buf, os_)
            for tag, gs, ge, _ in _items(buf, ss, se):
                if tag == 0x82:
                    out["san"].append(buf[gs:ge].decode("ascii", "replace"))
                elif tag == 0x87:
                    out["san"].append(str(ipaddress.ip_address(buf[gs:ge])))
        elif oid == "2.5.29.19":  # basicConstraints
            _, bs, be = _tlv(buf, os_)
            first = next(_items(buf, bs, be), None)
            out["is_ca"] = bool(first and first[0] == 0x01 and buf[first[1]] != 0)
        elif oid == "2.5.29.37":  # extendedKeyUsage
            _, ks, ke = _tlv(buf, os_)
            out["eku"] = [EKU_NAMES.get(_oid(buf, a, b), _oid(buf, a, b)) for _, a, b, _ in _items(buf, ks, ke)]
    return out


def parse_cert(der):
    """Parse a DER-encoded X.509 certificate into a plain dict."""
    buf = bytes(der)
    try:
        _, cs, ce, _ = next(_items(buf, 0, len(buf)))
        top = list(_items(buf, cs, ce))
        tbs = list(_items(buf, top[0][1], top[0][2]))
        sig = next(_items(buf, top[1][1], top[1][2]))
        sig_oid = _oid(buf, sig[1], sig[2])
        i = 1 if tbs[0][0] == 0xA0 else 0
        issuer = _name(buf, tbs[i + 2][1], tbs[i + 2][2])
        times = [_time(buf, t, vs, ve) for t, vs, ve, _ in _items(buf, tbs[i + 3][1], tbs[i + 3][2])]
        subject = _name(buf, tbs[i + 4][1], tbs[i + 4][2])
        info = {
            "subject": subject, "issuer": issuer,
            "cn": _pick(subject, "CN") or _pick(subject, "O") or "-",
            "issuer_name": _pick(issuer, "O") or _pick(issuer, "CN") or "-",
            "serial": format(int.from_bytes(buf[tbs[i][1]:tbs[i][2]], "big"), "X"),
            "not_before": times[0], "not_after": times[1],
            "sig_alg": SIG_OIDS.get(sig_oid, sig_oid),
            "self_signed": subject == issuer,
            "sha256": hashlib.sha256(buf).hexdigest().upper(),
            "sha1": hashlib.sha1(buf).hexdigest().upper(),
            "san": [], "has_san": False, "is_ca": False, "eku": [],
        }
        info.update(_public_key(buf, tbs[i + 5]))
        for tag, vs, ve, _ in tbs[i + 6:]:
            if tag == 0xA3:
                info.update(_extensions(buf, vs, ve))
    except (IndexError, ValueError, UnicodeError, StopIteration, TypeError) as exc:
        raise ValueError(f"not a valid X.509 certificate ({exc})") from exc
    return info


def load_cert_file(path):
    """Read a PEM (one or many certificates) or DER file -> list of DER bytes."""
    data = Path(path).read_bytes()
    if b"-----BEGIN CERTIFICATE-----" in data:
        blocks = re.findall(r"-----BEGIN CERTIFICATE-----.*?-----END CERTIFICATE-----",
                            data.decode("ascii", "ignore"), re.S)
        return [ssl.PEM_cert_to_DER_cert(b) for b in blocks]
    return [data]


def host_matches(host, names):
    """Does a certificate (list of DNS/IP names) cover this host? Wildcards match one label."""
    host = host.lower().rstrip(".")
    for name in names:
        name = name.lower().rstrip(".")
        if name == host:
            return True
        if name.startswith("*.") and host.count(".") == name.count(".") and host.endswith(name[1:]):
            return True
    return False


# --------------------------------------------------------- connections ----

def parse_target(raw, default_port=443):
    """'https://Example.com:8443/path' -> ('example.com', 8443)."""
    t = raw.strip()
    if "://" in t:
        t = t.split("://", 1)[1]
    t = t.split("/", 1)[0].split("?", 1)[0]
    if "@" in t:
        t = t.rsplit("@", 1)[1]
    port = default_port
    if t.startswith("["):  # IPv6 literal: [::1]:8443
        host, _, rest = t[1:].partition("]")
        if rest.startswith(":"):
            port = int(rest[1:])
    elif t.count(":") == 1:
        host, p = t.split(":")
        port = int(p)
    else:
        host = t
    if not host or not 0 < port < 65536:
        raise ValueError(f"invalid target: {raw!r}")
    return host.lower(), port


def load_targets(hosts, file, default_port):
    """Return a de-duplicated list of (raw_text, (host, port) or None)."""
    raw = list(hosts)
    if file:
        with open(file, encoding="utf-8") as fh:
            raw += [ln.strip() for ln in fh if ln.strip() and not ln.lstrip().startswith("#")]
    seen, items = set(), []
    for item in raw:
        try:
            target = parse_target(item, default_port)
        except ValueError:
            target = None
        key = target or item
        if key not in seen:
            seen.add(key)
            items.append((item, target))
    return items


def _chain_ders(tls):
    """Certificate chain as DER bytes. Needs Python 3.13+; returns [] on older versions."""
    for name in ("get_verified_chain", "get_unverified_chain"):
        fn = getattr(tls, name, None)
        if fn is None:
            continue
        try:
            chain = [bytes(c) for c in fn() if isinstance(c, (bytes, bytearray))]
        except (ssl.SSLError, ValueError, TypeError):
            continue
        if chain:
            return chain
    return []


def _connect(host, port, timeout, ctx):
    with socket.create_connection((host, port), timeout=timeout) as sock:
        with ctx.wrap_socket(sock, server_hostname=host) as tls:
            return {"der": tls.getpeercert(binary_form=True), "chain": _chain_ders(tls),
                    "protocol": tls.version(), "cipher": (tls.cipher() or ("-",))[0]}


def fetch_cert(host, port, timeout=5.0):
    """Handshake with host:port and read its certificate. Never raises."""
    res = {"host": host, "port": port, "trust_error": None, "error": None,
           "cert": None, "chain": [], "protocol": "-", "cipher": "-"}
    got, tls_reason = None, None
    try:
        got = _connect(host, port, timeout, ssl.create_default_context())
    except ssl.SSLCertVerificationError as exc:
        res["trust_error"] = exc.verify_message or str(exc)
    except socket.gaierror:
        res["error"] = "DNS lookup failed"
    except (socket.timeout, TimeoutError):
        res["error"] = f"timed out after {timeout:g}s"
    except ConnectionRefusedError:
        res["error"] = "connection refused"
    except ssl.SSLError as exc:  # e.g. a weak key or hash this device's TLS policy refuses
        tls_reason = exc.reason or str(exc)
        res["trust_error"] = f"rejected by this device's TLS policy: {tls_reason}"
    except OSError as exc:
        res["error"] = exc.strerror or str(exc)
    if res["error"]:
        return res

    if got is None:  # untrusted cert: reconnect without verification so the details can still be read
        try:
            ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            try:
                ctx.set_ciphers("ALL:@SECLEVEL=0")  # we only read the certificate, nothing is trusted
            except ssl.SSLError:
                pass
            got = _connect(host, port, timeout, ctx)
        except ssl.SSLError as exc:
            res["trust_error"], res["error"] = None, f"TLS error: {tls_reason or exc.reason or exc}"
            return res
        except OSError as exc:
            res["trust_error"], res["error"] = None, f"could not read certificate: {exc}"
            return res
    if not got["der"]:
        res["error"] = "server sent no certificate"
        return res
    try:
        res["cert"] = parse_cert(got["der"])
        res["chain"] = [parse_cert(d) for d in got["chain"]]
    except ValueError as exc:
        res["error"] = str(exc)
        return res
    res["protocol"], res["cipher"] = got["protocol"], got["cipher"]
    return res


def probe_protocol(host, port, timeout, version):
    """'yes' / 'no' / 'untestable' (this device can't speak that version) / 'timeout'."""
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    try:
        if version in (ssl.TLSVersion.TLSv1, ssl.TLSVersion.TLSv1_1):
            ctx.set_ciphers("ALL:@SECLEVEL=0")
        ctx.minimum_version = ctx.maximum_version = version
    except (ValueError, ssl.SSLError):
        return "untestable"
    try:
        with socket.create_connection((host, port), timeout=timeout) as sock:
            with ctx.wrap_socket(sock, server_hostname=host):
                return "yes"
    except ssl.SSLError as exc:
        return "untestable" if "NO_PROTOCOLS" in (exc.reason or "") else "no"
    except (socket.timeout, TimeoutError):
        return "timeout"
    except OSError:
        return "no"


def probe_protocols(host, port, timeout=5.0):
    with warnings.catch_warnings():
        warnings.simplefilter("ignore", DeprecationWarning)
        versions = [(label, ssl.TLSVersion[name]) for label, name in PROTOCOLS]
        with concurrent.futures.ThreadPoolExecutor(max_workers=4) as pool:
            futures = {label: pool.submit(probe_protocol, host, port, timeout, v) for label, v in versions}
            return {label: f.result() for label, f in futures.items()}


# ---------------------------------------------------- status & findings ----

def classify(days, warn, crit):
    if days < 0:
        return "EXPIRED"
    if days <= crit:
        return "CRITICAL"
    if days <= warn:
        return "WARNING"
    return "OK"


def _utcnow():
    return dt.datetime.now(dt.timezone.utc)


def evaluate(res, warn, crit, verify=True, now=None):
    """Add days left and a status to a fetch_cert() result."""
    res.setdefault("days", None)
    res.setdefault("note", None)
    res["warn"], res["crit"] = warn, crit
    if res.get("error"):
        res["status"] = "ERROR"
        return res
    now = now or _utcnow()
    cert = res["cert"]
    res["days"] = (cert["not_after"] - now).days
    status = classify(res["days"], warn, crit)
    if cert["not_before"] > now and status != "EXPIRED":
        status, res["note"] = "INVALID", "certificate is not valid yet"
    elif res.get("trust_error") and verify and status != "EXPIRED":
        status = "INVALID"
    res["status"] = status
    return res


def weak_key(c):
    return (c["key_type"] == "RSA" and c["key_bits"] < 2048) or (c["key_type"] == "EC" and c["key_bits"] < 256)


def weak_sig(c):
    return any(w in c["sig_alg"].lower() for w in ("md5", "sha1"))


def chain_findings(chain, warn, crit, now):
    """Problems with certificates above the leaf (intermediates and root)."""
    out = []
    for i, c in enumerate(chain[1:], start=2):
        role = "root" if c["self_signed"] else "intermediate"
        label = f"{role} '{c['cn']}'"
        days = (c["not_after"] - now).days
        level = classify(days, warn, crit)
        if level == "EXPIRED":
            out.append(("CRIT", f"{label} expired {-days} day(s) ago"))
        elif level == "CRITICAL":
            out.append(("CRIT", f"{label} expires in {days} day(s)"))
        elif level == "WARNING":
            out.append(("WARN", f"{label} expires in {days} day(s)"))
        if weak_key(c):
            out.append(("CRIT", f"{label} has a weak key ({c['key_desc']})"))
        if weak_sig(c) and not c["self_signed"]:
            out.append(("CRIT", f"{label} uses a weak signature ({c['sig_alg']})"))
    return out


def findings_for(res, protocols=None, verify=True, hostname=None, now=None):
    """List of (severity, message). Severities: CRIT, WARN, INFO."""
    now = now or _utcnow()
    c, out = res["cert"], []

    def add(sev, text):
        out.append((sev, text))

    days = res["days"]
    level = classify(days, res["warn"], res["crit"])
    if level == "EXPIRED":
        add("CRIT", f"certificate expired {-days} day(s) ago")
    elif level == "CRITICAL":
        add("CRIT", f"certificate expires in {days} day(s)")
    elif level == "WARNING":
        add("WARN", f"certificate expires in {days} day(s)")
    if c["not_before"] > now:
        add("CRIT", f"certificate is not valid until {c['not_before']:%Y-%m-%d}")
    if res.get("trust_error"):
        err = res["trust_error"]
        add("CRIT" if verify else "INFO", f"not trusted: {err}" + ("" if verify else " (ignored with -k)"))
        if "local issuer" in err.lower():
            add("INFO", "the server may not be sending its intermediate certificate")
    elif c["self_signed"] and not c["is_ca"]:
        add("WARN", "self-signed certificate")
    if weak_key(c):
        add("CRIT", f"weak public key ({c['key_desc']})")
    if weak_sig(c):
        add("CRIT", f"weak signature algorithm ({c['sig_alg']})")
    lifetime = (c["not_after"] - c["not_before"]).days
    if lifetime > 398 and not res.get("trust_error") and not c["self_signed"]:
        add("WARN", f"validity is {lifetime} days (browsers limit public certificates to 398)")
    if not c["has_san"]:
        add("WARN", "no Subject Alternative Names (modern browsers ignore the CN)")
    if any(n.startswith("*.") for n in c["san"]):
        add("INFO", "wildcard certificate: one stolen key covers every subdomain")
    if c["eku"] and "serverAuth" not in c["eku"]:
        add("WARN", "certificate is not marked for server authentication")
    if c["is_ca"]:
        add("WARN", "end-entity certificate has CA:TRUE")
    if hostname and not host_matches(hostname, c["san"] or [c["cn"]]):
        add("CRIT", f"does not cover {hostname}")
    if protocols:
        for label in ("TLS 1.0", "TLS 1.1"):
            if protocols.get(label) == "yes":
                add("WARN", f"deprecated protocol enabled: {label}")
        if protocols.get("TLS 1.2") == "no" and protocols.get("TLS 1.3") == "no":
            add("CRIT", "no modern TLS (neither 1.2 nor 1.3)")
        elif protocols.get("TLS 1.2") == "no":
            add("WARN", "TLS 1.2 not supported")
        elif protocols.get("TLS 1.3") == "no":
            add("INFO", "TLS 1.3 not supported")
    out += chain_findings(res.get("chain") or [], res["warn"], res["crit"], now)
    return out


def grade(findings):
    sev = [s for s, _ in findings]
    if "CRIT" in sev:
        return "F"
    warns = sev.count("WARN")
    return "A" if warns == 0 else "B" if warns == 1 else "C"


# ------------------------------------------------------------ baseline ----

def _iso(d):
    return d.isoformat()


def baseline_key(r):
    return f"{r['host']}:{r['port']}"


def save_baseline(path, results):
    p = Path(path)
    data = json.loads(p.read_text()) if p.exists() else {}
    saved = 0
    for r in results:
        c = r.get("cert")
        if c:
            data[baseline_key(r)] = {"sha256": c["sha256"], "issuer": c["issuer_name"],
                                     "not_before": _iso(c["not_before"]), "not_after": _iso(c["not_after"]),
                                     "saved": _iso(_utcnow())}
            saved += 1
    p.write_text(json.dumps(data, indent=2))
    return saved


def apply_baseline(results, path):
    """Compare each certificate's fingerprint with a saved baseline."""
    data = json.loads(Path(path).read_text())
    for r in results:
        c = r.get("cert")
        if not c:
            continue
        old = data.get(baseline_key(r))
        if old is None:
            r["baseline"], note = "new", "not in baseline"
        elif old["sha256"] == c["sha256"]:
            r["baseline"], note = "same", None
        elif c["not_before"] > dt.datetime.fromisoformat(old["not_before"]) and old["issuer"] == c["issuer_name"]:
            r["baseline"], note = "renewed", "renewed since baseline (new certificate, same issuer)"
        else:
            r["baseline"], note = "changed", "CERTIFICATE CHANGED since baseline"
            if r["status"] in ("OK", "WARNING", "CRITICAL"):
                r["status"] = "CHANGED"
        if note:
            r["note"] = f"{r['note']}; {note}" if r.get("note") else note
    return results


# ------------------------------------------------------------- running ----

def check_one(item, args):
    raw, target = item
    if target is None:
        return {"host": raw, "port": 0, "error": "invalid target", "trust_error": None,
                "days": None, "status": "ERROR", "cert": None, "chain": [], "note": None}
    res = fetch_cert(target[0], target[1], args.timeout)
    return evaluate(res, args.warn, args.crit, verify=not args.insecure)


def audit_one(item, args):
    res = check_one(item, args)
    if res["status"] == "ERROR":
        res.update(protocols=None, findings=[("CRIT", f"could not check: {res['error']}")], grade="-")
        return res
    protocols = None if args.no_protocols else probe_protocols(res["host"], res["port"], args.timeout)
    res["protocols"] = protocols
    res["findings"] = findings_for(res, protocols, verify=not args.insecure)
    res["grade"] = grade(res["findings"])
    return res


def run_parallel(func, items, args, quiet, text):
    workers = max(1, min(8, len(items)))
    with Progress(SpinnerColumn(), TextColumn("[cyan]{task.description}"), console=err_console,
                  transient=True, disable=quiet or len(items) < 2) as progress:
        progress.add_task(text.format(n=len(items)), total=None)
        with concurrent.futures.ThreadPoolExecutor(max_workers=workers) as pool:
            return list(pool.map(lambda it: func(it, args), items))


def sort_results(results):
    results.sort(key=lambda r: (RANK[r["status"]], r["days"] if r["days"] is not None else 0))
    return results


# -------------------------------------------------------------- output ----

def fmt_dt(d):
    return d.strftime("%Y-%m-%d %H:%M UTC")


def label(r):
    return r["host"] if r["port"] in (0, 443) else f"{r['host']}:{r['port']}"


def render_table(results):
    table = Table(title="ChronoCert", header_style="bold cyan")
    table.add_column("Host", overflow="fold")
    table.add_column("Status")
    table.add_column("Days", justify="right")
    table.add_column("Expires")
    for r in results:
        cell = f"[bold {COLORS[r['status']]}]{r['status']}[/]"
        note = r.get("error") or r.get("trust_error")
        if r.get("note"):
            note = f"{note}; {r['note']}" if note else r["note"]
        if note:
            cell += f"\n[dim]{escape(note)}[/]"
        expires = r["cert"]["not_after"].strftime("%Y-%m-%d") if r.get("cert") else "-"
        table.add_row(escape(label(r)), cell, "-" if r["days"] is None else str(r["days"]), expires)
    console.print(table)
    counts = {}
    for r in results:
        counts[r["status"]] = counts.get(r["status"], 0) + 1
    console.print("  ".join(f"[{COLORS[s]}]{counts[s]} {s.lower()}[/]" for s in RANK if s in counts))


def print_report(title, sections):
    table = Table(title=escape(title), header_style="bold cyan", show_header=False)
    table.add_column("Field", style="bold")
    table.add_column("Value", overflow="fold")
    for name, rows in sections:
        if not rows:
            continue
        table.add_section()
        table.add_row(f"[bold cyan]{name}[/]", "")
        for k, v, *style in rows:
            v = escape(str(v))
            table.add_row(escape(str(k)), f"[{style[0]}]{v}[/]" if style and style[0] else v)
    console.print(table)


def cert_rows(res):
    c = res["cert"]
    names = c["san"]
    return [
        ("Subject", c["cn"]),
        ("Issuer", c["issuer_name"]),
        ("Days left", res["days"], COLORS[classify(res["days"], res["warn"], res["crit"])]),
        ("Valid from", fmt_dt(c["not_before"])),
        ("Expires", fmt_dt(c["not_after"])),
        ("Key", c["key_desc"], "red" if weak_key(c) else "green"),
        ("Signature", c["sig_alg"], "red" if weak_sig(c) else "green"),
        ("Names (SAN)", f"{len(names)}: " + ", ".join(names[:6]) + (" ..." if len(names) > 6 else "")),
        ("CA certificate", "yes" if c["is_ca"] else "no"),
        ("Serial", c["serial"]),
        ("SHA-256", ":".join(c["sha256"][i:i + 2] for i in range(0, 64, 2))),
    ]


def chain_rows(res, now):
    rows = []
    for i, c in enumerate(res.get("chain") or [], start=1):
        role = "leaf" if i == 1 else "root" if c["self_signed"] else "intermediate"
        days = (c["not_after"] - now).days
        level = classify(days, res["warn"], res["crit"])
        rows.append((f"{i}. {role}", f"{c['cn']} | {c['key_desc']} | {days}d",
                     "" if level == "OK" else COLORS[level]))
    return rows


def finding_rows(findings):
    if not findings:
        return [("OK", "no issues found", "green")]
    order = {"CRIT": 0, "WARN": 1, "INFO": 2}
    return [(sev, text, SEV_COLOR[sev]) for sev, text in sorted(findings, key=lambda f: order[f[0]])]


def protocol_rows(protocols):
    rows = []
    for label_, state in (protocols or {}).items():
        bad = label_ in ("TLS 1.0", "TLS 1.1") and state == "yes"
        style = "red" if bad else "green" if state == "yes" else "dim" if state in ("no", "untestable") else "yellow"
        text = {"untestable": "untestable here", "no": "not offered", "yes": "offered"}.get(state, state)
        rows.append((label_, text + (" (deprecated)" if bad else ""), style))
    return rows


def render_audit(res):
    now = _utcnow()
    if res["status"] == "ERROR":
        print_report(label(res), [("SUMMARY", [("Status", "ERROR", "bold red"), ("Error", res["error"], "red")])])
        return
    summary = [("Grade", res["grade"], "bold " + {"A": "green", "B": "yellow", "C": "yellow", "F": "red"}[res["grade"]]),
               ("Status", res["status"], "bold " + COLORS[res["status"]])]
    chain = chain_rows(res, now) or [("chain", "not available (needs Python 3.13+)", "dim")]
    print_report(label(res), [
        ("SUMMARY", summary), ("CERTIFICATE", cert_rows(res)),
        ("CONNECTION", [("TLS version", res["protocol"]), ("Cipher", res["cipher"])]),
        ("PROTOCOLS", protocol_rows(res.get("protocols"))), ("CHAIN", chain),
        ("FINDINGS", finding_rows(res["findings"]))])


def cert_json(c):
    return {"subject": dict(c["subject"]), "issuer": dict(c["issuer"]), "serial": c["serial"],
            "not_before": _iso(c["not_before"]), "not_after": _iso(c["not_after"]),
            "key": c["key_desc"], "signature": c["sig_alg"], "names": c["san"],
            "is_ca": c["is_ca"], "self_signed": c["self_signed"], "sha256": c["sha256"], "sha1": c["sha1"]}


def to_json(r):
    out = {"host": r["host"], "port": r["port"], "status": r["status"], "days_left": r["days"]}
    if r.get("error"):
        out["error"] = r["error"]
        return out
    out.update({"tls_version": r["protocol"], "cipher": r["cipher"], "trust_error": r.get("trust_error"),
                "note": r.get("note"), "certificate": cert_json(r["cert"]),
                "chain": [cert_json(c) for c in r.get("chain") or []]})
    if "baseline" in r:
        out["baseline"] = r["baseline"]
    if "grade" in r:
        out.update({"grade": r["grade"], "protocols": r["protocols"],
                    "findings": [{"severity": s, "message": m} for s, m in r["findings"]]})
    return out


# ------------------------------------------------------------ commands ----

def cmd_check(args):
    items = load_targets(args.hosts, args.file, args.port)
    if not items:
        err_console.print("[red]Give at least one host, or -f FILE.[/]")
        return 2
    results = run_parallel(check_one, items, args, args.json, "checking {n} hosts")
    if args.baseline:
        try:
            apply_baseline(results, args.baseline)
        except (OSError, ValueError, KeyError) as exc:
            err_console.print(f"[red]Cannot use baseline:[/] {escape(str(exc))}")
            return 2
    sort_results(results)
    if args.save_baseline:
        n = save_baseline(args.save_baseline, results)
        err_console.print(f"[green]Baseline saved:[/] {n} host(s) -> {escape(args.save_baseline)}")
    if args.json:
        print(json.dumps([to_json(r) for r in results], indent=2))
    else:
        render_table(results)
    return 0 if all(r["status"] == "OK" for r in results) else 1


def cmd_audit(args):
    items = load_targets(args.hosts, None, args.port)
    results = run_parallel(audit_one, items, args, args.json, "auditing {n} hosts")
    if args.json:
        print(json.dumps([to_json(r) for r in results], indent=2))
    else:
        for r in results:
            render_audit(r)
    return 0 if all(r["grade"] in ("A", "B", "C") for r in results) else 1


def cmd_inspect(args):
    try:
        chain = [parse_cert(d) for d in load_cert_file(args.file)]
    except (OSError, ValueError) as exc:
        err_console.print(f"[red]Cannot read certificate:[/] {escape(str(exc))}")
        return 2
    if not chain:
        err_console.print("[red]No certificate found in that file.[/]")
        return 2
    res = evaluate({"host": Path(args.file).name, "port": 0, "error": None, "trust_error": None,
                    "cert": chain[0], "chain": chain, "protocol": "-", "cipher": "-"}, args.warn, args.crit)
    res["findings"] = findings_for(res, hostname=args.host)
    res["grade"] = grade(res["findings"])
    res["protocols"] = None
    if args.json:
        print(json.dumps(to_json(res), indent=2))
    else:
        sections = [("SUMMARY", [("Grade", res["grade"], "bold " + {"A": "green", "B": "yellow", "C": "yellow", "F": "red"}[res["grade"]]),
                                 ("Status", res["status"], "bold " + COLORS[res["status"]])]),
                    ("CERTIFICATE", cert_rows(res))]
        if args.host:
            ok = host_matches(args.host, chain[0]["san"] or [chain[0]["cn"]])
            sections.append(("HOSTNAME", [(args.host, "covered" if ok else "NOT covered", "green" if ok else "red")]))
        if len(chain) > 1:
            sections.append(("CHAIN IN FILE", chain_rows(res, _utcnow())))
        sections.append(("FINDINGS", finding_rows(res["findings"])))
        print_report(res["host"], sections)
    return 0 if res["grade"] != "F" else 1


# ----------------------------------------------------------------- CLI ----

def _thresholds(p):
    p.add_argument("-w", "--warn", type=int, default=DEFAULT_WARN, metavar="DAYS",
                   help=f"warning threshold (default {DEFAULT_WARN})")
    p.add_argument("-c", "--crit", type=int, default=DEFAULT_CRIT, metavar="DAYS",
                   help=f"critical threshold (default {DEFAULT_CRIT})")
    p.add_argument("--json", action="store_true", help="JSON output")


def _network(p):
    p.add_argument("-p", "--port", type=int, default=443, help="default port (default 443)")
    p.add_argument("-t", "--timeout", type=float, default=5.0, help="connect timeout in seconds (default 5)")
    p.add_argument("-k", "--insecure", action="store_true",
                   help="don't fail on self-signed/untrusted certs; judge by expiry only")


def build_parser():
    parser = argparse.ArgumentParser(
        prog="chronocert",
        description="ChronoCert - TLS certificate toolkit. Part of the CHRONO SUITE.",
        epilog=f"Dev: {DEV}  |  {DISCLAIMER}")
    parser.add_argument("-V", "--version", action="version", version=f"ChronoCert {VERSION} (Dev: {DEV})")
    sub = parser.add_subparsers(dest="command", required=True, metavar="{check,audit,inspect}")

    p = sub.add_parser("check", help="expiry check for one or many hosts (default command)")
    p.add_argument("hosts", nargs="*", help="host, host:port or https://host/...")
    p.add_argument("-f", "--file", metavar="FILE", help="file with one host per line (# for comments)")
    p.add_argument("--baseline", metavar="FILE", help="compare certificate fingerprints with a saved baseline")
    p.add_argument("--save-baseline", metavar="FILE", help="save current fingerprints (after comparing)")
    _network(p)
    _thresholds(p)
    p.set_defaults(func=cmd_check)

    p = sub.add_parser("audit", help="full audit: key, signature, protocols, chain, findings, grade")
    p.add_argument("hosts", nargs="+", help="host, host:port or https://host/...")
    p.add_argument("--no-protocols", action="store_true", help="skip the TLS version probe")
    _network(p)
    _thresholds(p)
    p.set_defaults(func=cmd_audit)

    p = sub.add_parser("inspect", help="analyse a certificate file offline (PEM or DER)")
    p.add_argument("file", help="certificate file (a PEM bundle shows the chain)")
    p.add_argument("--host", metavar="NAME", help="check that the certificate covers this hostname")
    _thresholds(p)
    p.set_defaults(func=cmd_inspect)
    return parser


def main():
    parser = build_parser()
    argv = sys.argv[1:]
    if not argv:
        show_banner()
        parser.print_help()
        sys.exit(0)
    if argv[0] not in SUBCOMMANDS and argv[0] not in ("-h", "--help", "-V", "--version"):
        argv.insert(0, "check")  # `chronocert example.com` still works
    args = parser.parse_args(argv)
    if args.crit >= args.warn:
        parser.error("--crit must be lower than --warn")
    try:
        sys.exit(args.func(args))
    except KeyboardInterrupt:
        err_console.print("\n[yellow]Interrupted.[/]")
        sys.exit(130)
    except OSError as exc:
        err_console.print(f"[red]Error:[/] {escape(str(exc))}")
        sys.exit(2)


if __name__ == "__main__":
    main()
