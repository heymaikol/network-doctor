# Checks one captured transcript of the BGP policy lab (lab/bgp-policy.sh). The lab runs this file
# on each capture, and internal/app's self-check runs the same file over committed FRR output and
# over edited copies, so the two cannot disagree about what a term means.
# Usage, with the capture on stdin. The checker takes no file path:
#   python3 -I bgp-policy-check.py json CMD PROMPT TERM... < capture
#   python3 -I bgp-policy-check.py text PROMPT TERM... < transcript
# It reads at most MAX_BYTES + 1 bytes, and more than MAX_BYTES fails. A json capture is the echoed
# CMD, CRLF, one strict JSON object, CRLF, and PROMPT with nothing after it. Duplicate keys, NaN, and
# Infinity fail. A text transcript ends with CRLF and PROMPT and holds no "% ", which FRR prints for a
# rejected line. Exit 0 only if the input and every TERM pass; exit 1 if one does not, including input
# that fails to decode or parse; exit 2 for a usage error, and for a text transcript that passes its
# framing but has no TERM. A TERM is op:arg, only these ops are read, and a TERM with an empty arg fails:
#   json  est:ADDR            a dict under key ADDR has a direct value "Established".
#         key:NAME            a key NAME is present at some depth.
#         paths:PREFIX=ID,ID  routes[PREFIX] lists exactly these peerId values, as a sorted multiset.
#         best:PREFIX=ID,ID   exactly these peerId values are on PREFIX's paths with "bestpath": true.
#         weight:PREFIX=ID=N  a path of PREFIX from peerId ID has "weight": N, a JSON integer.
#         absent:PREFIX       routes has no key PREFIX.
#   text  has:TEXT            TEXT appears in the input as a whole token: no letter, digit, "_",
#                             ".", "/", or "-" touches either end of it.
#         lacks:TEXT          TEXT does not appear in the input, as a substring.
#         inaf:TEXT           a line, stripped, equals TEXT and lies between a line
#                             "address-family ipv4 unicast" and the next "exit-address-family".
#                             Any other "address-family" line ends that part.
# Any other op fails. Other fields are never read.
import json
import re
import sys

# The most input bytes the checker reads. A lab capture is a few kilobytes, so this is a ceiling only.
MAX_BYTES = 1 << 20


def bad(c):
    raise ValueError(c)


def pairs(p):
    d = {}
    for k, v in p:
        if k in d:
            bad("duplicate key")
        d[k] = v
    return d


def find(o, k):
    if isinstance(o, dict):
        for kk, v in o.items():
            if kk == k:
                yield v
            yield from find(v, k)
    elif isinstance(o, list):
        for v in o:
            yield from find(v, k)


def paths_of(d, prefix):
    routes = d.get("routes")
    ps = routes.get(prefix) if isinstance(routes, dict) else None
    if not isinstance(ps, list) or not all(isinstance(p, dict) for p in ps):
        return None
    return ps


def json_term(d, op, arg):
    if not arg:
        return False
    if op == "est":
        return any(isinstance(v, dict) and "Established" in v.values() for v in find(d, arg))
    if op == "key":
        return any(True for _ in find(d, arg))
    if op == "absent":
        routes = d.get("routes")
        return isinstance(routes, dict) and arg not in routes
    prefix, _, rest = arg.partition("=")
    ps = paths_of(d, prefix)
    if ps is None:
        return False
    if op == "paths":
        return sorted(str(p.get("peerId")) for p in ps) == sorted(rest.split(","))
    if op == "best":
        return sorted(str(p.get("peerId")) for p in ps if p.get("bestpath") is True) == sorted(rest.split(","))
    if op == "weight":
        ident, _, value = rest.partition("=")
        return any(str(p.get("peerId")) == ident and type(p.get("weight")) is int and p["weight"] == int(value) for p in ps)
    return False


def text_term(t, op, arg):
    if not arg:
        return False
    if op == "has":
        # Whole token only: permit 10 does not match permit 100, nor R3-IN match R3-IN-old.
        return re.search(r"(?<![\w./-])" + re.escape(arg) + r"(?![\w./-])", t) is not None
    if op == "lacks":
        return arg not in t
    if op == "inaf":
        inside = False
        for line in t.split("\n"):
            s = line.strip()
            if s.startswith("address-family "):
                inside = s == "address-family ipv4 unicast"
            elif s == "exit-address-family":
                inside = False
            elif inside and s == arg:
                return True
        return False
    return False


def split(term):
    op, _, arg = term.partition(":")
    return op, arg


def main(argv):
    if len(argv) < 3 or argv[1] not in ("json", "text") or (argv[1] == "json" and len(argv) < 4):
        sys.exit(2)
    raw = sys.stdin.buffer.read(MAX_BYTES + 1)
    if len(raw) > MAX_BYTES:
        sys.exit(1)
    # Malformed input raises ValueError (JSON, UTF-8, NaN, duplicate keys) or RecursionError (deep
    # nesting). Both exit 1, with no traceback and no pass.
    try:
        if argv[1] == "json":
            cmd, prompt, terms = argv[2], argv[3], argv[4:]
            head = cmd.encode() + b"\r\n"
            tail = b"\r\n" + prompt.encode()
            if len(raw) < len(head) + len(tail) or not raw.startswith(head) or not raw.endswith(tail):
                sys.exit(1)
            d = json.loads(raw[len(head):len(raw) - len(tail)].decode("utf-8"), object_pairs_hook=pairs, parse_constant=bad)
            if not isinstance(d, dict):
                sys.exit(1)
            ok = all(json_term(d, *split(term)) for term in terms)
        else:
            prompt, terms = argv[2], argv[3:]
            if not raw.endswith(b"\r\n" + prompt.encode()) or b"% " in raw:
                sys.exit(1)
            if not terms:
                sys.exit(2)
            t = raw.decode("utf-8")
            ok = all(text_term(t, *split(term)) for term in terms)
    except (ValueError, RecursionError):
        sys.exit(1)
    sys.exit(0 if ok else 1)


if __name__ == "__main__":
    main(sys.argv)
