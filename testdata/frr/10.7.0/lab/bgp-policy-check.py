# Checks one captured transcript of the BGP policy lab (lab/bgp-policy.sh). The lab runs this file
# on each capture, and internal/app's self-check runs the same file over committed FRR output and
# over edited copies, so the two cannot disagree about what a term means.
# Usage:
#   python3 -I bgp-policy-check.py FILE json CMD PROMPT TERM...
#   python3 -I bgp-policy-check.py FILE text PROMPT TERM...
# A json file is the echoed CMD, CRLF, one strict JSON object, CRLF, and PROMPT with nothing after
# it. Duplicate keys, NaN, and Infinity fail. A text file ends with CRLF and PROMPT and holds no
# "% ", which FRR prints for a rejected line. Exit 0 only if the file and every TERM pass; exit 1
# if one does not; exit 2 for a usage error. A TERM is op:arg, and only these ops are read:
#   json  est:ADDR            a dict under key ADDR has a direct value "Established".
#         key:NAME            a key NAME is present at some depth.
#         paths:PREFIX=ID,ID  routes[PREFIX] lists exactly these peerId values, as a sorted multiset.
#         best:PREFIX=ID,ID   exactly these peerId values are on PREFIX's paths with "bestpath": true.
#         weight:PREFIX=ID=N  a path of PREFIX from peerId ID has "weight": N.
#         absent:PREFIX       routes has no key PREFIX.
#   text  has:TEXT            TEXT appears in the file.
#         lacks:TEXT          TEXT does not appear in the file.
#         inaf:TEXT           a line, stripped, equals TEXT and lies between a line
#                             "address-family ipv4 unicast" and the next "exit-address-family".
# Any other op fails. Other fields are never read.
import json
import sys


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
        return any(str(p.get("peerId")) == ident and p.get("weight") == int(value) for p in ps)
    return False


def text_term(t, op, arg):
    if op == "has":
        return arg in t
    if op == "lacks":
        return arg not in t
    if op == "inaf":
        inside = False
        for line in t.split("\n"):
            s = line.strip()
            if s == "address-family ipv4 unicast":
                inside = True
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
    if len(argv) < 4 or argv[2] not in ("json", "text"):
        sys.exit(2)
    with open(argv[1], "rb") as fh:
        raw = fh.read()
    if argv[2] == "json":
        if len(argv) < 5:
            sys.exit(2)
        cmd, prompt, terms = argv[3], argv[4], argv[5:]
        head = cmd.encode() + b"\r\n"
        tail = b"\r\n" + prompt.encode()
        if len(raw) < len(head) + len(tail) or not raw.startswith(head) or not raw.endswith(tail):
            sys.exit(1)
        d = json.loads(raw[len(head):len(raw) - len(tail)].decode("utf-8"), object_pairs_hook=pairs, parse_constant=bad)
        if not isinstance(d, dict):
            sys.exit(1)
        ok = all(json_term(d, *split(term)) for term in terms)
    else:
        prompt, terms = argv[3], argv[4:]
        if not raw.endswith(b"\r\n" + prompt.encode()) or b"% " in raw:
            sys.exit(1)
        t = raw.decode("utf-8")
        ok = all(text_term(t, *split(term)) for term in terms)
    sys.exit(0 if ok else 1)


if __name__ == "__main__":
    main(sys.argv)
