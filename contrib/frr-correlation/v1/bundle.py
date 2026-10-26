"""Package explicit instrumented-FRR edges. This is not a Network Doctor importer.

Claims concern historical operation results. No current FIB snapshot, forwarding
rating, packet delivery, or convergence conclusion is produced.
"""

import argparse
import hashlib
import ipaddress
import json
import os
from pathlib import Path
import re
import stat
import sys

SCHEMA = "netdoc-frr-correlation/v1"
SOURCE = "87fe21fda92ce9e2ba3eaf2b0a327bf71ee183ef"
ORIGINS = {"bgp", "ospf", "connected", "static", "local"}
VERIFIED_ORIGINS = ORIGINS - {"ospf"}
UUID = r"[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}"


class Refused(ValueError):
    pass


def require(condition, reason):
    if not condition:
        raise Refused(reason)


def pairs(items):
    result = {}
    for key, value in items:
        require(key not in result, "duplicate JSON key")
        result[key] = value
    return result


def constant(value):
    raise Refused("non-finite JSON value: " + value)


def decode(raw):
    return json.loads(raw, object_pairs_hook=pairs, parse_constant=constant)


def read_source(path, limit):
    # Opening first avoids a check-then-open symlink race; nonblocking rejects FIFOs.
    fd = os.open(path, os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW | os.O_NONBLOCK)
    with os.fdopen(fd, "rb") as source:
        require(stat.S_ISREG(os.fstat(source.fileno()).st_mode), "non-regular source file")
        raw = source.read(limit + 1)
        require(len(raw) <= limit, "source file size limit")
        return raw


def integer(value):
    return type(value) is int and 0 <= value < 2**64


def reference(row):
    return row["epoch"] + ":" + str(row["seq"])


def identity(value, epoch, kind):
    return isinstance(value, str) and re.fullmatch(re.escape(epoch) + "/" + kind + r"/[1-9][0-9]*", value)


def supported(row):
    require(isinstance(row["prefix"], str), "invalid route prefix type")
    network = ipaddress.ip_network(row["prefix"], strict=True)
    return network.version == 4 and type(row["vrf"]) is int and row["vrf"] == 0 \
        and type(row["table"]) is int and row["table"] == 254 and row.get("safi") == 1


def streams(directory, build):
    pinned = decode(Path(__file__).with_name("verified-build.json").read_bytes())
    require(build == pinned, "unsupported build or runtime manifest")
    require(build.get("schema") == "netdoc-frr-build/v1" and build.get("source") == SOURCE,
            "unsupported build manifest")
    files = sorted(Path(directory).glob("*.jsonl"))
    require(len(files) == 2, "need exactly one closed bgpd epoch and one closed zebra epoch; restarts require a new capture")
    sources, events = [], {}
    for path in files:
        raw = read_source(path, 67108864)
        require(raw.endswith(b"\n"), "truncated source")
        lines = raw.splitlines()
        require(2 <= len(lines) <= 1000000 and all(len(l) <= 65535 for l in lines), "source bounds")
        rows = [decode(line) for line in lines]
        start, end = rows[0], rows[-1]
        require(start["event"] == "start" and end["event"] == "end" and end.get("complete") is True,
                "missing complete source trailer")
        require(start.get("schema") == SCHEMA and start.get("build_id") == build.get("build_id")
                and start.get("frr_source") == SOURCE and start.get("os") == "linux"
                and start.get("machine") == "x86_64", "unsupported producer build, schema, or operating system")
        require(start.get("kernel") == build.get("verified_kernel"), "kernel outside verified subset")
        epoch, daemon = start["epoch"], start["daemon"]
        require(isinstance(epoch, str) and re.fullmatch(UUID, epoch) and daemon in ("bgpd", "zebra"), "invalid source identity")
        require(path.name == f"{daemon}.{epoch}.jsonl" and daemon not in events, "contradictory source epochs")
        require(integer(start["netns_inode"]) and re.fullmatch(UUID, start["boot_id"]), "missing namespace or boot identity")
        previous = 0
        for seq, row in enumerate(rows, 1):
            require(row["epoch"] == epoch and row["daemon"] == daemon and type(row["seq"]) is int
                    and row["seq"] == seq, "event gap or epoch mismatch")
            require(integer(row["monotonic_ns"]) and row["monotonic_ns"] >= previous
                    and integer(row["utc_ns"]), "invalid source clock")
            previous = row["monotonic_ns"]
            for key in ("revision", "generation", "resolver_generation", "dplane_sequence", "netlink_sequence",
                        "vrf", "table", "safi", "nhg", "selection_generation", "remote_as", "local_as", "leg",
                        "lookup_flags", "resolving_vrf", "resolver_table", "terminal_ifindex"):
                if key in row:
                    require(integer(row[key]), "invalid integer field: " + key)
            if "error" in row:
                require(type(row["error"]) is int and -(2**31) <= row["error"] < 2**31, "invalid kernel error type")
        events[daemon] = rows
        sources.append({"epoch": epoch, "daemon": daemon, "file": path.name,
                        "sha256": hashlib.sha256(raw).hexdigest(), "records": len(rows),
                        "netns_inode": start["netns_inode"], "boot_id": start["boot_id"],
                        "start_monotonic_ns": start["monotonic_ns"],
                        "end_monotonic_ns": end["monotonic_ns"]})
    require({s["daemon"] for s in sources} == {"bgpd", "zebra"}, "missing daemon source")
    require(len({(s["netns_inode"], s["boot_id"]) for s in sources}) == 1, "mixed namespaces or boots")
    return sources, events


def produce(directory, build):
    sources, events = streams(directory, build)
    output = {"schema": SCHEMA, "producer": build,
              "capture": {"complete": True, "snapshot_complete": False,
                          "scope": "closed producer histories; historical claims only",
                          "netns_inode": sources[0]["netns_inode"], "boot_id": sources[0]["boot_id"],
                          "gaps": []}, "sources": sources, "bgp_paths": [], "routes": [],
              "fib_entries": [], "resolutions": [], "claims": [], "refusals": []}

    def refusal(row, reason):
        output["refusals"].append({"source_ref": reference(row), "reason": reason})

    paths, submissions, sessions, revisions = {}, {}, {}, {}
    bgp_epoch = events["bgpd"][0]["epoch"]
    for row in events["bgpd"][1:-1]:
        kind = row["event"]
        if kind == "peer_state":
            sessions[row["peer_id"]] = (row["session_id"], row["state"])
        elif kind == "bgp_path":
            require(identity(row["path_id"], bgp_epoch, "path") and identity(row["peer_id"], bgp_epoch, "peer")
                    and identity(row["session_id"], bgp_epoch, "session"), "invalid BGP object identity")
            require(type(row["revision"]) is int and row["revision"] == revisions.get(row["path_id"], 0) + 1,
                    "path revision gap or duplicate")
            revisions[row["path_id"]] = row["revision"]
            require(sessions.get(row["peer_id"]) == (row["session_id"], "Established"), "stale or unrecorded peer session")
            require(supported(row) and row["valid"] is True and row["stale"] is False, "unsupported or stale BGP path")
            require(isinstance(row["peer_address"], str) and isinstance(row["nexthop"], str) and
                    ipaddress.ip_address(row["peer_address"]).version == 4 and
                    ipaddress.ip_address(row["nexthop"]).version == 4, "unsupported BGP address family")
            paths[(row["path_id"], row["revision"])] = row
            output["bgp_paths"].append(row)
        elif kind == "bgp_submission":
            token, contributors = row["announcement_id"], row["contributors"]
            require(identity(token, bgp_epoch, "announcement") and token not in submissions, "invalid or duplicate announcement")
            require(1 <= len(contributors) <= 64 and {c["leg"] for c in contributors} == set(range(len(contributors))),
                    "incomplete contributor ordinals")
            require(len({c["path_id"] for c in contributors}) == len(contributors), "duplicate contributor")
            for c in contributors:
                path = paths.get((c["path_id"], c["revision"]))
                require(path is not None and all(c[k] == path[k] for k in ("peer_id", "session_id")), "missing or contradictory path edge")
                require(all(row[k] == path[k] for k in ("prefix", "vrf", "table")), "contradictory submission context")
            submissions[token] = row
        elif kind == "refusal":
            refusal(row, row["reason"])
        else:
            raise Refused("unknown BGP event")

    routes, selections, operations, sends, acks, resolutions, results = {}, {}, {}, {}, {}, {}, set()
    verified_resolutions = set()
    zebra_epoch = events["zebra"][0]["epoch"]

    def route_key(row):
        return row["route_id"], row["generation"]

    def operation_match(row, original):
        return all(row[k] == original[k] for k in ("route_id", "generation", "operation", "prefix", "vrf", "table", "safi", "dplane_sequence"))

    for row in events["zebra"][1:-1]:
        kind = row["event"]
        if kind in ("route_received", "route_generation"):
            require(identity(row["route_id"], zebra_epoch, "route") and type(row["generation"]) is int
                    and row["generation"] > 0, "invalid Zebra route identity")
            key = route_key(row)
            require(key not in routes, "duplicate route generation")
            if kind == "route_received":
                require(row["generation"] == 1, "route generation starts late")
            else:
                previous = routes.get((row["route_id"], row["generation"] - 1))
                require(previous is not None and all(row.get(k) == previous.get(k)
                        for k in ("origin", "prefix", "vrf", "table", "safi", "announcement_id", "contributors")), "route replacement without new identity")
            routes[key] = row
            output["routes"].append(row)
            if not supported(row) or row["origin"] not in VERIFIED_ORIGINS:
                refusal(row, "unsupported route context or unmapped origin")
                continue
            if row["origin"] == "bgp":
                token = row.get("announcement_id")
                if token is None:
                    refusal(row, "BGP route has no explicit submission identity")
                    continue
                submission = submissions.get(token)
                require(submission is not None, "missing BGP submission")
                require(row["contributors"] == submission["contributors"] and
                        all(row[k] == submission[k] for k in ("prefix", "vrf", "table")), "contradictory path-to-route edge")
                for c in row["contributors"]:
                    output["claims"].append({"type": "path_submitted_as_route", "path_id": c["path_id"],
                        "path_revision": c["revision"], "peer_id": c["peer_id"], "session_id": c["session_id"],
                        "route_id": row["route_id"], "generation": row["generation"],
                        "source_refs": [reference(paths[(c["path_id"], c["revision"])]), reference(submission), reference(row)]})
        elif kind == "selection":
            destination = row["destination_id"]
            require(identity(destination, zebra_epoch, "destination") and
                    row["selection_generation"] == selections.get(destination, 0) + 1, "selection generation gap")
            selections[destination] = row["selection_generation"]
            if row["route_id"] is not None:
                require(route_key(row) in routes, "selection names missing route generation")
        elif kind == "resolution":
            consumer, resolver = routes.get(route_key(row)), routes.get((row["resolver_id"], row["resolver_generation"]))
            require(consumer is not None and resolver is not None, "missing resolution object edge")
            require(row["resolver_origin"] == resolver["origin"] and row["resolver_prefix"] == resolver["prefix"], "contradictory resolver identity")
            require(identity(row["resolution_id"], zebra_epoch, "resolution") and row["resolution_id"] not in resolutions,
                    "invalid or duplicate resolution identity")
            resolutions[row["resolution_id"]] = row
            output["resolutions"].append(row)
            if row["supported"] is not True or not supported(consumer) or not supported(resolver) \
                    or consumer["origin"] not in VERIFIED_ORIGINS or resolver["origin"] not in VERIFIED_ORIGINS \
                    or (row["recursive"] and (consumer["origin"], resolver["origin"]) != ("static", "bgp")):
                refusal(row, "unsupported recursive lookup context")
                continue
            verified_resolutions.add(row["resolution_id"])
            output["claims"].append({"type": "route_leg_resolved_by_route", "route_id": row["route_id"],
                "generation": row["generation"], "resolver_id": row["resolver_id"],
                "resolver_generation": row["resolver_generation"], "resolution_id": row["resolution_id"],
                "leg": row["leg"], "source_refs": [reference(row), reference(consumer), reference(resolver)]})
        elif kind == "operation":
            key = row["operation_id"]
            require(identity(key, zebra_epoch, "operation") and key not in operations and route_key(row) in routes, "invalid dataplane operation edge")
            route = routes[route_key(row)]
            require(all(row[k] == route[k] for k in ("prefix", "vrf", "table", "safi")), "contradictory operation context")
            refs = row["resolution_refs"]
            require(integer(row["source_leg_count"]) and len(refs) == min(row["source_leg_count"], 64)
                    and [r["leg"] for r in refs] == list(range(len(refs))), "incomplete operation leg inventory")
            for ref in refs:
                if ref["resolution_id"] is None:
                    continue
                edge = resolutions.get(ref["resolution_id"])
                require(edge is not None and route_key(edge) == route_key(row) and edge["leg"] == ref["leg"],
                        "missing or contradictory operation-to-resolution edge")
            operations[key] = row
        elif kind in ("netlink_send", "netlink_ack", "operation_result"):
            key = row["operation_id"]
            original = operations.get(key)
            require(original is not None and operation_match(row, original), "missing or contradictory operation identity")
            if kind == "netlink_send":
                require(key not in sends and row["netlink_sequence"] > 0, "duplicate or invalid netlink send")
                sends[key] = row
            elif kind == "netlink_ack":
                require(key in sends and key not in acks and row["netlink_sequence"] == sends[key]["netlink_sequence"], "missing or contradictory netlink sequence")
                acks[key] = row
            else:
                require(key not in results, "duplicate dataplane result")
                results.add(key)
                route, ack = routes[route_key(row)], acks.get(key)
                if not supported(route) or route["origin"] not in VERIFIED_ORIGINS or original["supported"] is not True:
                    refusal(row, "unsupported installation context or origin")
                elif row["accepted_generation"] is not True or row["result"] != "SUCCESS":
                    refusal(row, "unsuccessful or stale-generation dataplane result")
                elif ack is None or ack["error"] != 0:
                    refusal(row, "missing or unsuccessful explicit kernel ACK")
                elif route["origin"] in ("bgp", "static") and any(ref["resolution_id"] not in verified_resolutions for ref in original["resolution_refs"]):
                    refusal(row, "consuming-route resolution is not recorded")
                elif row["operation"] in ("ROUTE_INSTALL", "ROUTE_UPDATE"):
                    output["fib_entries"].append(row)
                    output["claims"].append({"type": "route_installed_as_fib", "route_id": row["route_id"],
                        "generation": row["generation"], "operation_id": key, "historical": True,
                        "resolution_ids": [r["resolution_id"] for r in original["resolution_refs"]],
                        "source_refs": [reference(original), reference(sends[key]), reference(ack), reference(row)]})
        else:
            raise Refused("unknown Zebra event")
    pending = sorted(set(operations) - results)
    for key in pending:
        refusal(operations[key], "dataplane operation has no recorded main-thread result")
    output["capture"]["pending_operations"] = pending
    output["capture"]["attribution_complete"] = not output["refusals"]
    return output


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("directory", type=Path)
    parser.add_argument("--build", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    args = parser.parse_args()
    try:
        result = produce(args.directory, decode(read_source(args.build, 1048576)))
        status = 0
    except (Refused, ValueError, KeyError, TypeError, OSError) as error:
        result = {"schema": SCHEMA, "capture": {"complete": False, "snapshot_complete": False},
                  "claims": [], "refusals": [{"reason": str(error)}]}
        status = 2
    try:
        # Never overwrite evidence, or follow an existing output symlink.
        with args.output.open("x", encoding="utf-8") as destination:
            destination.write(json.dumps(result, indent=2, sort_keys=True) + "\n")
    except OSError as error:
        print("cannot create bundle output: " + str(error), file=sys.stderr)
        return 2
    return status


if __name__ == "__main__":
    raise SystemExit(main())
