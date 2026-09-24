"""Bounded command-line interface for canonical policies and certificates."""
from __future__ import annotations
import argparse
import json
import os
import tempfile
from pathlib import Path
from language import read_policy, pretty, PolicyError
from compiler import compile_policy, certificate, diagnose, decompile
from checker import inspect_policy, inspect_machine, load, verify, Rejected

def output(path, value, byte_limit=None):
    """Write a bounded complete value without replacing an existing destination.

    A temporary file in the same directory is linked only after encoding succeeds.
    JSON and sentence limits agree with the corresponding readers.
    """
    path = Path(path)
    limit = byte_limit if byte_limit is not None else (4 if isinstance(value, str) else 32) * 1024 * 1024
    if path.exists():
        raise FileExistsError("refusing to overwrite " + path.name)
    chunks = (value,) if isinstance(value, str) else json.JSONEncoder(ensure_ascii=False, separators=(",", ":")).iterencode(value)
    temporary = None
    try:
        with tempfile.NamedTemporaryFile(mode="wb", dir=path.parent, delete=False) as stream:
            temporary = Path(stream.name)
            total = 0
            for chunk in chunks:
                data = chunk.encode("utf-8")
                total += len(data)
                if total > limit:
                    raise PolicyError("LIMIT", "serialized output exceeds reader envelope")
                stream.write(data)
            if not isinstance(value, str):
                if total + 1 > limit:
                    raise PolicyError("LIMIT", "serialized output exceeds reader envelope")
                stream.write(b"\n")
        # link() fails, rather than replacing a concurrently created destination.
        os.link(temporary, path)
    finally:
        if temporary is not None:
            temporary.unlink(missing_ok=True)

def main():
    ap = argparse.ArgumentParser()
    sub = ap.add_subparsers(dest="command", required=True)
    n = sub.add_parser("normalize"); n.add_argument("policy"); n.add_argument("output")
    c = sub.add_parser("compile"); c.add_argument("policy"); c.add_argument("directory")
    for name in ("diagnose", "reify"):
        s = sub.add_parser(name); s.add_argument("policy"); s.add_argument("machine"); s.add_argument("output")
    args = ap.parse_args()
    try:
        p = read_policy(args.policy); inspect_policy(p)
        if args.command == "normalize":
            output(args.output, pretty(p))
        elif args.command == "compile":
            destination = Path(args.directory); destination.mkdir(parents=True, exist_ok=False)
            m = compile_policy(p)
            output(destination / "policy.json", p); output(destination / "policy.cnl", pretty(p))
            output(destination / "automaton.json", m); output(destination / "certificate.json", certificate(m))
        else:
            m = load(args.machine); inspect_machine(p, m, compare_initial=False)
            if args.command == "reify":
                output(args.output, pretty(decompile(m, p)))
            else:
                result = diagnose(p, m)
                if result["equivalent"]:
                    verify(p, m, certificate(m))
                output(args.output, result)
        print(json.dumps({"completed": True}))
    except (PolicyError, Rejected, ValueError, TypeError, KeyError, OverflowError, RecursionError, OSError) as error:
        inconclusive = (isinstance(error, PolicyError) and error.category == "LIMIT") or (isinstance(error, Rejected) and error.kind == "inconclusive")
        print(json.dumps({"completed": False, "kind": "inconclusive" if inconclusive else "invalid", "reason": str(error)}))
        raise SystemExit(2 if inconclusive else 1)

if __name__ == "__main__": main()
