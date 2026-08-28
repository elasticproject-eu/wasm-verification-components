#!/usr/bin/env python3
"""
Prove the vendored ReCFA verifier agrees with unmodified upstream `check`.

Runs both binaries over the same inputs and asserts that the structured result
from vendor/check.cpp (via tools/parity-driver) matches what upstream printed on
stdout: same verdict, same |M|/|F|, same number of attested events, same queue
depth on a shadow-stack failure.

Usage:
  parity-check.py --oracle /path/to/ReCFA/bin/check \
                  --driver ./parity-driver \
                  --data   ../test_data \
                  [--case pass_simple ...]

Exit status is non-zero if any case disagrees.
"""
import argparse
import os
import re
import subprocess
import sys

VERDICT_SECURE = 1
VERDICT_SHADOW = 2
VERDICT_ICALL = 3
VERDICT_IJMP = 4
VERDICT_DYNINST = 5
VERDICT_POLICY_F = 6
VERDICT_BAD_EVIDENCE = 7

VERDICT_NAME = {
    0: "unknown",
    1: "secure",
    2: "shadow-stack-violation",
    3: "indirect-call-violation",
    4: "indirect-jump-violation",
    5: "cfg/policy-M-inconsistent",
    6: "policy-F-inconsistent",
    7: "malformed-evidence",
}


def parse_oracle(out):
    """Map upstream check(1) stdout onto the structured fields."""
    r = {"verdict": 0, "total": None, "unprocessed": 0, "M": None, "F": None}
    m = re.search(r"\|M\|=\s*(\d+),\s*\|F\|=\s*(\d+)", out)
    if m:
        r["M"], r["F"] = int(m.group(1)), int(m.group(2))
    if "No events left unprocessed.Progarm is secure" in out:
        r["verdict"] = VERDICT_SECURE
    m = re.search(r"fail,(\d+) events unprocessed", out)
    if m:
        r["verdict"] = VERDICT_SHADOW
        r["unprocessed"] = int(m.group(1))
    if re.search(r"^Indirect Call$", out, re.M):
        r["verdict"] = VERDICT_ICALL
    if re.search(r"^Indirect Jump$", out, re.M):
        r["verdict"] = VERDICT_IJMP
    if "Policy F read error." in out:
        r["verdict"] = VERDICT_POLICY_F
    if "dyninst fail" in out:
        r["verdict"] = VERDICT_DYNINST
    m = re.search(r"Num of addresses attested:\s*(\d+)", out)
    if m:
        r["total"] = int(m.group(1))
    return r


def parse_driver(out):
    m = re.search(
        r"RESULT verdict=(-?\d+) total=(-?\d+) unprocessed=(-?\d+) "
        r"reconstructed=(-?\d+) M=(\d+) F=(\d+)",
        out,
    )
    if not m:
        raise SystemExit("driver produced no RESULT line:\n" + out)
    return {
        "verdict": int(m.group(1)),
        "total": int(m.group(2)),
        "unprocessed": int(m.group(3)),
        "reconstructed": int(m.group(4)),
        "M": int(m.group(5)),
        "F": int(m.group(6)),
    }


def discover_cases(data):
    return sorted(
        f[: -len(".trace")] for f in os.listdir(data) if f.endswith(".trace")
    )


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--oracle", required=True, help="unmodified upstream bin/check")
    ap.add_argument("--driver", required=True, help="tools/parity-driver")
    ap.add_argument("--data", required=True, help="directory with the fixture")
    ap.add_argument("--asm", default="prog.asm")
    ap.add_argument("--dot", default="prog.dot")
    ap.add_argument("--policy-f", default="binfo.prog")
    ap.add_argument("--compiler", default="gcc")
    ap.add_argument("--num-executions", default="1")
    ap.add_argument("--case", nargs="*", default=None)
    args = ap.parse_args()

    d = args.data
    cases = args.case if args.case else discover_cases(d)
    if not cases:
        raise SystemExit("no .trace files found in %s" % d)

    def argv_for(binary, case):
        return [
            binary,
            os.path.join(d, args.asm),
            os.path.join(d, args.dot),
            os.path.join(d, args.policy_f),
            os.path.join(d, case + ".map"),
            os.path.join(d, case + ".trace"),
            args.num_executions,
            args.compiler,
        ]

    failures = 0
    print("%-18s %-26s %-8s %-8s %s" % ("CASE", "VERDICT", "EVENTS", "|M|/|F|", "PARITY"))
    for case in cases:
        o = subprocess.run(
            argv_for(args.oracle, case), capture_output=True, text=True, timeout=600
        )
        v = subprocess.run(
            argv_for(args.driver, case), capture_output=True, text=True, timeout=600
        )
        exp = parse_oracle(o.stdout)
        got = parse_driver(v.stdout)

        problems = []
        if exp["verdict"] != got["verdict"]:
            problems.append(
                "verdict %s != %s" % (exp["verdict"], got["verdict"])
            )
        if exp["M"] is not None and exp["M"] != got["M"]:
            problems.append("|M| %s != %s" % (exp["M"], got["M"]))
        if exp["F"] is not None and exp["F"] != got["F"]:
            problems.append("|F| %s != %s" % (exp["F"], got["F"]))
        # upstream only prints the event total when it did not exit(-1)
        if exp["total"] is not None and exp["total"] != got["total"]:
            problems.append("total %s != %s" % (exp["total"], got["total"]))
        if exp["verdict"] == VERDICT_SHADOW and exp["unprocessed"] != got["unprocessed"]:
            problems.append(
                "unprocessed %s != %s" % (exp["unprocessed"], got["unprocessed"])
            )

        status = "OK" if not problems else "MISMATCH: " + "; ".join(problems)
        if problems:
            failures += 1
        print(
            "%-18s %-26s %-8s %-8s %s"
            % (
                case,
                VERDICT_NAME.get(got["verdict"], got["verdict"]),
                got["total"],
                "%s/%s" % (got["M"], got["F"]),
                status,
            )
        )

    print()
    if failures:
        print("FAILED: %d of %d cases disagree with upstream" % (failures, len(cases)))
        return 1
    print("PASS: vendored verifier matches upstream on all %d cases" % len(cases))
    return 0


if __name__ == "__main__":
    sys.exit(main())
