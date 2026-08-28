#!/usr/bin/env python3
"""
Derive tampered traces from a real ReCFA folded event stream, to check that the
verifier actually rejects control-flow hijacks rather than just accepting good
traces.

Produces two files next to the input:

  <trace>.tamper_icall  an indirect call retargeted to a real function that
                        policy F does not permit at that site  -> "Indirect Call"
  <trace>.tamper_ret    a return target corrupted mid-stream
                        -> shadow-stack violation

Usage:
  make-tamper.py <folded_trace> <policy_F_binfo>
"""
import re
import struct
import sys


def main():
    if len(sys.argv) != 3:
        print(__doc__)
        return 2
    trace_path, policy_f_path = sys.argv[1], sys.argv[2]

    raw = open(trace_path, "rb").read()
    n = len(raw) // 4
    v = list(struct.unpack("<%dI" % n, raw[: n * 4]))
    print("events: %d" % n)

    # policy F: legal indirect-call targets, per call site
    allowed = {}
    pat = re.compile(
        r"Indirectstar0x([0-9a-z]{6})  ([0-9]{1}) Indirectend0x([0-9a-z]{6})"
    )
    for line in open(policy_f_path, errors="replace"):
        m = pat.search(line)
        if m:
            allowed.setdefault(int(m.group(1), 16), set()).add(int(m.group(3), 16))
    if not allowed:
        raise SystemExit("no Indirectstar entries in %s" % policy_f_path)
    all_targets = set().union(*allowed.values())
    print("indirect call sites in policy F: %d" % len(allowed))

    # 1. retarget an indirect call to a function that is real but not permitted here
    sites = set(allowed)
    hit = None
    for i, x in enumerate(v):
        if x in sites and i + 1 < n:
            cand = sorted(all_targets - allowed[x])
            if cand:
                hit = (i, x, v[i + 1], cand[0])
                break
    if hit is None:
        raise SystemExit("no indirect call site occurs in this trace")
    i, site, orig, bogus = hit
    print(
        "icall tamper @event %d: site 0x%06x target 0x%06x -> 0x%06x "
        "(real function, not among the %d permitted here)"
        % (i, site, orig, bogus, len(allowed[site]))
    )
    w = list(v)
    w[i + 1] = bogus
    out1 = trace_path + ".tamper_icall"
    open(out1, "wb").write(struct.pack("<%dI" % n, *w))

    # 2. corrupt a return target halfway through, skipping compressed events
    j = n // 2
    while j < n and (v[j] & 0x80000000):
        j += 1
    if j >= n:
        raise SystemExit("no plain event found mid-stream")
    print("return tamper @event %d: 0x%08x -> 0x40dead" % (j, v[j]))
    w2 = list(v)
    w2[j] = 0x40DEAD
    out2 = trace_path + ".tamper_ret"
    open(out2, "wb").write(struct.pack("<%dI" % n, *w2))

    print("wrote:\n  %s\n  %s" % (out1, out2))
    return 0


if __name__ == "__main__":
    sys.exit(main())
