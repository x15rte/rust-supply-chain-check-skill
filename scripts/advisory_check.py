#!/usr/bin/env python3
"""Cross-check a Cargo.lock against the RustSec advisory-db.

Usage:
    python advisory_check.py Cargo.lock /path/to/advisory-db

Get the advisory DB (tarball, no git clone required):
    https://codeload.github.com/rustsec/advisory-db/tar.gz/refs/heads/main

Implements Cargo semver-range semantics: comma = AND, ops >= > <= < = ^ ~,
bare version = caret, `*` = any; prerelease < release; numeric prerelease
parts < alphabetic. A locked version is vulnerable when it satisfies no
`[versions] unaffected` and no `[versions] patched` range; empty patched with
no unaffected means all versions affected.

Exit code: 0 = no unpatched advisories; 1 = unpatched advisories found.
Informational advisories (unmaintained/unsound) print separately and never
affect the exit code.

Requires Python 3.11+ (tomllib). Standard library only.
"""

import glob
import os
import re
import sys
import tomllib

MAX_ENTRY = 64 * 1024  # guard against pathological single-line files


def parse_version(v):
    v = v.strip()
    m = re.match(
        r"^(\d+)(?:\.(\d+))?(?:\.(\d+))?(?:-([0-9A-Za-z.-]+))?(?:\+[0-9A-Za-z.-]+)?$", v
    )
    if not m:
        return None
    major, minor, patch, pre = m.groups()
    return ((int(major), int(minor or 0), int(patch or 0)), pre)


def cmp_versions(a, b):
    (ra, pa), (rb, pb) = a, b
    if ra != rb:
        return (ra > rb) - (ra < rb)
    if pa is None and pb is None:
        return 0
    if pa is None:
        return 1
    if pb is None:
        return -1
    aa, bb = pa.split("."), pb.split(".")
    for x, y in zip(aa, bb):
        xn, yn = x.isdigit(), y.isdigit()
        if xn and yn:
            xi, yi = int(x), int(y)
            if xi != yi:
                return (xi > yi) - (xi < yi)
        elif xn != yn:
            return -1 if xn else 1
        elif x != y:
            return (x > y) - (x < y)
    return (len(aa) > len(bb)) - (len(aa) < len(bb))


def satisfies_clause(pv, clause):
    clause = clause.strip()
    if clause in ("*", ""):
        return True
    m = re.match(r"^(>=|<=|>|<|=|\^|~)?\s*(.+)$", clause)
    op, vstr = m.groups()
    cv = parse_version(vstr)
    if cv is None:
        return False
    if op in (None, "^"):
        lo = cv
        if cv[0][0] != 0:
            hi = ((cv[0][0] + 1, 0, 0), None)
        elif cv[0][1] != 0:
            hi = ((0, cv[0][1] + 1, 0), None)
        else:
            hi = ((0, 0, cv[0][2] + 1), None)
        return cmp_versions(pv, lo) >= 0 and cmp_versions(pv, hi) < 0
    if op == "~":
        lo = cv
        hi = ((cv[0][0], cv[0][1] + 1, 0), None) if cv[0][1] else ((cv[0][0] + 1, 0, 0), None)
        return cmp_versions(pv, lo) >= 0 and cmp_versions(pv, hi) < 0
    if op == "=":
        return cmp_versions(pv, cv) == 0
    if op == ">=":
        return cmp_versions(pv, cv) >= 0
    if op == "<=":
        return cmp_versions(pv, cv) <= 0
    if op == ">":
        return cmp_versions(pv, cv) > 0
    if op == "<":
        return cmp_versions(pv, cv) < 0
    return False


def in_any(pv, ranges):
    return any(
        all(satisfies_clause(pv, c) for c in r.split(",") if c.strip())
        for r in ranges
    )


def load_lock(path):
    """Map crate name -> list of locked versions (a lock can hold several)."""
    with open(path, "rb") as fh:
        pkgs = tomllib.load(fh)["package"]
    versions = {}
    for p in pkgs:
        versions.setdefault(p["name"], []).append(p["version"])
    return versions


def load_advisories(db_dir):
    advs = []
    for f in glob.glob(os.path.join(db_dir, "crates", "*", "RUSTSEC-*.md")):
        with open(f, encoding="utf-8") as fh:
            text = fh.read(MAX_ENTRY * 4)
        for block in re.findall(r"```toml\n(.*?)```", text, re.S):
            try:
                data = tomllib.loads(block)
            except Exception:
                continue
            adv = data.get("advisory", {})
            ver = data.get("versions", {})
            advs.append(
                {
                    "id": adv.get("id", "?"),
                    "package": adv.get("package"),
                    "informational": adv.get("informational"),
                    "title": adv.get("summary", "?"),
                    "patched": ver.get("patched", []),
                    "unaffected": ver.get("unaffected", []),
                }
            )
    return advs


def main():
    if len(sys.argv) != 3:
        print(__doc__)
        return 2
    lock_path, db_dir = sys.argv[1], sys.argv[2]
    locked = load_lock(lock_path)
    n_pkgs = sum(len(v) for v in locked.values())
    advs = [a for a in load_advisories(db_dir) if a["package"] in locked]
    print(
        f"advisories touching {n_pkgs} locked package versions "
        f"({len(locked)} crates): {len(advs)} (db: {db_dir})"
    )
    vuln, info = [], []
    for a in advs:
        for ver in locked[a["package"]]:
            pv = parse_version(ver)
            if pv is None:
                continue
            if in_any(pv, a["unaffected"]) or in_any(pv, a["patched"]):
                continue
            rec = (a["package"], ver, a["id"], a["title"], a["patched"])
            (info if a["informational"] else vuln).append(rec)
    print(f"\nVULNERABLE ({len(vuln)}):")
    for r in vuln:
        print(f"  {r[0]} {r[1]}  {r[2]}  patched: {r[4] or 'none'}  — {r[3]}")
    print(f"\nINFORMATIONAL (unmaintained/unsound, {len(info)}):")
    for r in info:
        print(f"  {r[0]} {r[1]}  {r[2]}  — {r[3]}")
    return 1 if vuln else 0


if __name__ == "__main__":
    sys.exit(main())
