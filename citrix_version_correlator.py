#!/usr/bin/env python3
"""
Citrix NetScaler Version Correlator

Correlates GZIP timestamps (build/compile dates) with publicly known
version release dates to identify or predict unknown firmware versions.

Uses two data sources:
  1. Existing fingerprint DB (known stamp -> version mappings)
  2. Public release date DB (version -> GA release date, scraped from
     docs.netscaler.com and citrix.com/downloads — no login required)

The tool calculates the typical compile-to-release offset per branch,
then uses that to predict which version an unknown timestamp belongs to.

Usage:
    python3 citrix_version_correlator.py                    # show stats
    python3 citrix_version_correlator.py --stamp 1768297927 # identify a stamp
    python3 citrix_version_correlator.py --scan https://target  # scan + identify
    python3 citrix_version_correlator.py --export           # export merged DB
"""

import argparse
import csv
import struct
import ssl
import sys
from collections import defaultdict
from datetime import datetime, timezone, timedelta
from io import StringIO

# ═══════════════════════════════════════════════════════════════════════════
# PUBLIC RELEASE DATE DATABASE
# Source: docs.netscaler.com, citrix.com/downloads (no login required)
# Format: version, GA release date, branch
# ═══════════════════════════════════════════════════════════════════════════
RELEASE_DATES_CSV = """\
version,release_date,branch
14.1-66.62,2026-03-24,14.1
14.1-66.59,2026-03-23,14.1
14.1-60.58,2026-03-24,14.1
14.1-60.57,2026-01-20,14.1
14.1-56.74,2025-11-11,14.1
14.1-56.71,2025-10-24,14.1
14.1-51.83,2025-09-29,14.1
14.1-51.80,2025-09-29,14.1
14.1-51.72,2025-09-02,14.1
14.1-47.48,2025-08-26,14.1
14.1-47.46,2025-06-13,14.1
14.1-47.44,2025-05-21,14.1
14.1-47.43,2025-05-20,14.1
14.1-47.40,2025-05-13,14.1
14.1-43.56,2025-06-17,14.1
14.1-43.50,2025-02-21,14.1
14.1-43.109,2025-04-09,14.1
14.1-38.53,2024-12-18,14.1
14.1-34.42,2024-10-28,14.1
14.1-34.107,2025-03-14,14.1
14.1-34.105,2025-03-06,14.1
14.1-34.101,2024-10-29,14.1
14.1-29.72,2024-11-12,14.1
14.1-29.63,2024-08-18,14.1
14.1-25.56,2024-07-07,14.1
14.1-25.53,2024-07-09,14.1
14.1-25.108,2024-07-05,14.1
14.1-25.107,2024-06-24,14.1
14.1-21.57,2024-04-23,14.1
14.1-17.38,2024-02-20,14.1
14.1-12.35,2024-01-16,14.1
14.1-12.34,2023-12-08,14.1
14.1-12.30,2024-01-16,14.1
14.1-8.50,2023-09-25,14.1
14.1-8.122,2024-01-02,14.1
14.1-8.120,2023-12-06,14.1
14.1-4.42,2023-08-07,14.1
13.1-62.23,2026-03-23,13.1
13.1-61.26,2026-01-20,13.1
13.1-61.23,2025-11-09,13.1
13.1-60.32,2025-11-11,13.1
13.1-60.29,2025-09-21,13.1
13.1-60.26,2025-09-08,13.1
13.1-59.22,2025-08-26,13.1
13.1-59.19,2025-06-25,13.1
13.1-58.32,2025-06-17,13.1
13.1-58.21,2025-04-08,13.1
13.1-57.26,2025-02-04,13.1
13.1-56.18,2024-11-18,13.1
13.1-55.34,2024-11-12,13.1
13.1-55.29,2024-09-23,13.1
13.1-54.29,2024-07-22,13.1
13.1-53.24,2024-07-08,13.1
13.1-53.17,2024-05-13,13.1
13.1-52.19,2024-03-11,13.1
13.1-51.15,2024-01-16,13.1
13.1-51.14,2024-01-16,13.1
13.1-50.23,2023-10-23,13.1
13.1-49.15,2023-10-10,13.1
13.1-49.13,2023-10-10,13.1
13.1-48.47,2023-06-12,13.1
13.1-45.64,2023-05-18,13.1
13.1-45.63,2023-04-30,13.1
13.1-45.62,2023-04-26,13.1
13.1-45.61,2023-05-18,13.1
13.1-42.47,2023-02-22,13.1
13.1-37.262,2026-03-23,13.1-FIPS
13.1-37.259,2026-01-22,13.1-FIPS
13.1-37.255,2025-12-09,13.1-FIPS
13.1-37.250,2025-11-11,13.1-FIPS
13.1-37.247,2025-09-17,13.1-FIPS
13.1-37.246,2025-09-08,13.1-FIPS
13.1-37.241,2025-08-20,13.1-FIPS
13.1-37.235,2025-06-10,13.1-FIPS
13.1-37.232,2025-04-17,13.1-FIPS
13.1-37.219,2024-11-29,13.1-FIPS
13.1-37.207,2024-10-07,13.1-FIPS
13.1-37.199,2024-08-13,13.1-FIPS
13.1-37.190,2024-07-04,13.1-FIPS
13.1-37.188,2024-06-14,13.1-FIPS
13.1-37.183,2024-05-14,13.1-FIPS
13.1-37.176,2024-01-05,13.1-FIPS
13.1-37.164,2023-09-27,13.1-FIPS
13.1-37.159,2023-07-07,13.1-FIPS
13.1-37.150,2023-04-24,13.1-FIPS
13.1-37.38,2022-11-29,13.1-FIPS
13.0-92.31,2024-07-04,13.0
13.0-92.21,2023-12-14,13.0
13.0-92.19,2023-09-21,13.0
13.0-92.18,2023-08-30,13.0
13.0-91.13,2023-07-18,13.0
13.0-91.12,2023-05-12,13.0
13.0-90.12,2023-05-15,13.0
13.0-90.11,2023-04-19,13.0
13.0-90.7,2023-01-24,13.0
13.0-89.7,2022-12-19,13.0
13.0-88.16,2022-12-01,13.0
13.0-88.14,2022-11-03,13.0
13.0-88.13,2022-10-31,13.0
13.0-88.12,2022-10-20,13.0
13.0-87.9,2022-08-04,13.0
13.0-86.17,2022-06-20,13.0
13.0-85.19,2022-05-19,13.0
13.0-85.15,2022-03-10,13.0
13.0-84.11,2021-12-24,13.0
13.0-84.10,2021-12-24,13.0
13.0-83.29,2021-11-15,13.0
13.0-83.27,2021-09-29,13.0
13.0-82.45,2021-07-19,13.0
13.0-82.42,2021-06-10,13.0
13.0-82.41,2021-07-19,13.0
13.0-79.64,2021-04-05,13.0
13.0-76.31,2021-03-09,13.0
13.0-76.29,2021-02-18,13.0
13.0-71.44,2020-12-26,13.0
13.0-71.40,2020-12-03,13.0
13.0-67.43,2020-11-13,13.0
13.0-67.39,2020-10-07,13.0
13.0-64.35,2020-09-01,13.0
13.0-61.48,2020-07-22,13.0
13.0-58.32,2020-07-02,13.0
13.0-58.30,2020-06-01,13.0
13.0-52.24,2020-03-19,13.0
13.0-47.24,2020-01-20,13.0
13.0-47.22,2019-11-28,13.0
13.0-41.28,2019-10-11,13.0
13.0-41.20,2019-09-10,13.0
13.0-36.27,2019-05-13,13.0
12.1-65.39,2023-12-18,12.1
12.1-65.35,2023-04-28,12.1
12.1-65.25,2022-11-30,12.1
12.1-65.21,2022-10-04,12.1
12.1-65.17,2022-06-29,12.1
12.1-65.15,2022-04-22,12.1
12.1-64.17,2022-04-21,12.1
12.1-64.16,2022-01-20,12.1
12.1-63.24,2021-12-22,12.1
12.1-63.23,2021-11-11,12.1
12.1-63.22,2021-10-13,12.1
12.1-62.27,2021-07-07,12.1
12.1-62.25,2021-06-10,12.1
12.1-62.23,2021-05-17,12.1
12.1-62.21,2021-05-10,12.1
12.1-61.19,2021-03-08,12.1
12.1-61.18,2021-02-02,12.1
12.1-60.19,2020-12-26,12.1
12.1-60.16,2020-11-04,12.1
12.1-59.16,2020-09-22,12.1
12.1-58.15,2020-09-01,12.1
12.1-58.14,2020-08-14,12.1
12.1-57.18,2020-06-09,12.1
12.1-56.22,2020-03-29,12.1
12.1-55.333,2025-11-11,12.1-FIPS
12.1-55.330,2025-08-20,12.1-FIPS
12.1-55.328,2025-06-10,12.1-FIPS
12.1-55.325,2025-02-11,12.1-FIPS
12.1-55.321,2024-10-07,12.1-FIPS
12.1-55.309,2024-07-08,12.1-FIPS
12.1-55.307,2024-06-12,12.1-FIPS
12.1-55.304,2024-04-26,12.1-FIPS
12.1-55.302,2023-12-18,12.1-FIPS
12.1-55.300,2023-09-21,12.1-FIPS
12.1-55.297,2023-07-07,12.1-FIPS
12.1-55.296,2023-04-05,12.1-FIPS
12.1-55.291,2022-11-28,12.1-FIPS
12.1-55.289,2022-10-12,12.1-FIPS
12.1-55.282,2022-07-06,12.1-FIPS
12.1-55.278,2022-04-21,12.1-FIPS
12.1-55.276,2022-04-03,12.1-FIPS
12.1-55.265,2022-01-28,12.1-FIPS
12.1-55.210,2021-01-04,12.1-FIPS
12.1-55.190,2020-10-08,12.1-FIPS
12.1-55.24,2020-02-28,12.1-FIPS
12.1-55.18,2020-01-20,12.1-FIPS
12.1-55.13,2019-11-05,12.1-FIPS
12.1-51.19,2019-03-25,12.1
12.1-51.16,2019-02-27,12.1
12.1-50.31,2019-01-18,12.1
12.1-50.28,2018-11-28,12.1
12.1-49.37,2018-10-16,12.1
12.1-49.23,2018-08-25,12.1
12.0-63.21,2020-06-01,12.0
11.1-65.23,2021-10-12,11.1
11.1-65.22,2021-07-07,11.1
11.1-65.20,2021-05-29,11.1
11.1-65.12,2020-09-10,11.1
11.1-64.14,2020-06-02,11.1
11.1-63.15,2020-01-16,11.1
"""

# ═══════════════════════════════════════════════════════════════════════════
# KNOWN FINGERPRINT DB (from fox-it + BLS additions)
# ═══════════════════════════════════════════════════════════════════════════
FINGERPRINT_CSV = """\
rdx_en_date,rdx_en_stamp,vhash,version
2018-08-25 03:29:12+00:00,1535167752,,12.1-49.23
2018-10-16 17:54:20+00:00,1539712460,,12.1-49.37
2019-05-13 17:41:47+00:00,1557769307,86b4b2567b05dff896aae46d6e0765bc,13.0-36.27
2019-11-05 05:18:47+00:00,1572931127,8c62b39f7068ea2f3d3f7d40860c0cd4,12.1-55.13
2020-01-16 13:36:04+00:00,1579181764,,11.1-63.15
2021-09-10 07:31:30+00:00,1631259090,98a21b87cc25d486eb4189ab52cbc870,13.1-4.43
2023-07-07 15:32:56+00:00,1688743976,,13.0-91.13
2023-07-10 18:36:31+00:00,1689014191,,13.1-49.13
2023-07-28 00:25:01+00:00,1690503901,,14.1-4.42
2024-07-04 16:31:28+00:00,1720110688,,14.1-25.56
2025-11-09 02:30:07+00:00,1762655407,,14.1-56.74
2025-11-09 04:45:20+00:00,1762663520,,13.1-61.23
2025-11-11 03:01:37+00:00,1762830097,11ba0524227f5450bc03fb70ed17c3d5,12.1-55.333
2026-01-13 09:52:07+00:00,1768297927,914e500e5a4fc7bab9e75f7a2b43e8d8,13.1-61.26
"""


def load_release_dates():
    """Load version -> release date mapping."""
    db = {}
    for row in csv.DictReader(StringIO(RELEASE_DATES_CSV)):
        db[row["version"]] = {
            "release_date": datetime.strptime(row["release_date"], "%Y-%m-%d").replace(tzinfo=timezone.utc),
            "branch": row["branch"],
        }
    return db


def load_fingerprints():
    """Load stamp -> (version, build_date) mapping."""
    db = {}
    for row in csv.DictReader(StringIO(FINGERPRINT_CSV)):
        ver = row["version"]
        if ver == "unknown":
            continue
        stamp = int(row["rdx_en_stamp"])
        build_date = datetime.fromtimestamp(stamp, tz=timezone.utc)
        db[ver] = {"stamp": stamp, "build_date": build_date}
    return db


def compute_offsets(release_db, fingerprint_db):
    """Calculate compile-to-release offset for versions in both databases."""
    offsets = []
    by_branch = defaultdict(list)

    for ver, fp in fingerprint_db.items():
        if ver in release_db:
            rel = release_db[ver]
            delta = rel["release_date"] - fp["build_date"]
            days = delta.total_seconds() / 86400
            offsets.append({
                "version": ver,
                "branch": rel["branch"],
                "build_date": fp["build_date"],
                "release_date": rel["release_date"],
                "offset_days": days,
            })
            by_branch[rel["branch"]].append(days)

    return offsets, by_branch


def predict_version(stamp, release_db, by_branch):
    """Given a GZIP timestamp, predict the most likely version."""
    build_date = datetime.fromtimestamp(stamp, tz=timezone.utc)

    candidates = []
    for ver, rel in release_db.items():
        # The build date should be BEFORE the release date
        delta = rel["release_date"] - build_date
        days = delta.total_seconds() / 86400

        # Typical offset: build is 0-30 days before release
        branch = rel["branch"]
        avg_offset = 7  # default
        if branch in by_branch and by_branch[branch]:
            avg_offset = sum(by_branch[branch]) / len(by_branch[branch])

        # Score: how close is this version's expected build window?
        if -3 <= days <= 45:  # build within 3 days after to 45 days before release
            score = abs(days - avg_offset)
            candidates.append({
                "version": ver,
                "branch": branch,
                "release_date": rel["release_date"],
                "days_before_release": days,
                "score": score,
            })

    candidates.sort(key=lambda x: x["score"])
    return build_date, candidates


def main():
    parser = argparse.ArgumentParser(
        description="Correlate GZIP timestamps with Citrix version release dates.",
    )
    parser.add_argument("--stamp", type=int, help="GZIP MTIME timestamp to identify")
    parser.add_argument("--scan", help="Target URL to scan and identify")
    parser.add_argument("--stats", action="store_true", help="Show offset statistics")
    parser.add_argument("--export", action="store_true", help="Export merged version database")
    args = parser.parse_args()

    release_db = load_release_dates()
    fingerprint_db = load_fingerprints()
    offsets, by_branch = compute_offsets(release_db, fingerprint_db)

    if args.stats or (not args.stamp and not args.scan and not args.export):
        print(f"\n{'='*65}")
        print(f" Citrix Version Correlator — Offset Statistics")
        print(f"{'='*65}\n")
        print(f"  Release date DB: {len(release_db)} versions")
        print(f"  Fingerprint DB:  {len(fingerprint_db)} stamps")
        print(f"  Matched:         {len(offsets)} versions in both DBs\n")

        print(f"  {'Branch':<12} {'Count':>5} {'Avg Offset':>12} {'Min':>8} {'Max':>8}")
        print(f"  {'-'*48}")
        for branch in sorted(by_branch.keys()):
            vals = by_branch[branch]
            avg = sum(vals) / len(vals)
            print(f"  {branch:<12} {len(vals):>5} {avg:>10.1f}d {min(vals):>7.1f}d {max(vals):>7.1f}d")

        print(f"\n  Overall average: build is compiled "
              f"{sum(v for vals in by_branch.values() for v in vals) / max(len(offsets),1):.1f} "
              f"days before GA release\n")

    if args.stamp:
        build_date, candidates = predict_version(args.stamp, release_db, by_branch)
        print(f"\n{'='*65}")
        print(f" Identifying timestamp {args.stamp}")
        print(f" Build date: {build_date.strftime('%Y-%m-%d %H:%M:%S UTC')}")
        print(f"{'='*65}\n")

        if candidates:
            print(f"  Top candidates (by compile-to-release offset fit):\n")
            print(f"  {'#':<4} {'Version':<16} {'Branch':<12} {'Release Date':<14} {'Days Before':>12}")
            print(f"  {'-'*60}")
            for i, c in enumerate(candidates[:10], 1):
                rd = c["release_date"].strftime("%Y-%m-%d")
                print(f"  {i:<4} {c['version']:<16} {c['branch']:<12} {rd:<14} {c['days_before_release']:>10.1f}d")
            print(f"\n  Best guess: {candidates[0]['version']} "
                  f"(released {candidates[0]['release_date'].strftime('%Y-%m-%d')})")
        else:
            print("  No candidates found — timestamp may be newer than release DB.")

    if args.scan:
        target = args.scan
        if not target.startswith(("http://", "https://")):
            target = f"https://{target}"

        from urllib.parse import urlparse
        parsed = urlparse(target)
        host = parsed.hostname
        port = parsed.port or 443

        print(f"\n  Scanning {target} ...")
        try:
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            import http.client
            conn = http.client.HTTPSConnection(host, port, context=ctx, timeout=15)
            conn.request("GET", "/vpn/js/rdx/core/lang/rdx_en.json.gz",
                         headers={"User-Agent": "Mozilla/5.0", "Accept-Encoding": "identity"})
            resp = conn.getresponse()
            if resp.status != 200:
                print(f"  HTTP {resp.status} — not a Citrix target or endpoint blocked")
                sys.exit(1)
            data = resp.read()
            conn.close()

            # Handle double-gzip
            if not data.startswith(b"\x1f\x8b\x08\x08"):
                import requests, urllib3
                urllib3.disable_warnings()
                r = requests.get(f"{target}/vpn/js/rdx/core/lang/rdx_en.json.gz",
                                 verify=False, timeout=15, stream=True)
                data = r.raw.read(decode_content=False)
                r.close()

            if len(data) < 16 or not data.startswith(b"\x1f\x8b\x08\x08"):
                print("  Not a valid GZIP response")
                sys.exit(1)

            stamp = struct.unpack("<I", data[4:8])[0]
            print(f"  GZIP MTIME: {stamp}")
            args.stamp = stamp
            build_date, candidates = predict_version(stamp, release_db, by_branch)
            print(f"  Build date: {build_date.strftime('%Y-%m-%d %H:%M:%S UTC')}\n")

            if candidates:
                print(f"  Top candidates:\n")
                print(f"  {'#':<4} {'Version':<16} {'Branch':<12} {'Release Date':<14} {'Days Before':>12}")
                print(f"  {'-'*60}")
                for i, c in enumerate(candidates[:5], 1):
                    rd = c["release_date"].strftime("%Y-%m-%d")
                    print(f"  {i:<4} {c['version']:<16} {c['branch']:<12} {rd:<14} {c['days_before_release']:>10.1f}d")
                print(f"\n  Best guess: {candidates[0]['version']}")
            else:
                print("  No candidates found.")
        except Exception as e:
            print(f"  Error: {e}")
            sys.exit(1)

    if args.export:
        print("version,build_date,release_date,branch,offset_days,source")
        for ver, rel in sorted(release_db.items()):
            fp = fingerprint_db.get(ver)
            if fp:
                delta = (rel["release_date"] - fp["build_date"]).total_seconds() / 86400
                print(f"{ver},{fp['build_date'].strftime('%Y-%m-%d')},{rel['release_date'].strftime('%Y-%m-%d')},{rel['branch']},{delta:.1f},both")
            else:
                print(f"{ver},,{rel['release_date'].strftime('%Y-%m-%d')},{rel['branch']},,release_only")


if __name__ == "__main__":
    main()
