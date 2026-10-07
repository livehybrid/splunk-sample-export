#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
splunk_sample_export.py - export a proportionally representative event sample
from Splunk, for load testing, with optional field-name rewriting.

Two passes:

  1. Count pass    <base search> | stats count by <field>
                   gives the real population share of every value of <field>.

  2. Fetch pass    one search per value, <base search> <field>="v" | head N
                   where N is that value's share of --target, allocated with
                   the largest-remainder method so the totals land exactly on
                   --target and nothing is over-sampled.

So if audit_type=X is 1% of the window and you ask for 10000 events, you get
100 of them. Values are capped at what actually exists and the shortfall is
redistributed over the remaining values, proportionally, until --target is met
or the window is exhausted.

Field-name rewriting (--rename audit=apple) renames the keys in the exported
records AND the field-name-shaped tokens inside _raw ("audit_id": and
audit_id= forms), because _raw is what gets re-indexed when you replay this.
Values are never touched unless you ask for --raw-replace-all.

Stdlib only. Python 3.6+.

Examples
--------
  # see the distribution and the sampling plan, export nothing
  ./splunk_sample_export.py --host splunk.example.com --token-env SPLUNK_TOKEN \
      --search 'index=audit' --field audit_type \
      --earliest -24h --latest now --target 10000 --count-only

  # export, rename audit* -> apple*, newline-delimited JSON
  ./splunk_sample_export.py --host splunk.example.com --token-env SPLUNK_TOKEN \
      --search 'index=audit' --field audit_type \
      --earliest -24h --latest now --target 10000 \
      --rename audit=apple -o sample.ndjson

  # raw lines only, ready to feed a file monitor or an eventgen
  ./splunk_sample_export.py ... --format raw -o sample.log

  # HEC-ready envelopes
  ./splunk_sample_export.py ... --format hec -o sample.hec.ndjson
"""

from __future__ import print_function

import argparse
import calendar
import json
import math
import os
import random
import re
import ssl
import sys
import threading
import time

from concurrent.futures import ThreadPoolExecutor
from urllib.error import HTTPError, URLError
from urllib.parse import urlencode
from urllib.request import HTTPSHandler, Request, build_opener

if sys.version_info < (3, 6):
    sys.stderr.write("This script needs Python 3.6 or newer.\n")
    sys.exit(2)

DEFAULT_MISSING = "__MISSING__"

# Scratch fields used by --select. These must NOT start with an underscore:
# Splunk treats leading-underscore fields as internal and a following `where`
# never sees them, which silently returns zero events.
SCRATCH_N = "zz_sample_n"
SCRATCH_R = "zz_sample_r"
# Splunk renders _time with a timezone ABBREVIATION ("2026-10-07 16:37:42.576
# BST"), which cannot be parsed unambiguously (BST is both British Summer Time
# and Bougainville Standard Time). So ask Splunk for the epoch instead of
# guessing: `eval zz_epoch=_time` yields _time's numeric value.
SCRATCH_EPOCH = "zz_epoch"
EPOCH_FIELD = "_epoch"

# Search-time cruft that is regenerated on re-index. Dropped unless
# --keep-internal.
NOISE_FIELDS = {
    "_bkt", "_cd", "_si", "_serial", "_indextime", "_subsecond",
    "_sourcetype", "_eventtype_color", "_kv", "_confstr",
    "splunk_server", "splunk_server_group", "eventtype", "punct",
    "timestartpos", "timeendpos", "tag",
    SCRATCH_N, SCRATCH_R, SCRATCH_EPOCH,
}
NOISE_PREFIXES = ("tag::", "date_")
ALWAYS_KEEP = {"_raw", "_time", "host", "source", "sourcetype", "index",
               "linecount", EPOCH_FIELD}

_print_lock = threading.Lock()


def log(msg):
    with _print_lock:
        sys.stderr.write(msg + "\n")
        sys.stderr.flush()


# --------------------------------------------------------------------------
# Splunk REST
# --------------------------------------------------------------------------

def make_opener(verify):
    ctx = ssl.create_default_context()
    if not verify:
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
    return build_opener(HTTPSHandler(context=ctx))


class SplunkError(Exception):
    pass


class SplunkClient(object):
    def __init__(self, base_url, token=None, session_key=None, verify=True,
                 timeout=900, app=None, owner=None):
        self.base_url = base_url.rstrip("/")
        self.token = token
        self.session_key = session_key
        self.verify = verify
        self.timeout = timeout
        self.app = app
        self.owner = owner
        self._opener = make_opener(verify)

    def _headers(self):
        if self.token:
            return {"Authorization": "Bearer " + self.token}
        return {"Authorization": "Splunk " + self.session_key}

    def _namespace(self, endpoint):
        if self.app:
            owner = self.owner or "nobody"
            return "/servicesNS/%s/%s%s" % (owner, self.app, endpoint)
        return "/services" + endpoint

    def post(self, endpoint, params, stream=False):
        url = self.base_url + self._namespace(endpoint)
        body = urlencode(params, doseq=True).encode("utf-8")
        req = Request(url, data=body, headers=self._headers())
        try:
            resp = self._opener.open(req, timeout=self.timeout)
        except HTTPError as exc:
            detail = exc.read().decode("utf-8", "replace")[:2000]
            raise SplunkError("HTTP %s from %s: %s" % (exc.code, url, detail))
        except URLError as exc:
            raise SplunkError("cannot reach %s: %s" % (url, exc.reason))
        if stream:
            return resp
        return resp.read().decode("utf-8", "replace")

    @classmethod
    def from_password(cls, base_url, username, password, verify=True, **kw):
        url = base_url.rstrip("/") + "/services/auth/login"
        body = urlencode({"username": username,
                          "password": password,
                          "output_mode": "json"}).encode("utf-8")
        opener = make_opener(verify)
        try:
            raw = opener.open(Request(url, data=body), timeout=60).read()
        except HTTPError as exc:
            exc.read()
            raise SplunkError("login failed for %r: HTTP %s" % (username, exc.code))
        except URLError as exc:
            raise SplunkError("cannot reach %s: %s" % (url, exc.reason))
        key = json.loads(raw.decode("utf-8", "replace")).get("sessionKey")
        if not key:
            raise SplunkError("login succeeded but returned no sessionKey")
        return cls(base_url, session_key=key, verify=verify, **kw)

    def export(self, search, earliest, latest, extra_params=None):
        """Stream results of a search. Yields dicts."""
        params = {
            "search": normalise_search(search),
            "output_mode": "json",
            "earliest_time": earliest,
            "latest_time": latest,
            "count": 0,
        }
        if extra_params:
            params.update(extra_params)
        resp = self.post("/search/jobs/export", params, stream=True)
        try:
            for line in resp:
                line = line.decode("utf-8", "replace").strip()
                if not line:
                    continue
                try:
                    obj = json.loads(line)
                except ValueError:
                    continue
                if "result" in obj:
                    # A sort in the pipeline (--select random) makes the export
                    # endpoint emit a preview batch before the final one. Taking
                    # both would double-count.
                    if obj.get("preview") is True:
                        continue
                    yield obj["result"]
                elif "messages" in obj:
                    for m in obj["messages"]:
                        if m.get("type", "").upper() in ("ERROR", "FATAL", "WARN"):
                            log("  splunk %s: %s" % (m.get("type"), m.get("text")))
        finally:
            resp.close()


def normalise_search(spl):
    spl = spl.strip()
    if spl.startswith("|") or spl.lower().startswith("search "):
        return spl
    return "search " + spl


def escape_spl_value(value):
    return value.replace("\\", "\\\\").replace('"', '\\"')


# --------------------------------------------------------------------------
# Distribution and allocation
# --------------------------------------------------------------------------

def fetch_distribution(client, base, field, earliest, latest,
                       include_missing, missing_label):
    if include_missing:
        spl = '%s | fillnull value="%s" %s | stats count by %s' % (
            base, missing_label, field, field)
    else:
        spl = "%s | stats count by %s" % (base, field)
    log("count pass: %s" % spl)
    counts = {}
    for row in client.export(spl, earliest, latest):
        if field not in row:
            continue
        try:
            counts[row[field]] = int(row.get("count") or 0)
        except (TypeError, ValueError):
            continue
    return {k: v for k, v in counts.items() if v > 0}


def largest_remainder(counts, target):
    """Hamilton apportionment of `target` over `counts`."""
    total = float(sum(counts.values()))
    if total <= 0 or target <= 0:
        return {k: 0 for k in counts}
    quota = {k: target * (v / total) for k, v in counts.items()}
    alloc = {k: int(math.floor(q)) for k, q in quota.items()}
    leftover = target - sum(alloc.values())
    order = sorted(counts,
                   key=lambda k: (-(quota[k] - alloc[k]), -counts[k], str(k)))
    for k in order[:leftover]:
        alloc[k] += 1
    return alloc


def allocate(counts, target, min_per_type=0):
    """Proportional allocation, capped at availability, summing to target."""
    total = sum(counts.values())
    target = min(target, total)
    floors = {k: min(min_per_type, counts[k]) for k in counts}

    if sum(floors.values()) > target:
        # Not enough budget for the floor. Hand out one at a time, biggest
        # population first, so the common types are still represented.
        alloc = {k: 0 for k in counts}
        order = sorted(counts, key=lambda k: (-counts[k], str(k)))
        left = target
        while left > 0:
            moved = False
            for k in order:
                if left == 0:
                    break
                if alloc[k] < floors[k]:
                    alloc[k] += 1
                    left -= 1
                    moved = True
            if not moved:
                break
        return alloc

    alloc = dict(floors)
    left = target - sum(alloc.values())
    while left > 0:
        pool = {k: counts[k] for k in counts if alloc[k] < counts[k]}
        if not pool:
            break
        room = sum(counts[k] - alloc[k] for k in pool)
        add = largest_remainder(pool, min(left, room))
        moved = False
        for k, n in add.items():
            take = min(n, counts[k] - alloc[k])
            if take > 0:
                alloc[k] += take
                left -= take
                moved = True
        if not moved:
            k = max(pool, key=lambda k: (counts[k], str(k)))
            alloc[k] += 1
            left -= 1
    return alloc


# --------------------------------------------------------------------------
# Fetch
# --------------------------------------------------------------------------

def build_fetch_search(base, field, value, n, available, select, missing_label):
    if value == missing_label:
        filt = "NOT %s=*" % field
    else:
        filt = '%s="%s"' % (field, escape_spl_value(value))
    spl = "%s %s" % (base, filt)
    if select == "spread" and n > 0 and available > n:
        step = max(2, int(available // n))
        spl += (" | streamstats count as %s | where (%s %% %d)==0"
                " | head %d | fields - %s"
                % (SCRATCH_N, SCRATCH_N, step, n, SCRATCH_N))
    elif select == "random":
        spl += (" | eval %s=random() | sort 0 %s | head %d | fields - %s"
                % (SCRATCH_R, SCRATCH_R, n, SCRATCH_R))
    else:
        spl += " | head %d" % n
    return spl + " | eval %s=_time" % SCRATCH_EPOCH


def fetch_one(client, base, field, value, n, available, earliest, latest,
              select, missing_label):
    spl = build_fetch_search(base, field, value, n, available, select,
                             missing_label)
    rows = []
    for row in client.export(spl, earliest, latest):
        rows.append(row)
        if len(rows) >= n:
            break
    return value, spl, rows


# --------------------------------------------------------------------------
# Transform
# --------------------------------------------------------------------------

class Renamer(object):
    """Substring rewrite of field NAMES, in record keys and inside _raw."""

    def __init__(self, rules, ignore_case=False, rename_internal=False):
        self.rules = list(rules)
        self.flags = re.IGNORECASE if ignore_case else 0
        self.rename_internal = rename_internal
        self._key_cache = {}
        self._raw_pats = []
        for needle, repl in self.rules:
            name = (r"[A-Za-z0-9_.\-]*" + re.escape(needle) +
                    r"[A-Za-z0-9_.\-]*")
            json_pat = re.compile(r'"(' + name + r')"(\s*:)', self.flags)
            kv_pat = re.compile(r"(?<![A-Za-z0-9_.\-])(" + name + r")(\s*=)",
                                self.flags)
            self._raw_pats.append((json_pat, kv_pat, needle, repl))

    def active(self):
        return bool(self.rules)

    def _sub(self, needle, repl, text):
        return re.sub(re.escape(needle), lambda m: repl, text, flags=self.flags)

    def key(self, key):
        try:
            return self._key_cache[key]
        except KeyError:
            pass
        new = key
        if self.rename_internal or not key.startswith("_"):
            for needle, repl in self.rules:
                new = self._sub(needle, repl, new)
        self._key_cache[key] = new
        return new

    def raw(self, text):
        for json_pat, kv_pat, needle, repl in self._raw_pats:
            text = json_pat.sub(
                lambda m: '"' + self._sub(needle, repl, m.group(1)) + '"' + m.group(2),
                text)
            text = kv_pat.sub(
                lambda m: self._sub(needle, repl, m.group(1)) + m.group(2),
                text)
        return text

    def raw_blunt(self, text):
        for needle, repl in self.rules:
            text = self._sub(needle, repl, text)
        return text


_ISO_RE = re.compile(
    r"^(\d{4})-(\d{2})-(\d{2})[T ](\d{2}):(\d{2}):(\d{2})"
    r"(?:\.(\d+))?(Z|[+-]\d{2}:?\d{2})?$")


def iso_to_epoch(value):
    if value is None:
        return None
    text = str(value).strip()
    try:
        return float(text)  # already epoch
    except ValueError:
        pass
    m = _ISO_RE.match(text)
    if not m:
        return None
    y, mo, d, h, mi, s, frac, tz = m.groups()
    epoch = calendar.timegm((int(y), int(mo), int(d), int(h), int(mi),
                             int(s), 0, 0, 0))
    if frac:
        epoch += float("0." + frac)
    if tz and tz != "Z":
        tz = tz.replace(":", "")
        sign = 1 if tz[0] == "+" else -1
        epoch -= sign * (int(tz[1:3]) * 3600 + int(tz[3:5]) * 60)
    return epoch


def record_epoch(row):
    """Epoch for an event. Prefers the value Splunk computed for us."""
    value = row.get(SCRATCH_EPOCH)
    if value is not None:
        try:
            return float(value)
        except (TypeError, ValueError):
            pass
    return iso_to_epoch(row.get("_time"))


def clean_record(row, keep_internal, whitelist):
    out = {}
    for k, v in row.items():
        if whitelist and k not in whitelist and k not in ("_raw", "_time"):
            continue
        if not keep_internal and k not in ALWAYS_KEEP:
            if k in NOISE_FIELDS or k.startswith(NOISE_PREFIXES):
                continue
        out[k] = v
    return out


def transform(row, renamer, args):
    epoch = record_epoch(row)
    rec = clean_record(row, args.keep_internal, args.whitelist)
    rec.pop(SCRATCH_EPOCH, None)
    if epoch is not None:
        rec[EPOCH_FIELD] = round(epoch, 3)
    raw = rec.get("_raw")
    if raw is not None and renamer.active():
        if args.raw_replace_all:
            raw = renamer.raw_blunt(raw)
        elif args.rename_in_raw:
            raw = renamer.raw(raw)
        rec["_raw"] = raw
    if renamer.active():
        rec = {renamer.key(k): v for k, v in rec.items()}
    return rec


# --------------------------------------------------------------------------
# Output
# --------------------------------------------------------------------------

def write_output(records, args, fh):
    multiline = 0
    for rec in records:
        if not args.epoch_field and args.format != "hec":
            rec.pop(EPOCH_FIELD, None)
        if args.format == "ndjson":
            fh.write(json.dumps(rec, ensure_ascii=False, sort_keys=True) + "\n")
        elif args.format == "raw":
            raw = rec.get("_raw", "")
            if "\n" in raw:
                multiline += 1
                if args.escape_newlines:
                    raw = raw.replace("\\", "\\\\").replace("\n", "\\n").replace("\r", "\\r")
            fh.write(raw + "\n")
        elif args.format == "hec":
            event = rec.get("_raw", "")
            if args.hec_parse_json:
                try:
                    event = json.loads(event)
                except (ValueError, TypeError):
                    pass
            env = {"event": event}
            epoch = rec.get(EPOCH_FIELD)
            if epoch is None:
                epoch = iso_to_epoch(rec.get("_time"))
            if epoch is not None:
                env["time"] = round(epoch, 3)
            for key, field in (("host", "host"), ("source", "source"),
                               ("sourcetype", "sourcetype"), ("index", "index")):
                if field in rec and rec[field]:
                    env[key] = rec[field]
            if args.hec_index:
                env["index"] = args.hec_index
            fh.write(json.dumps(env, ensure_ascii=False) + "\n")
    return multiline


# --------------------------------------------------------------------------
# CLI
# --------------------------------------------------------------------------

def parse_rename(values):
    rules = []
    for item in values or []:
        if "=" not in item:
            raise argparse.ArgumentTypeError(
                "--rename needs OLD=NEW, got %r" % item)
        old, new = item.split("=", 1)
        if not old:
            raise argparse.ArgumentTypeError("--rename OLD must not be empty")
        rules.append((old, new))
    return rules


# Splunk time modifiers start with "-", which argparse reads as a flag.
# "--earliest -24h" is the idiom everyone types, so glue it back together.
_TIME_OPTS = ("--earliest", "--latest")


def glue_time_args(argv):
    out = []
    i = 0
    while i < len(argv):
        tok = argv[i]
        if tok in _TIME_OPTS and i + 1 < len(argv) and argv[i + 1].startswith("-"):
            out.append("%s=%s" % (tok, argv[i + 1]))
            i += 2
            continue
        out.append(tok)
        i += 1
    return out


def build_args(argv=None):
    p = argparse.ArgumentParser(
        description="Export a proportionally representative Splunk event sample.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__.split("Examples")[-1])

    conn = p.add_argument_group("connection")
    conn.add_argument("--host", help="Splunk management host")
    conn.add_argument("--port", type=int, default=8089)
    conn.add_argument("--url", help="full base URL, overrides --host/--port")
    conn.add_argument("--token", help="auth token (prefer --token-env)")
    conn.add_argument("--token-env", default="SPLUNK_TOKEN",
                      help="env var holding the auth token (default SPLUNK_TOKEN)")
    conn.add_argument("--username")
    conn.add_argument("--password-env", default="SPLUNK_PASSWORD")
    conn.add_argument("--app", help="run in this app namespace")
    conn.add_argument("--owner", help="namespace owner (default nobody)")
    conn.add_argument("-k", "--insecure", action="store_true",
                      help="do not verify the TLS certificate")
    conn.add_argument("--timeout", type=int, default=900)

    sel = p.add_argument_group("sampling")
    sel.add_argument("--search", required=True,
                     help="base search, e.g. 'index=audit sourcetype=foo'")
    sel.add_argument("--field", required=True,
                     help="field to stratify on, e.g. audit_type")
    sel.add_argument("--earliest", default="-24h")
    sel.add_argument("--latest", default="now")
    sel.add_argument("--target", type=int, default=10000,
                     help="total events wanted (default 10000)")
    sel.add_argument("--min-per-type", type=int, default=0,
                     help="floor per value. 0 (default) keeps the sample "
                          "strictly proportional; 1 guarantees every value "
                          "appears, at the cost of over-weighting rare ones")
    sel.add_argument("--select", choices=("head", "spread", "random"),
                     default="head",
                     help="head: newest N, cheapest (default). spread: every "
                          "Nth across the window. random: shuffle then take, "
                          "most expensive")
    sel.add_argument("--no-missing", dest="include_missing",
                     action="store_false",
                     help="ignore events where the field is absent (default is "
                          "to treat them as their own bucket)")
    sel.add_argument("--missing-label", default=DEFAULT_MISSING)
    sel.add_argument("--workers", type=int, default=4,
                     help="concurrent searches (default 4; lower it if the "
                          "role's search quota is tight)")
    sel.add_argument("--dist-file",
                     help="read the distribution from this JSON instead of "
                          "running the count pass")
    sel.add_argument("--save-dist",
                     help="write the distribution to this JSON")
    sel.add_argument("--count-only", action="store_true",
                     help="show the distribution and the plan, export nothing")

    red = p.add_argument_group("redaction")
    red.add_argument("--rename", action="append", metavar="OLD=NEW",
                     help="rewrite OLD to NEW inside field names, e.g. "
                          "audit=apple turns audit_type into apple_type. "
                          "Repeatable")
    red.add_argument("--no-rename-in-raw", dest="rename_in_raw",
                     action="store_false",
                     help="only rename the record keys, leave _raw alone "
                          "(default also rewrites field names inside _raw, "
                          "which is what gets re-indexed on replay)")
    red.add_argument("--raw-replace-all", action="store_true",
                     help="blunt substring replace in _raw, values included. "
                          "Use only if you know the string never appears in "
                          "data you want to keep")
    red.add_argument("--rename-internal", action="store_true",
                     help="also rename fields starting with _")
    red.add_argument("--ignore-case", action="store_true")

    out = p.add_argument_group("output")
    out.add_argument("-o", "--output", required=False,
                     help="output file (default stdout)")
    out.add_argument("--format", choices=("ndjson", "raw", "hec"),
                     default="ndjson")
    out.add_argument("--order", choices=("time", "source", "shuffle"),
                     default="time",
                     help="time: oldest first, realistic for replay (default). "
                          "source: grouped by field value. shuffle: random")
    out.add_argument("--keep-internal", action="store_true",
                     help="keep _bkt/_cd/date_*/punct etc (dropped by default)")
    out.add_argument("--fields", dest="whitelist_csv",
                     help="comma separated whitelist of fields to keep")
    out.add_argument("--escape-newlines", action="store_true",
                     help="--format raw: escape newlines so one event is "
                          "always one line")
    out.add_argument("--hec-parse-json", action="store_true",
                     help="--format hec: embed _raw as an object when it "
                          "parses as JSON")
    out.add_argument("--hec-index", help="--format hec: override the index")
    out.add_argument("--no-epoch-field", dest="epoch_field",
                     action="store_false",
                     help="omit the %s field. It is added because Splunk "
                          "renders _time with an ambiguous timezone "
                          "abbreviation, so _time alone cannot be converted "
                          "reliably downstream" % EPOCH_FIELD)
    out.add_argument("--manifest",
                     help="write a run manifest here (default <output>.manifest.json)")
    out.add_argument("--seed", type=int, help="seed for --order shuffle")

    args = p.parse_args(glue_time_args(list(sys.argv[1:] if argv is None else argv)))
    if not args.url and not args.host:
        p.error("one of --host or --url is required")
    args.base_url = args.url or ("https://%s:%d" % (args.host, args.port))
    args.rename_rules = parse_rename(args.rename)
    args.whitelist = set(
        f.strip() for f in args.whitelist_csv.split(",") if f.strip()
    ) if args.whitelist_csv else None
    if not re.match(r"^[A-Za-z_][A-Za-z0-9_.]*$", args.field):
        p.error("--field %r is not a plain field name; quote-sensitive names "
                "are not supported" % args.field)
    return args


def connect(args):
    token = args.token or (os.environ.get(args.token_env) if args.token_env else None)
    kw = dict(verify=not args.insecure, timeout=args.timeout,
              app=args.app, owner=args.owner)
    if token:
        return SplunkClient(args.base_url, token=token.strip(), **kw)
    if args.username:
        password = os.environ.get(args.password_env)
        if not password:
            raise SplunkError("--username given but $%s is empty" % args.password_env)
        return SplunkClient.from_password(args.base_url, args.username,
                                          password, verify=not args.insecure,
                                          timeout=args.timeout, app=args.app,
                                          owner=args.owner)
    raise SplunkError(
        "no credentials: set $%s, or pass --token, or --username with $%s"
        % (args.token_env, args.password_env))


def report_plan(counts, alloc, target):
    total = sum(counts.values())
    planned = sum(alloc.values())
    rows = sorted(counts, key=lambda k: (-counts[k], str(k)))
    width = max([len(str(k)) for k in rows] + [len("value")])
    lines = ["",
             "%-*s %12s %8s %8s %8s" % (width, "value", "population",
                                        "share%", "planned", "out%"),
             "-" * (width + 42)]
    for k in rows:
        share = 100.0 * counts[k] / total if total else 0.0
        oshare = 100.0 * alloc.get(k, 0) / planned if planned else 0.0
        lines.append("%-*s %12d %8.3f %8d %8.3f"
                     % (width, k, counts[k], share, alloc.get(k, 0), oshare))
    lines.append("-" * (width + 42))
    lines.append("%-*s %12d %8s %8d" % (width, "TOTAL", total, "", planned))
    zeroed = [k for k in rows if alloc.get(k, 0) == 0]
    if zeroed:
        lines.append("")
        lines.append("%d value(s) allocated 0 events: too rare for a sample of "
                     "%d. Use --min-per-type 1 to force them in."
                     % (len(zeroed), target))
        lines.append("  " + ", ".join(str(k) for k in zeroed[:20])
                     + (" ..." if len(zeroed) > 20 else ""))
    if planned < target:
        lines.append("")
        lines.append("Only %d events available in the window, below the target "
                     "of %d." % (planned, target))
    return "\n".join(lines)


def main(argv=None):
    args = build_args(argv)
    if args.seed is not None:
        random.seed(args.seed)
    started = time.time()
    client = connect(args)

    if args.dist_file:
        with open(args.dist_file) as fh:
            counts = {k: int(v) for k, v in json.load(fh)["counts"].items()}
        log("distribution loaded from %s (%d values)" % (args.dist_file, len(counts)))
    else:
        counts = fetch_distribution(client, args.search, args.field,
                                    args.earliest, args.latest,
                                    args.include_missing, args.missing_label)
    if not counts:
        log("no events matched '%s' between %s and %s"
            % (args.search, args.earliest, args.latest))
        return 1
    log("%d distinct %s values, %d events in the window"
        % (len(counts), args.field, sum(counts.values())))

    if args.save_dist:
        with open(args.save_dist, "w") as fh:
            json.dump({"search": args.search, "field": args.field,
                       "earliest": args.earliest, "latest": args.latest,
                       "counts": counts}, fh, indent=2, sort_keys=True)
        log("distribution written to %s" % args.save_dist)

    alloc = allocate(counts, args.target, max(0, args.min_per_type))
    print(report_plan(counts, alloc, args.target))

    if args.count_only:
        return 0

    wanted = {k: n for k, n in alloc.items() if n > 0}
    records = []
    per_value = {}
    searches = {}
    errors = []
    done = [0]

    def task(value):
        return fetch_one(client, args.search, args.field, value,
                         wanted[value], counts[value], args.earliest,
                         args.latest, args.select, args.missing_label)

    log("")
    log("fetch pass: %d searches, %d workers" % (len(wanted), args.workers))
    with ThreadPoolExecutor(max_workers=max(1, args.workers)) as pool:
        for value, spl, rows in pool.map(task, list(wanted)):
            searches[value] = spl
            per_value[value] = len(rows)
            records.extend(rows)
            done[0] += 1
            if len(rows) < wanted[value]:
                errors.append("%s: asked %d, got %d"
                              % (value, wanted[value], len(rows)))
            if done[0] % 10 == 0 or done[0] == len(wanted):
                log("  %d/%d searches, %d events"
                    % (done[0], len(wanted), len(records)))

    # A wildcard in a value would make the SPL filter over-match. Check.
    foreign = {}
    for row in records:
        got = row.get(args.field, args.missing_label)
        if got not in wanted:
            foreign[got] = foreign.get(got, 0) + 1
    if foreign:
        log("WARNING: %d event(s) came back with unexpected %s values "
            "(a wildcard or a multivalue field in the data): %s"
            % (sum(foreign.values()), args.field,
               ", ".join(sorted(foreign)[:5])))

    if args.order == "time":
        records.sort(key=lambda r: (record_epoch(r) or 0.0))
    elif args.order == "shuffle":
        random.shuffle(records)

    renamer = Renamer(args.rename_rules, args.ignore_case, args.rename_internal)
    out_records = (transform(r, renamer, args) for r in records)

    if args.output:
        fh = open(args.output, "w", encoding="utf-8")
    else:
        fh = sys.stdout
    try:
        multiline = write_output(out_records, args, fh)
    finally:
        if args.output:
            fh.close()

    log("")
    log("exported %d events to %s (%s)"
        % (len(records), args.output or "stdout", args.format))
    if multiline and not args.escape_newlines:
        log("NOTE: %d event(s) span multiple lines. --format raw will need a "
            "LINE_BREAKER on the way back in, or use --escape-newlines."
            % multiline)
    if errors:
        log("%d value(s) returned fewer events than planned:" % len(errors))
        for e in errors[:10]:
            log("  " + e)
    if renamer.active():
        log("renamed field names: %s"
            % ", ".join("%s->%s" % r for r in args.rename_rules))

    manifest_path = args.manifest
    if not manifest_path and args.output:
        manifest_path = args.output + ".manifest.json"
    if manifest_path:
        total = sum(counts.values())
        got = sum(per_value.values()) or 1
        manifest = {
            "generated": time.strftime("%Y-%m-%dT%H:%M:%S%z"),
            "elapsed_seconds": round(time.time() - started, 1),
            "source": {"base_url": args.base_url, "search": args.search,
                       "field": args.field, "earliest": args.earliest,
                       "latest": args.latest, "app": args.app},
            "sampling": {"target": args.target, "select": args.select,
                         "min_per_type": args.min_per_type,
                         "include_missing": args.include_missing,
                         "population": total, "exported": sum(per_value.values())},
            "renames": ["%s=%s" % r for r in args.rename_rules],
            "output": {"path": args.output, "format": args.format,
                       "order": args.order},
            "per_value": {
                str(k): {"population": counts[k],
                         "population_share_pct": round(100.0 * counts[k] / total, 6) if total else 0,
                         "planned": alloc.get(k, 0),
                         "exported": per_value.get(k, 0),
                         "exported_share_pct": round(100.0 * per_value.get(k, 0) / got, 6)}
                for k in sorted(counts, key=lambda k: (-counts[k], str(k)))
            },
            "searches": searches,
        }
        with open(manifest_path, "w") as mf:
            json.dump(manifest, mf, indent=2, sort_keys=True)
        log("manifest written to %s" % manifest_path)
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except SplunkError as exc:
        sys.stderr.write("error: %s\n" % exc)
        sys.exit(1)
    except KeyboardInterrupt:
        sys.stderr.write("\ninterrupted\n")
        sys.exit(130)
