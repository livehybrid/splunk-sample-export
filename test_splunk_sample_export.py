#!/usr/bin/env python3
"""Offline tests for splunk_sample_export.py. No Splunk needed.

    python3 test_splunk_sample_export.py
"""
import importlib.util
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
spec = importlib.util.spec_from_file_location(
    "sse", os.path.join(HERE, "splunk_sample_export.py"))
sse = importlib.util.module_from_spec(spec)
spec.loader.exec_module(sse)

failures = []


def check(label, got, want):
    if got == want:
        print("ok   %s" % label)
    else:
        failures.append(label)
        print("FAIL %s\n       want: %r\n       got : %r" % (label, want, got))


# ---------------------------------------------------------------- renaming
R = sse.Renamer([("audit", "apple")])

RAW_CASES = [
    ("json keys",
     '{"audit_type":"login","audit_id":7,"user":"will"}',
     '{"apple_type":"login","apple_id":7,"user":"will"}'),
    ("json nested and spaced key",
     '{"outer": {"pre_audit_stage" : "x"}}',
     '{"outer": {"pre_apple_stage" : "x"}}'),
    ("json value left alone",
     '{"note":"audit failed","audit_id":1}',
     '{"note":"audit failed","apple_id":1}'),
    ("key=value keys",
     'ts=1 audit_type=login audit.sub=3 pre_audit=1',
     'ts=1 apple_type=login apple.sub=3 pre_apple=1'),
    ("key=value value left alone",
     'action=audit result=ok',
     'action=audit result=ok'),
    ("prose inside a quoted value left alone",
     'info="audit_type is login"',
     'info="audit_type is login"'),
    ("nested key=value inside a value IS renamed (Splunk extracts it too)",
     'info="audit_type=login"',
     'info="apple_type=login"'),
    ("bare csv header is not a field-name position",
     'audit_type,user,host',
     'audit_type,user,host'),
    ("partial word boundary",
     '{"preaudit":1,"auditing":2}',
     '{"preapple":1,"appleing":2}'),
]
for label, src, want in RAW_CASES:
    check("raw: " + label, R.raw(src), want)

check("key: plain", R.key("audit_type"), "apple_type")
check("key: infix", R.key("x_audit_y"), "x_apple_y")
check("key: internal fields protected", R.key("_audit_time"), "_audit_time")
check("key: untouched", R.key("unrelated"), "unrelated")
check("key: internal renamed on request",
      sse.Renamer([("audit", "apple")], rename_internal=True).key("_audit_time"),
      "_apple_time")
check("ignore case",
      sse.Renamer([("audit", "apple")], ignore_case=True).raw('{"AUDIT_type":1}'),
      '{"apple_type":1}')
check("blunt mode hits values too",
      R.raw_blunt('action=audit note="audit failed"'),
      'action=apple note="apple failed"')
check("multiple rules",
      sse.Renamer([("audit", "apple"), ("user", "owner")]).raw('audit_user=1'),
      'apple_owner=1')

# -------------------------------------------------------------- allocation
POP = {"a": 900000, "b": 90000, "c": 9000, "d": 900, "e": 90, "f": 9, "g": 1}
for target in (100, 1000, 10000, 99999):
    alloc = sse.allocate(POP, target)
    check("allocate sums to target (%d)" % target, sum(alloc.values()), target)
check("allocate is proportional at 10000",
      sse.allocate(POP, 10000),
      {"a": 9000, "b": 900, "c": 90, "d": 9, "e": 1, "f": 0, "g": 0})
check("allocate clamps to availability",
      sse.allocate({"x": 3, "y": 2}, 100), {"x": 3, "y": 2})
check("allocate redistributes a capped value's surplus",
      sse.allocate({"x": 10, "y": 1}, 11), {"x": 10, "y": 1})
alloc = sse.allocate(POP, 1000, min_per_type=1)
check("min-per-type floor reaches every value",
      sorted(v > 0 for v in alloc.values()), [True] * len(POP))
check("min-per-type still sums to target", sum(alloc.values()), 1000)
check("min-per-type over budget stays on target",
      sum(sse.allocate(POP, 3, min_per_type=1).values()), 3)
check("empty population", sse.allocate({}, 100), {})

# ------------------------------------------------------------------- misc
check("epoch from iso with offset",
      sse.iso_to_epoch("2026-10-07T15:36:55.265+01:00"), 1791383815.265)
check("epoch from iso Z", sse.iso_to_epoch("2026-10-07T14:36:55Z"), 1791383815.0)
check("epoch passthrough", sse.iso_to_epoch("1791387520.265"), 1791387520.265)
check("epoch of junk", sse.iso_to_epoch("not a time"), None)
check("spl value escaping", sse.escape_spl_value('a"b\\c'), 'a\\"b\\\\c')
check("search normalised", sse.normalise_search("index=x"), "search index=x")
check("piped search untouched", sse.normalise_search("| tstats count"),
      "| tstats count")
check("negative time modifier glued",
      sse.glue_time_args(["--earliest", "-24h", "--target", "10"]),
      ["--earliest=-24h", "--target", "10"])
check("missing bucket uses NOT field=*",
      sse.build_fetch_search("search index=x", "audit_type", "__MISSING__", 5,
                             50, "head", "__MISSING__"),
      'search index=x NOT audit_type=* | head 5 | eval zz_epoch=_time')
check("fetch search carries the epoch eval",
      sse.build_fetch_search("search index=x", "audit_type", "v", 5, 50,
                             "head", "__MISSING__"),
      'search index=x audit_type="v" | head 5 | eval zz_epoch=_time')
check("epoch prefers splunk's computed value",
      sse.record_epoch({"zz_epoch": "1791387520.265",
                        "_time": "2026-10-07 16:37:42.576 BST"}),
      1791387520.265)
check("epoch falls back to iso",
      sse.record_epoch({"_time": "2026-10-07T15:36:55.265+01:00"}),
      1791383815.265)
check("tz abbreviation is unparseable, hence the eval",
      sse.iso_to_epoch("2026-10-07 16:37:42.576 BST"), None)
check("spread search shape",
      sse.build_fetch_search("search index=x", "audit_type", "v", 10, 1000,
                             "spread", "__MISSING__"),
      'search index=x audit_type="v" | streamstats count as zz_sample_n '
      '| where (zz_sample_n % 100)==0 | head 10 | fields - zz_sample_n'
      ' | eval zz_epoch=_time')
check("noise fields dropped",
      sorted(sse.clean_record({"_raw": "x", "_cd": "1:2", "_bkt": "b",
                               "date_hour": "4", "tag::action": "t",
                               "audit_type": "a"}, False, None)),
      ["_raw", "audit_type"])
check("noise kept on request",
      "_cd" in sse.clean_record({"_raw": "x", "_cd": "1:2"}, True, None), True)

print("\n%d checks failed" % len(failures))
sys.exit(1 if failures else 0)
