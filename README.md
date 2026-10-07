# splunk_sample_export.py

Export a **proportionally representative** sample of Splunk events for load
testing, optionally rewriting field names on the way out.

Single file, standard library only, Python 3.6+. Copy
`splunk_sample_export.py` to the target environment and run it. No Splunk SDK, no
`pip install`, nothing else to put on the box.

Written for the case where the Splunk estate you need to sample is not the one
you can develop against.

## What it does

If `audit_type=X` is 1% of the events in your window and you ask for 10,000
events, you get 100 of them. Every value keeps its real share.

Two passes:

1. **Count pass** — `<base search> | stats count by <field>` gives the true
   population share of every value.
2. **Fetch pass** — one search per value, `<base search> <field>="v" | head N`,
   where `N` is that value's share of `--target`.

The split uses the largest-remainder method, so the parts sum to exactly
`--target` rather than drifting by a few dozen events from rounding. Values are
capped at what actually exists and any shortfall is redistributed over the
remaining values, still proportionally, until the target is met or the window is
exhausted.

## Quick start

```bash
export SPLUNK_TOKEN='...'          # or use --username with $SPLUNK_PASSWORD

# 1. Look before you leap: distribution + sampling plan, exports nothing.
./splunk_sample_export.py --host splunk.example.com -k \
    --search 'index=audit' --field audit_type \
    --earliest -24h --latest now --target 10000 --count-only

# 2. Export, renaming audit* -> apple*
./splunk_sample_export.py --host splunk.example.com -k \
    --search 'index=audit' --field audit_type \
    --earliest -24h --latest now --target 10000 \
    --rename audit=apple -o sample.ndjson
```

`--count-only` is cheap and is the right first move on an unfamiliar index: it
shows you the real distribution, how many events each value would contribute,
and which values are too rare to appear at all.

## Output formats

| `--format` | Shape | Use for |
|---|---|---|
| `ndjson` (default) | one JSON object per event, `_raw` plus the fields | highest fidelity, inspection, re-processing |
| `raw` | just `_raw`, one event per line | file monitor, eventgen, replay |
| `hec` | `{"time","host","source","sourcetype","index","event"}` per line | posting straight to HEC |

Events are written oldest-first by default (`--order time`) so a replay looks
like real traffic rather than a block of one type followed by a block of
another. `--order source` groups by field value and streams; `--order shuffle`
randomises.

`--format raw` warns if any event spans multiple lines, because one event will
no longer be one line on the way back in. Either set a `LINE_BREAKER` in the
receiving props.conf or use `--escape-newlines`.

## Renaming field names

`--rename audit=apple` turns `audit_type` into `apple_type`, `pre_audit_id` into
`pre_apple_id`, and so on. It is a substring rewrite inside the **name**, so the
rest of the name survives. Repeatable for multiple rules.

It rewrites two places:

1. The keys of the exported records.
2. Field-name-shaped tokens inside `_raw` — `"audit_type":` in JSON and
   `audit_type=` in key=value. **This is the part that matters**, because `_raw`
   is what gets re-indexed when you replay the file. Renaming only the JSON keys
   of the export would leave `audit_*` field names in the replayed data.

Values are never touched. `action=audit` stays `action=audit`;
`info="audit failed"` stays as it is. The one deliberate exception is a nested
key=value inside a value, e.g. `info="audit_type=login"`, which becomes
`info="apple_type=login"` — because Splunk's KV extraction would pull that out
as a field on re-index too.

Other switches:

- `--no-rename-in-raw` — rename only the record keys, leave `_raw` alone.
- `--raw-replace-all` — blunt substring replace across all of `_raw`, values
  included. Only safe if the string never appears in data you want to keep.
- `--rename-internal` — also rename `_`-prefixed fields (off by default).
- `--ignore-case`.

Check the result before you trust it:

```bash
# field-name positions that still contain the old word (want: nothing)
grep -oE '(^|[^A-Za-z0-9_.-])[A-Za-z0-9_.-]*audit[A-Za-z0-9_.-]*[[:space:]]*[=:]' sample.ndjson | sort -u
```

## Sampling choices worth knowing

**`--min-per-type`** defaults to 0, which keeps the sample strictly
proportional. The cost is that genuinely rare values get allocated zero events:
a type that is 1 in 50,000 cannot appear in a sample of 10,000 without being
over-represented. The plan table lists every value that got zero. If you would
rather exercise every parsing path than hold the ratios exactly, use
`--min-per-type 1`; the floor is taken out of the budget and the remainder is
still allocated proportionally.

**`--select`** decides *which* events of a value you get:

- `head` (default) — the newest N. Cheapest by far. The sample is a narrow slice
  at the recent end of the window.
- `spread` — every Nth event across the whole window, via `streamstats`. Better
  time coverage, reads more of the window.
- `random` — shuffles the value's whole population, then takes N. Most
  representative, by a long way the most expensive, and `sort 0` is memory
  hungry on a large population. Fine for small indexes, not for busy ones.

Measured on a 4 hour window: `head` returned 300 events spanning **4.7 minutes**,
`spread` returned 300 spanning the full **238 minutes**. If the load test cares
about time distribution and not just the mix of types, `head` is the wrong
default for you.

**Missing values.** Events where the field is absent form their own
`__MISSING__` bucket and are sampled like any other value, fetched with
`NOT <field>=*`. `--no-missing` drops them instead.

**Two-stage runs.** If the count pass is slow, run it once with
`--count-only --save-dist dist.json`, then reuse it with `--dist-file dist.json`
for as many exports as you like. You can also hand-edit the counts in that file
to force a distribution.

**Concurrency.** The fetch pass runs `--workers` searches at once (default 4).
If the role's concurrent-search quota is tight, drop it to 1; it only costs wall
clock. 100 distinct values means 100 searches, each one cheap because
`<field>="value"` is a term lookup and `head` stops the search early.

## The `_epoch` field

Each exported record gets an `_epoch` field, and `--format hec` uses it for
`time`. This is not decoration. Splunk renders `_time` in export output with a
timezone **abbreviation**:

    "_time": "2026-10-07 16:37:42.576 BST"

`BST` is both British Summer Time and Bougainville Standard Time, so nothing
downstream can convert that reliably. The script appends `| eval zz_epoch=_time`
to each fetch search and takes the numeric value from Splunk itself rather than
guessing. `--no-epoch-field` removes it if you really do not want the extra
field.

## Noise fields

Search-time cruft that Splunk regenerates on re-index (`_bkt`, `_cd`, `_si`,
`_indextime`, `_subsecond`, `punct`, `date_*`, `tag::*`, `eventtype`, ...) is
dropped. `_raw`, `_time`, `host`, `source`, `sourcetype`, `index` and
`linecount` are always kept. `--keep-internal` keeps everything;
`--fields a,b,c` keeps only what you name.

## Manifest

Every run with `-o` writes `<output>.manifest.json`: the search, time range,
target, per-value population share vs exported share, and the exact SPL used for
each value. It is the evidence that the sample is representative, and it makes a
run reproducible months later. No credentials are recorded.

## Gotchas found while building this

- Scratch fields must not start with `_`. Splunk treats leading-underscore
  fields as internal and a following `where` never sees them, so
  `streamstats count as __n | where (__n % 10)==0` silently returns **zero**
  events, with no error. The script uses `zz_sample_n`.
- `--select random` puts a `sort` in the pipeline, which makes
  `search/jobs/export` emit a **preview batch followed by the final batch**.
  Reading both double-counts every event. The script skips `"preview": true`.
- `--earliest -24h` would normally break `argparse`, since `-24h` looks like a
  flag. The script glues the pair back together, so the natural Splunk idiom
  works and you do not need `--earliest=-24h`.
- `stats count by <field>` silently drops events where the field is missing,
  which quietly biases the whole sample. Hence the `__MISSING__` bucket being on
  by default.
- A `*` in a field value would make `<field>="v*"` over-match. The script
  verifies what came back and warns if a search returned foreign values.
- `_time` comes back as a timezone abbreviation, not an offset, so it is not
  safely parseable. See `_epoch` above.

## Tests

```bash
python3 test_splunk_sample_export.py
```

45 offline checks on the renamer, the allocator, time parsing, search
construction and field filtering. No Splunk needed.

Verified live against Splunk 10.5 (`index=_audit`, 23,000 events, 26 distinct
`action` values): exports land exactly on `--target`, and the worst proportional
drift between a value's population share and its share of the output was
**0.024 percentage points** on a 2,000 event sample, which is integer rounding
and nothing else.
