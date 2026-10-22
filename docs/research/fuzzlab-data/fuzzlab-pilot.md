# fuzzlab-pilot

- target: cjson-1.7.19
- budget: seconds = 40 per campaign
- seeds: 1337
- campaigns: 3

## Per-arm results

```
arm        runs execs(mean)   execs[min..max]  edges(mean)  edges[min..max]  crashes  distinct
----------------------------------------------------------------------------------------------
stock         1        3882        3882..3882        207.0         207..207        0         0
all           1        3961        3961..3961        225.0         225..225        0         0
full          1        3613        3613..3613        240.0         240..240        0         0
```

## Comparison

```
deltas are against the baseline; `spread` is that arm's own max-min across seeds,
so a delta inside the spread is not evidence of anything

arm           edges  edge_delta  spread  distinct_defects                    verdict
------------------------------------------------------------------------------------
stock         207.0        +0.0       0                 0                   baseline
all           225.0       +18.0       0                 0    better (outside spread)
full          240.0       +33.0       0                 0    better (outside spread)
```

## Scheduler mechanism

A policy that moved a number without changing the admission pattern moved it by
accident. These are the decisions the plugin actually made:

```
(no plugin decision logs)
```

## Notes

- pilot run: one seed only, not a comparison

## Environment

```
{
  "corpus_digest": "004061651669fa8d60b4a95c172205b7afc0d8498803aae0eee6e9349618106b",
  "fuzzing_os": "Alpine Linux (WSL2)",
  "host_os": "Windows",
  "host_python": "10.0.26200",
  "power_schedule": "AFL++ default (-p explore)",
  "sanitizer": "ASAN (-fsanitize=address via AFL_USE_ASAN=1)",
  "toolchain": [
    "Alpine clang version 22.1.3",
    "",
    "x86_64"
  ]
}
```
