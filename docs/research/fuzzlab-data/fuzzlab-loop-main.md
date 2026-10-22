# fuzzlab-loop-main

| policy | runs | 边覆盖 mean [min..max] | 离散度 | 崩溃 |
|---|---|---|---|---|
| `libfuzzer` | 3 | 263.67 [262..265] | 3 | 0 |
| `fifo` | 3 | 238.0 [237..239] | 2 | 0 |
| `rr` | 3 | 274.67 [270..282] | 12 | 0 |
| `static` | 3 | 237.33 [235..240] | 5 | 0 |
| `feedback` | 3 | 277.33 [274..279] | 5 | 0 |
| `full` | 3 | 276.0 [273..279] | 6 | 0 |

| policy | Δ vs `rr` | 判读 |
|---|---|---|
| `libfuzzer` | -11.00 | inside seed spread |
| `fifo` | -36.67 | outside seed spread |
| `rr` | +0.00 | baseline A |
| `static` | -37.34 | outside seed spread |
| `feedback` | +2.66 | inside seed spread |
| `full` | +1.33 | inside seed spread |
