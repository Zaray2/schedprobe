# fuzzlab-loop-pilot

| policy | runs | 边覆盖 mean [min..max] | 离散度 | 崩溃 |
|---|---|---|---|---|
| `libfuzzer` | 1 | 117.0 [117..117] | 0 | 1 |
| `fifo` | 1 | 239.0 [239..239] | 0 | 0 |
| `rr` | 1 | 282.0 [282..282] | 0 | 0 |
| `static` | 1 | 237.0 [237..237] | 0 | 0 |
| `feedback` | 1 | 274.0 [274..274] | 0 | 0 |
| `full` | 1 | 276.0 [276..276] | 0 | 0 |

| policy | Δ vs `rr` | 判读 |
|---|---|---|
| `libfuzzer` | -165.00 | outside seed spread |
| `fifo` | -43.00 | outside seed spread |
| `rr` | +0.00 | baseline A |
| `static` | -45.00 | outside seed spread |
| `feedback` | -8.00 | outside seed spread |
| `full` | -6.00 | outside seed spread |
