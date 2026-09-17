# CesSpace ARC — RC-02 Performance Baseline

- **Generated:** 2026-09-17T13:44:23.567Z
- **Environment:** Linux x86_64, Node.js v24.21.0, v8 Engine
- **Total Process Memory:** RSS 117.8 MB, Heap 24.2 MB
- **Status:** Measured RC-02 Baseline

---

## 1. Executive Summary

This document establishes the official performance and latency baseline for the **CesSpace ARC RC-02 Controlled Terminal & Process Execution Core**.
All 13 permitted tools (9 RC-01 read-only inspection tools + 4 RC-02 controlled execution tools) were benchmarked using the automated harness (`benchmarks/rc02-benchmark.js`) across synthetic fixtures spanning Small (10 files), Medium (500 files), and Large (2,000 files) workspaces.

### Key Observations

1. **Control Plane Operations (`health`, `system_status`):**
   - Sub-millisecond to low-millisecond median latency (p50: < 0.5 ms).
2. **Process Lifecycle Operations (`process_status`, `process_output`, `terminate_process`):**
   - Process metadata lookups and buffered output reads execute in-memory with sub-millisecond median latency.
   - Process termination signals are dispatched promptly to OS child processes.
3. **Controlled Command Execution (`run_command`):**
   - Subprocess execution latency is bounded by the child executable execution time, canonical path check, and policy admission.
   - For short-lived commands (`node --version`), median p50 latency remains under 60 ms including full policy evaluation, spawn, output buffering, secret scrubbing, and SHA-256 audit log chaining.
4. **Git Operations (`git_status`, `git_diff`, `git_log`):**
   - Subprocess invocation using the deterministic trusted system Git binary with fixed isolation arguments and sanitized environment (`GIT_OPTIONAL_LOCKS=0`).

---

## 2. Benchmark Results Table

| Fixture             | Tool                | p50 Latency (ms) | p95 Latency (ms) | p99 Latency (ms) | Throughput (ops/sec) | Heap Delta (KB) |
| :------------------ | :------------------ | :--------------: | :--------------: | :--------------: | :------------------: | :-------------: |
| Small (10 files)    | `health`            |      0.194       |      0.421       |      0.787       |        4171.0        |      710.5      |
| Small (10 files)    | `system_status`     |      0.488       |      0.792       |      1.506       |        2020.4        |      676.5      |
| Small (10 files)    | `list_directory`    |      0.342       |      0.609       |      0.772       |        2833.3        |     1585.8      |
| Small (10 files)    | `read_file`         |      0.393       |      1.587       |      2.176       |        1805.0        |     1219.8      |
| Small (10 files)    | `search_files`      |      0.346       |      0.559       |      0.710       |        2627.2        |     2426.1      |
| Small (10 files)    | `search_text`       |      1.010       |      1.408       |      1.974       |        965.7         |     -4166.0     |
| Small (10 files)    | `git_status`        |      27.292      |      46.493      |      56.769      |         35.0         |     1740.2      |
| Small (10 files)    | `git_diff`          |      8.730       |      13.324      |      13.999      |        106.4         |     2932.5      |
| Small (10 files)    | `git_log`           |      9.207       |      27.041      |      34.227      |         67.1         |     -1853.9     |
| Small (10 files)    | `run_command`       |      8.540       |      11.937      |      13.432      |        111.2         |     1832.2      |
| Small (10 files)    | `process_status`    |      0.148       |      0.301       |      1.267       |        4740.4        |      711.6      |
| Small (10 files)    | `process_output`    |      0.128       |      0.235       |      0.300       |        7578.5        |      763.6      |
| Small (10 files)    | `terminate_process` |      0.307       |      1.275       |      1.604       |        286.5         |     2522.7      |
| Medium (500 files)  | `health`            |      0.079       |      0.103       |      0.134       |       11780.5        |      417.3      |
| Medium (500 files)  | `system_status`     |      0.343       |      0.661       |      1.662       |        2233.1        |      444.1      |
| Medium (500 files)  | `list_directory`    |      0.601       |      0.768       |      1.232       |        1562.5        |     1523.1      |
| Medium (500 files)  | `read_file`         |      0.323       |      0.391       |      0.410       |        3003.8        |      766.3      |
| Medium (500 files)  | `search_files`      |      1.362       |      5.518       |      7.723       |        383.6         |    -10802.6     |
| Medium (500 files)  | `search_text`       |      3.642       |      8.100       |      8.525       |        219.7         |     6089.2      |
| Medium (500 files)  | `git_status`        |      34.216      |      71.480      |      83.004      |         25.4         |     -6952.8     |
| Medium (500 files)  | `git_diff`          |      18.417      |      27.052      |      27.101      |         52.3         |     1923.7      |
| Medium (500 files)  | `git_log`           |      10.670      |      15.231      |      15.279      |         88.7         |     2062.3      |
| Medium (500 files)  | `run_command`       |      9.442       |      15.310      |      15.670      |         99.2         |     1077.3      |
| Medium (500 files)  | `process_status`    |      0.074       |      0.151       |      0.158       |       12729.0        |      464.4      |
| Medium (500 files)  | `process_output`    |      0.099       |      0.392       |      0.538       |        6936.5        |      493.3      |
| Medium (500 files)  | `terminate_process` |      0.237       |      0.386       |      0.395       |        271.3         |     1586.2      |
| Large (2,000 files) | `health`            |      0.134       |      0.236       |      0.255       |        6861.8        |      318.9      |
| Large (2,000 files) | `system_status`     |      0.286       |      0.533       |      0.657       |        3000.8        |      330.1      |
| Large (2,000 files) | `list_directory`    |      0.864       |      2.049       |      3.031       |        904.8         |     1734.1      |
| Large (2,000 files) | `read_file`         |      0.224       |      0.285       |      0.298       |        4243.9        |      536.6      |
| Large (2,000 files) | `search_files`      |      0.775       |      2.798       |      6.461       |        828.6         |    -12390.0     |
| Large (2,000 files) | `search_text`       |      3.298       |      3.788       |      4.166       |        300.0         |     4172.9      |
| Large (2,000 files) | `git_status`        |      36.859      |      58.165      |      80.162      |         24.9         |     3176.1      |
| Large (2,000 files) | `git_diff`          |      16.596      |      22.365      |      22.380      |         56.6         |     1296.9      |
| Large (2,000 files) | `git_log`           |      11.883      |      29.056      |      31.022      |         63.8         |     -9540.9     |
| Large (2,000 files) | `run_command`       |      9.492       |      14.086      |      14.320      |         94.9         |      785.9      |
| Large (2,000 files) | `process_status`    |      0.051       |      0.105       |      0.157       |       16762.5        |      349.2      |
| Large (2,000 files) | `process_output`    |      0.102       |      0.178       |      0.228       |        8883.7        |      379.9      |
| Large (2,000 files) | `terminate_process` |      0.241       |      0.336       |      0.351       |        312.8         |     1272.0      |

---

## 3. Methodology & Fixture Design

### Fixture Specifications

- **Small Workspace:** 10 files across 1 subdirectory, 5 git commits, 1 uncommitted change.
- **Medium Workspace:** 500 files evenly distributed across 10 subdirectories, 10 git commits, 1 uncommitted change.
- **Large Workspace:** 2,000 files evenly distributed across 40 subdirectories, 10 git commits, 1 uncommitted change.

### Execution Parameters

- Warmup iterations: 3 iterations per tool to stabilize JIT compilation.
- Measurement sample: 30 iterations (Small), 20 iterations (Medium), 15 iterations (Large).
- Metrics captured: High-resolution timer (`performance.now()`), V8 process memory delta.
- All requests passed through the full production pipeline:
  `dispatchToolCall -> Zod strict schema validation -> WorkspaceRegistry binding -> SecurityKernel evaluate -> ControlledProcessRunner / Subsystem sandbox -> SHA-256 AuditLogger chain -> Sanitized response`.

---

## 4. Performance Gates for Future Releases

Future release candidates (RC-03+) must adhere to the following performance regression thresholds:

- Control plane tools (`health`, `system_status`) must maintain p95 < 2.0 ms.
- Direct read tools (`read_file`, `list_directory` shallow) must maintain p95 < 5.0 ms.
- In-memory process status and output tools must maintain p95 < 5.0 ms.
- Short-lived execution tools (`run_command node --version`) must maintain p95 < 120.0 ms.
- Memory leak tolerance: Zero cumulative RSS growth over 10,000 consecutive invocations.
