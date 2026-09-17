# CesSpace ARC — RC-02 Performance Baseline

- **Generated:** 2026-09-17T15:12:46.784Z
- **Environment:** Linux x86_64, Node.js v24.21.0, v8 Engine
- **Total Process Memory:** RSS 118.2 MB, Heap 32.6 MB
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
| Small (10 files)    | `health`            |      0.124       |      0.388       |      10.290      |        1584.6        |     -5249.1     |
| Small (10 files)    | `system_status`     |      0.363       |      4.550       |      4.761       |        896.2         |      673.6      |
| Small (10 files)    | `list_directory`    |      0.480       |      1.706       |      2.076       |        1659.0        |     1548.3      |
| Small (10 files)    | `read_file`         |      0.600       |      1.042       |      1.669       |        1470.2        |     1216.9      |
| Small (10 files)    | `search_files`      |      0.533       |      0.883       |      1.224       |        1736.6        |     2422.7      |
| Small (10 files)    | `search_text`       |      1.079       |      1.903       |      2.555       |        894.7         |     -3828.4     |
| Small (10 files)    | `git_status`        |      31.136      |      42.568      |      45.476      |         32.7         |     1708.8      |
| Small (10 files)    | `git_diff`          |      8.796       |      14.895      |      16.599      |        101.3         |     2931.6      |
| Small (10 files)    | `git_log`           |      8.098       |      12.879      |      15.334      |        111.1         |     -1812.8     |
| Small (10 files)    | `run_command`       |      12.869      |      14.111      |      15.702      |         80.8         |     3561.2      |
| Small (10 files)    | `process_status`    |      0.093       |      0.480       |      1.514       |        4962.9        |      733.7      |
| Small (10 files)    | `process_output`    |      0.129       |      0.456       |      1.758       |        4352.1        |      806.4      |
| Small (10 files)    | `terminate_process` |      0.642       |      2.448       |      3.847       |        173.3         |     4819.4      |
| Medium (500 files)  | `health`            |      0.085       |      0.112       |      0.121       |       11459.2        |      415.1      |
| Medium (500 files)  | `system_status`     |      0.372       |      1.211       |      1.296       |        2067.6        |      441.7      |
| Medium (500 files)  | `list_directory`    |      0.718       |      1.250       |      1.398       |        1302.5        |     1527.5      |
| Medium (500 files)  | `read_file`         |      0.356       |      1.394       |      12.108      |        928.4         |    -13925.1     |
| Medium (500 files)  | `search_files`      |      1.311       |      3.982       |      5.395       |        468.0         |     3911.3      |
| Medium (500 files)  | `search_text`       |      2.585       |      4.101       |      4.281       |        347.8         |     6012.9      |
| Medium (500 files)  | `git_status`        |      41.063      |      50.306      |      56.423      |         24.3         |     4666.1      |
| Medium (500 files)  | `git_diff`          |      15.092      |      21.813      |      23.065      |         61.9         |     1916.4      |
| Medium (500 files)  | `git_log`           |      9.186       |      13.260      |      14.188      |        101.2         |     2070.3      |
| Medium (500 files)  | `run_command`       |      9.407       |      15.039      |      16.139      |         97.0         |     2211.1      |
| Medium (500 files)  | `process_status`    |      0.067       |      0.175       |      0.467       |       10123.6        |      467.3      |
| Medium (500 files)  | `process_output`    |      0.092       |      0.359       |      1.719       |        4641.0        |      519.3      |
| Medium (500 files)  | `terminate_process` |      0.451       |      5.632       |      10.437      |        127.0         |    -11434.9     |
| Large (2,000 files) | `health`            |      0.066       |      0.722       |      1.569       |        5025.7        |     -130.6      |
| Large (2,000 files) | `system_status`     |      0.325       |      3.021       |      4.157       |        1141.9        |      345.1      |
| Large (2,000 files) | `list_directory`    |      0.747       |      4.500       |      4.794       |        719.3         |     1749.7      |
| Large (2,000 files) | `read_file`         |      0.217       |      0.258       |      0.265       |        4471.5        |      534.9      |
| Large (2,000 files) | `search_files`      |      0.723       |      0.795       |      0.799       |        1360.1        |     2165.2      |
| Large (2,000 files) | `search_text`       |      3.016       |      4.048       |      4.946       |        315.4         |     4184.0      |
| Large (2,000 files) | `git_status`        |      32.960      |      39.597      |      40.044      |         29.3         |     3158.6      |
| Large (2,000 files) | `git_diff`          |      15.702      |      22.833      |      27.922      |         57.3         |     1293.8      |
| Large (2,000 files) | `git_log`           |      14.061      |      26.591      |      27.563      |         59.8         |     1425.1      |
| Large (2,000 files) | `run_command`       |      10.136      |      13.872      |      14.500      |         92.0         |     1617.7      |
| Large (2,000 files) | `process_status`    |      0.042       |      0.085       |      0.106       |       19576.3        |      352.8      |
| Large (2,000 files) | `process_output`    |      0.085       |      0.166       |      0.223       |       10189.0        |      380.7      |
| Large (2,000 files) | `terminate_process` |      0.397       |      0.426       |      0.430       |        286.4         |     2461.5      |

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
