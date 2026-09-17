# CesSpace ARC — RC-02 Performance Baseline

- **Generated:** 2026-09-17T14:19:04.113Z
- **Environment:** Linux x86_64, Node.js v24.21.0, v8 Engine
- **Total Process Memory:** RSS 122.1 MB, Heap 32.5 MB
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
| Small (10 files)    | `health`            |      0.093       |      0.286       |      0.310       |        7771.8        |      703.9      |
| Small (10 files)    | `system_status`     |      0.353       |      0.538       |      0.589       |        2701.8        |      670.4      |
| Small (10 files)    | `list_directory`    |      0.464       |      0.675       |      0.710       |        2049.7        |     1578.2      |
| Small (10 files)    | `read_file`         |      0.437       |      2.548       |      3.254       |        1245.4        |     1214.0      |
| Small (10 files)    | `search_files`      |      0.554       |      2.669       |      2.830       |        923.8         |     2419.8      |
| Small (10 files)    | `search_text`       |      3.198       |      9.376       |      13.463      |        251.5         |     -4342.2     |
| Small (10 files)    | `git_status`        |      24.248      |      33.039      |      36.482      |         39.5         |     1621.5      |
| Small (10 files)    | `git_diff`          |      8.059       |      12.304      |      13.910      |        113.7         |     2940.8      |
| Small (10 files)    | `git_log`           |      8.088       |      12.712      |      14.967      |        112.5         |     -1882.0     |
| Small (10 files)    | `run_command`       |      12.804      |      14.388      |      15.938      |         77.4         |     -1834.1     |
| Small (10 files)    | `process_status`    |      0.101       |      0.191       |      0.349       |        8169.5        |     1403.6      |
| Small (10 files)    | `process_output`    |      0.113       |      0.848       |      2.174       |        4075.3        |      74.3       |
| Small (10 files)    | `terminate_process` |      0.450       |      1.589       |      3.677       |        222.5         |     4710.8      |
| Medium (500 files)  | `health`            |      0.085       |      0.220       |      0.225       |        9320.8        |      412.9      |
| Medium (500 files)  | `system_status`     |      0.377       |      0.492       |      0.498       |        2667.8        |      439.3      |
| Medium (500 files)  | `list_directory`    |      0.551       |      1.677       |      1.922       |        1443.6        |     1528.3      |
| Medium (500 files)  | `read_file`         |      0.279       |      0.492       |      0.504       |        3202.2        |      761.6      |
| Medium (500 files)  | `search_files`      |      1.147       |      4.090       |      5.534       |        557.9         |     4012.7      |
| Medium (500 files)  | `search_text`       |      4.128       |      7.138       |      7.872       |        222.5         |     6008.1      |
| Medium (500 files)  | `git_status`        |      30.040      |      37.966      |      42.067      |         32.6         |     4656.9      |
| Medium (500 files)  | `git_diff`          |      15.833      |      29.654      |      31.030      |         54.0         |     1914.2      |
| Medium (500 files)  | `git_log`           |      13.203      |      16.707      |      18.881      |         76.5         |     2098.5      |
| Medium (500 files)  | `run_command`       |      9.361       |      13.343      |      14.565      |        103.3         |     2124.0      |
| Medium (500 files)  | `process_status`    |      0.065       |      0.084       |      0.107       |       14727.6        |      461.8      |
| Medium (500 files)  | `process_output`    |      0.072       |      0.174       |      0.247       |        9972.2        |      501.5      |
| Medium (500 files)  | `terminate_process` |      0.420       |      0.521       |      1.124       |        268.1         |    -11448.3     |
| Large (2,000 files) | `health`            |      0.062       |      0.219       |      0.235       |       11282.5        |      314.9      |
| Large (2,000 files) | `system_status`     |      0.288       |      0.376       |      0.377       |        3288.5        |      326.8      |
| Large (2,000 files) | `list_directory`    |      0.697       |      1.015       |      1.275       |        1329.6        |     1736.2      |
| Large (2,000 files) | `read_file`         |      0.290       |      0.397       |      0.403       |        3266.6        |      533.7      |
| Large (2,000 files) | `search_files`      |      0.813       |      1.064       |      1.109       |        1152.0        |     2189.6      |
| Large (2,000 files) | `search_text`       |      3.250       |      4.563       |      5.140       |        302.4         |     4179.3      |
| Large (2,000 files) | `git_status`        |      37.763      |      66.232      |      79.664      |         24.1         |     3160.4      |
| Large (2,000 files) | `git_diff`          |      18.315      |      36.817      |      39.999      |         46.2         |     1292.5      |
| Large (2,000 files) | `git_log`           |      9.504       |      14.960      |      15.938      |         97.6         |     1436.5      |
| Large (2,000 files) | `run_command`       |      10.116      |      15.991      |      16.572      |         85.3         |     1575.6      |
| Large (2,000 files) | `process_status`    |      0.044       |      0.108       |      0.128       |       18442.6        |      289.9      |
| Large (2,000 files) | `process_output`    |      0.076       |      0.121       |      0.169       |       12505.0        |      369.7      |
| Large (2,000 files) | `terminate_process` |      0.414       |      0.576       |      0.592       |        230.8         |     2372.8      |

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
