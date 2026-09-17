# CesSpace ARC — RC-01 Performance Baseline

- **Generated:** 2026-09-17T10:34:28.911Z
- **Environment:** Linux x86_64, Node.js v24.21.0, v8 Engine
- **Total Process Memory:** RSS 117.8 MB, Heap 22.9 MB
- **Status:** Measured RC-01 Baseline — Pending Independent Review

---

## 1. Executive Summary

This document establishes the official performance and latency baseline for the **CesSpace ARC RC-01 Read-Only MCP Core**.
All 9 permitted tools were benchmarked using the automated harness (`benchmarks/rc01-benchmark.js`) across synthetic fixtures spanning Small (10 files), Medium (500 files), and Large (2,000 files) workspaces.

### Key Observations

1. **Control Plane Operations (`health`, `system_status`):**
   - In-memory health checks execute with sub-millisecond median latency (p50: < 0.2 ms).
   - Host system status inspection samples host OS metrics and disk statistics; see measured p50/p95/p99 table below; results vary by fixture and tool.
2. **Filesystem Read Operations (`read_file`, `list_directory`):**
   - Read operations execute via direct file descriptors and non-recursive canonical path enclosure checks; see measured p50/p95/p99 table below; results vary by fixture and tool.
3. **Search Subsystem (`search_files`, `search_text`):**
   - In-memory traversal with ReDoS guards scales with workspace size and file count; see measured p50/p95/p99 table below; results vary by fixture and tool.
4. **Git Read-Only Operations (`git_status`, `git_diff`, `git_log`):**
   - Operations execute via sandboxed subprocess invocation using the trusted system Git binary with fixed isolation arguments and sanitized environment (`GIT_OPTIONAL_LOCKS=0`).
   - Execution time is dominated by subprocess invocation and repository topology verification; see measured p50/p95/p99 table below; results vary by fixture and tool.

---

## 2. Benchmark Results Table

| Fixture             | Tool             | p50 Latency (ms) | p95 Latency (ms) | p99 Latency (ms) | Throughput (ops/sec) | Heap Delta (KB) |
| :------------------ | :--------------- | :--------------: | :--------------: | :--------------: | :------------------: | :-------------: |
| Small (10 files)    | `health`         |      0.121       |      0.270       |      0.312       |        6681.5        |     1109.7      |
| Small (10 files)    | `system_status`  |      0.324       |      2.410       |      5.813       |        1343.4        |     -5087.3     |
| Small (10 files)    | `list_directory` |      0.370       |      0.598       |      0.720       |        2497.8        |     2525.7      |
| Small (10 files)    | `read_file`      |      0.297       |      2.384       |      2.587       |        2095.3        |     1943.8      |
| Small (10 files)    | `search_files`   |      0.639       |      3.494       |      7.021       |        680.3         |     -3830.3     |
| Small (10 files)    | `search_text`    |      1.431       |      7.023       |      17.463      |        368.9         |     -1625.1     |
| Small (10 files)    | `git_status`     |      32.049      |      39.389      |      41.934      |         31.9         |      966.3      |
| Small (10 files)    | `git_diff`       |      8.748       |      13.386      |      14.055      |        106.9         |     4730.8      |
| Small (10 files)    | `git_log`        |      12.727      |      15.496      |      19.932      |         84.0         |     -5405.5     |
| Medium (500 files)  | `health`         |      0.087       |      0.155       |      0.370       |        9229.7        |      613.1      |
| Medium (500 files)  | `system_status`  |      0.326       |      0.432       |      0.447       |        2979.1        |      664.7      |
| Medium (500 files)  | `list_directory` |      0.698       |      3.809       |      4.296       |        791.5         |     2210.0      |
| Medium (500 files)  | `read_file`      |      0.336       |      0.473       |      0.546       |        2978.2        |     1069.0      |
| Medium (500 files)  | `search_files`   |      0.935       |      1.193       |      1.571       |        1076.3        |     4831.7      |
| Medium (500 files)  | `search_text`    |      2.325       |      4.296       |      6.545       |        383.2         |     -5855.7     |
| Medium (500 files)  | `git_status`     |      40.003      |      49.895      |      71.219      |         24.2         |     6334.6      |
| Medium (500 files)  | `git_diff`       |      15.880      |      42.071      |      43.367      |         49.4         |     2538.9      |
| Medium (500 files)  | `git_log`        |      9.749       |      14.292      |      15.683      |         98.1         |     2798.1      |
| Large (2,000 files) | `health`         |      0.090       |      0.687       |      1.932       |        4383.5        |      407.4      |
| Large (2,000 files) | `system_status`  |      0.368       |      2.560       |      2.576       |        1141.2        |      432.7      |
| Large (2,000 files) | `list_directory` |      0.613       |      1.388       |      1.400       |        1344.2        |     2263.2      |
| Large (2,000 files) | `read_file`      |      0.220       |      0.380       |      0.455       |        3953.5        |      704.2      |
| Large (2,000 files) | `search_files`   |      0.744       |      0.827       |      1.058       |        1320.1        |     2849.6      |
| Large (2,000 files) | `search_text`    |      7.505       |      10.937      |      15.805      |        133.5         |     -8884.3     |
| Large (2,000 files) | `git_status`     |      32.183      |      38.975      |      39.051      |         29.6         |     3899.3      |
| Large (2,000 files) | `git_diff`       |      18.136      |      39.251      |      44.116      |         41.9         |     1674.8      |
| Large (2,000 files) | `git_log`        |      9.857       |      16.047      |      16.263      |         90.4         |     -9022.2     |

---

## 3. Methodology & Fixture Design

### Fixture Specifications

- **Small Workspace:** 10 files across 1 subdirectory, 5 git commits, 1 uncommitted change.
- **Medium Workspace:** 500 files evenly distributed across 10 subdirectories, 10 git commits, 1 uncommitted change.
- **Large Workspace:** 2,000 files evenly distributed across 40 subdirectories, 10 git commits, 1 uncommitted change.

### Execution Parameters

- Warmup iterations: 3 iterations per tool to stabilize JIT compilation.
- Measurement sample: 50 iterations (Small), 30 iterations (Medium), 20 iterations (Large).
- Metrics captured: High-resolution timer (`performance.now()`), V8 process memory delta.
- All requests passed through the full production pipeline:
  `dispatchToolCall -> Zod strict schema validation -> WorkspaceRegistry binding -> SecurityKernel evaluate -> Subsystem sandbox -> SHA-256 AuditLogger chain -> Sanitized response`.

### Methodology Note

The benchmark harness calls `dispatchToolCall` directly in-process to measure the ARC dispatch, strict Zod schema validation, WorkspaceRegistry binding, SecurityKernel evaluation, subsystem sandboxing, SHA-256 AuditLogger chain, and response sanitization pipeline. It measures the internal ARC control and security pipeline directly, not stdio JSON-RPC transport latency or external process IPC overhead. Comparative claims against third-party servers require dedicated comparative benchmarks and are not asserted here.

---

## 4. Performance Gates for Future Releases

Future release candidates (RC-02+) must adhere to the following performance regression thresholds:

- Control plane tools (`health`, `system_status`) must maintain p95 < 2.0 ms.
- Direct read tools (`read_file`, `list_directory` shallow) must maintain p95 < 5.0 ms.
- Git read operations must maintain p95 < 50.0 ms.
- Memory leak tolerance: Zero cumulative RSS growth over 10,000 consecutive invocations.
