# CesSpace ARC — RC-02 Performance Baseline

- **Generated:** 2026-09-17T16:41:14.519Z
- **Environment:** Linux x86_64, Node.js v24.21.0, v8 Engine
- **Total Process Memory:** RSS 119.2 MB, Heap 32.9 MB
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

| Fixture | Tool | p50 Latency (ms) | p95 Latency (ms) | p99 Latency (ms) | Throughput (ops/sec) | Heap Delta (KB) |
| :--- | :--- | :---: | :---: | :---: | :---: | :---: |
| Small (10 files) | `health` | 0.142 | 0.655 | 5.359 | 2317.7 | -5116.7 |
| Small (10 files) | `system_status` | 0.298 | 0.459 | 0.907 | 2967.8 | 673.0 |
| Small (10 files) | `list_directory` | 0.402 | 0.916 | 1.221 | 2082.8 | 1541.6 |
| Small (10 files) | `read_file` | 0.359 | 0.823 | 1.163 | 2324.1 | 1216.5 |
| Small (10 files) | `search_files` | 0.494 | 0.868 | 1.794 | 1697.3 | 2422.1 |
| Small (10 files) | `search_text` | 3.057 | 5.111 | 6.294 | 364.3 | -4297.8 |
| Small (10 files) | `git_status` | 30.779 | 37.887 | 39.374 | 33.7 | 1673.3 |
| Small (10 files) | `git_diff` | 8.581 | 12.510 | 13.319 | 108.7 | 2928.6 |
| Small (10 files) | `git_log` | 9.066 | 14.366 | 18.723 | 99.3 | -1803.4 |
| Small (10 files) | `run_command` | 12.275 | 14.320 | 14.552 | 87.0 | 3675.8 |
| Small (10 files) | `process_status` | 0.108 | 0.209 | 0.222 | 8318.9 | 719.0 |
| Small (10 files) | `process_output` | 0.154 | 0.253 | 0.308 | 6381.9 | 806.5 |
| Small (10 files) | `terminate_process` | 0.641 | 1.424 | 2.073 | 229.3 | 4934.0 |
| Medium (500 files) | `health` | 0.119 | 0.167 | 0.170 | 8078.5 | 415.8 |
| Medium (500 files) | `system_status` | 0.437 | 0.798 | 0.829 | 2068.9 | 441.9 |
| Medium (500 files) | `list_directory` | 0.796 | 2.400 | 2.550 | 939.8 | 1526.8 |
| Medium (500 files) | `read_file` | 0.290 | 1.558 | 2.758 | 2025.8 | 765.1 |
| Medium (500 files) | `search_files` | 1.033 | 2.942 | 3.133 | 764.8 | 3943.3 |
| Medium (500 files) | `search_text` | 3.601 | 6.300 | 8.022 | 250.9 | 6060.4 |
| Medium (500 files) | `git_status` | 29.844 | 74.992 | 76.912 | 28.7 | 4667.0 |
| Medium (500 files) | `git_diff` | 13.531 | 18.663 | 19.934 | 73.4 | 1894.7 |
| Medium (500 files) | `git_log` | 13.586 | 17.615 | 24.898 | 73.8 | 2101.9 |
| Medium (500 files) | `run_command` | 9.723 | 15.337 | 16.180 | 96.7 | 2277.5 |
| Medium (500 files) | `process_status` | 0.047 | 0.145 | 0.157 | 15797.7 | 467.3 |
| Medium (500 files) | `process_output` | 0.112 | 0.205 | 0.297 | 7685.7 | 515.9 |
| Medium (500 files) | `terminate_process` | 0.423 | 0.928 | 4.054 | 262.5 | -11351.5 |
| Large (2,000 files) | `health` | 0.074 | 0.223 | 0.249 | 9474.7 | 316.5 |
| Large (2,000 files) | `system_status` | 0.326 | 1.744 | 2.293 | 1769.2 | 352.7 |
| Large (2,000 files) | `list_directory` | 0.859 | 1.700 | 2.783 | 1019.7 | 1754.6 |
| Large (2,000 files) | `read_file` | 0.351 | 0.517 | 0.538 | 2785.3 | 534.9 |
| Large (2,000 files) | `search_files` | 0.977 | 2.272 | 3.343 | 820.9 | 2165.2 |
| Large (2,000 files) | `search_text` | 2.238 | 2.712 | 2.789 | 429.0 | 4184.7 |
| Large (2,000 files) | `git_status` | 34.366 | 74.720 | 81.151 | 25.0 | 3163.1 |
| Large (2,000 files) | `git_diff` | 16.780 | 22.477 | 24.007 | 55.7 | 1291.6 |
| Large (2,000 files) | `git_log` | 19.608 | 27.522 | 28.544 | 53.6 | 1416.6 |
| Large (2,000 files) | `run_command` | 9.704 | 13.463 | 14.701 | 97.7 | 1660.7 |
| Large (2,000 files) | `process_status` | 0.044 | 0.122 | 0.132 | 17531.5 | 352.4 |
| Large (2,000 files) | `process_output` | 0.100 | 0.147 | 0.202 | 10273.3 | 380.4 |
| Large (2,000 files) | `terminate_process` | 0.367 | 0.558 | 0.637 | 271.5 | 2498.0 |

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
