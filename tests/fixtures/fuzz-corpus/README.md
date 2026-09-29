# RC-08 deterministic fuzz corpus

Unexpected property failures are written in bounded, sanitized JSON form beneath
`failures/`. Passing runs create no artifacts. Files in that directory record
only the control name, seed, fast-check path, a bounded counterexample summary,
and the exact reproduction command.
