# Initial static analysis adapter

Run `cvefuzz static PATH --semgrep /absolute/path/to/semgrep --output .cvefuzz/static.json --html .cvefuzz/static.html`. Install a trusted Semgrep CE executable separately on a supported system; CVEFuzz does not install or bundle the analyzer. This adapter is contract-tested with mocked responses on Windows. Actual Semgrep execution and rule matching have not yet been validated in this workspace; WSL and Semgrep are unavailable here.

The first rules flag `eval(...)` in Python, JavaScript, and TypeScript. They are intentionally broad, low-confidence API-use warnings: constant expressions can match, aliases can be missed, and no input flow or exploitability is established. This is a small adapter increment, not a general security ruleset. No registry rules are downloaded. These original CVEFuzz rule definitions are dedicated to the public domain under [CC0-1.0](https://creativecommons.org/publicdomain/zero/1.0/). Semgrep CE is separately licensed under LGPL-2.1; registry rules have separate terms and are not redistributed here.

Source bytes are checked against inventory hashes and copied into the ignored scan artifact directory. Only supported source copies are given to Semgrep; repository configuration and ignore files are not copied. Inline `nosemgrep` suppressions are disabled. `--exclude DIRECTORY_NAME` uses the inventory directory-basename exclusions. Reasoned finding suppressions and custom rule configuration remain deferred. Source copies and raw scanner outputs may contain sensitive code; manage `.cvefuzz` artifacts accordingly.

The adapter sets local JSON rules, CE-only mode, metrics off, version checks off, one job, a 10-second per-rule/file timeout, a 512 MB engine memory setting, and a configurable whole CLI timeout (default 120 seconds, plus up to 15 seconds for version detection). It accepts at most 1000 source files, 1 MB per file, and 20 MB total. These are adapter/engine controls, not an OS sandbox: hard process-tree CPU, memory, and output-storage enforcement is not implemented. Captured output is not size-bounded. No repository source, dependency installers, or build scripts are executed.

Reports record engine version/license, rule ID/license/version, severity source, source range, confidence, and any returned data-flow trace. Findings retain `static-warning` evidence labels. Tool failure, timeout, malformed output, changed or oversized files, unsupported recognized source languages, and unconfirmed file coverage make the scan incomplete. Unknown file types remain visible in inventory without analysis. Exit codes are 0 for a completed check without warnings (or `--fail-on never`), 1 for warnings, and 2 for incomplete/error; `--fail-on never` does not hide errors. Dependency analysis and fuzzing remain skipped in a `static` run.

| Language | Inventory | Dependencies | Static adapter | Reachability/build/fuzzing |
| --- | --- | --- | --- | --- |
| Python | Yes | Plain pinned requirements | Initial eval rule; live validation pending | No |
| JavaScript/TypeScript | Yes | npm v2/v3 bounded provenance | Initial eval rule; live validation pending | No |
| C/C++, Go, Java, Rust | Yes | Explicitly unsupported | Explicitly unsupported | No |

To run the opt-in positive/negative rule test, set `CVEFUZZ_SEMGREP` to a trusted Semgrep executable and run `python -m unittest discover -s tests -v`. The fixture code is generated locally and never executed. Without the environment variable this one test is skipped; deterministic adapter tests still run.

Contracts checked against the [Semgrep CLI reference](https://docs.semgrep.dev/cli-reference), [rule testing guide](https://docs.semgrep.dev/writing-rules/testing-rules), and [Semgrep engine terms](https://semgrep.dev/legal/terms). Broader language/rule support and live acceptance are separate remaining work.
