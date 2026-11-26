# CVEFuzz

Local-first, multi-language security testing controller. Inventories repositories, checks selected dependency files with OSV-Scanner v2, rechecks saved projects against OSV on demand or through an operating-system scheduler, and stores versioned results in SQLite with JSON/HTML reports. An initial local Semgrep adapter supports static warnings; live engine validation is outstanding. Fuzzing is not implemented yet.

Requires Python 3.11 or newer. No runtime dependencies. From PowerShell:

For the initial Semgrep `static` command, capability matrix, rule licenses, resource limits, and current validation gaps, see [static analysis](docs/static-analysis.md).

For local development, `cvefuzz.cmd` can use a separately downloaded portable Python runtime under `.tools/python`. That runtime is not distributed with this repository. Use a full Python installation for the instructions below.

```powershell
python -m venv .venv
.venv\Scripts\python -m pip install -e .
.venv\Scripts\cvefuzz inventory tests/fixtures/mixed --output .cvefuzz/inventory.json
.venv\Scripts\cvefuzz capabilities
```

Source-only use without installation:

```powershell
$env:PYTHONPATH = 'src'
python -m cvefuzz inventory tests/fixtures/mixed --output .cvefuzz/inventory.json
python -m unittest discover -s tests -v
```

On Linux use `python3` and `.venv/bin/` equivalents. Docker is not needed for inventory. Linux Docker build and fuzzing runners are deferred to Milestone 4; no active runner currently exists.

Inventory never executes source code or build scripts. It recognizes Python, JavaScript, TypeScript, C, C++, Go, Java, and Rust through filenames and extensions; manifest contents and dependency versions are not parsed yet. Unknown files remain visible. Standard generated/dependency directories and symbolic links are skipped. Repeat `--exclude DIRECTORY_NAME` to exclude additional directory basenames.

Content identity hashes included paths and their bytes in deterministic traversal order. It represents the inventoried subset, not an atomic filesystem snapshot or Git revision. Avoid editing files during inventory. Put output and database files in the excluded `.cvefuzz` directory when scanning the project itself.

`inventory` exit code 0 means inventory completed, **not** that the code is safe. Code 2 indicates an operational error or incomplete inventory. Reports mark security checks skipped and advisory data not fetched. The default database is `.cvefuzz/scans.sqlite3` relative to the current directory; override it using `--database`.

Development and testing take place locally. The implementation plan, downloaded runtimes, virtual environments, build outputs, and scan results are excluded from version control. GitHub stores the source and tests; no hosted build or deployment workflow is configured.

## Dependency vulnerability scanning

Install a trusted [OSV-Scanner v2 binary](https://google.github.io/osv-scanner/installation/) separately, then run:

```powershell
cvefuzz scan path/to/project --osv-scanner path/to/osv-scanner.exe --output .cvefuzz/report.json --html .cvefuzz/report.html
```

In this workspace the verified Windows v2.7.0 binary is available locally:

```powershell
.\cvefuzz.cmd scan tests/fixtures/dependencies/vulnerable --osv-scanner .tools/osv-scanner.exe --output .cvefuzz/report.json --html .cvefuzz/report.html
```

On Linux use the installed `cvefuzz` command and a Linux OSV-Scanner binary. Windows execution is validated; Linux execution remains untested.

The initial supported inputs are **requirements.txt with exact pinned versions** and **package-lock.json v2/v3**. JavaScript and TypeScript projects share npm lockfiles. Other recognized manifests are reported as unsupported or unresolved. Python inputs must enumerate transitive dependencies if those dependencies are to be checked. Unknown/unclassified files are listed in inventory and are not security-scanned.

For npm v2/v3 package maps, `dependency_path` records one deterministic shortest declared chain per package name and exact version, for example `["parser@1.0.0", "helper@2.0.0"]`. Paths start at a root dependency, omit the project itself, and follow declared production, development (root only), optional, and peer dependencies through nested or hoisted package locations. This is dependency provenance, not runtime reachability; alternate paths and install locations are not enumerated. Workspace links, npm aliases, missing required edges, unsupported lockfile versions, malformed package maps, and scanner packages without a matching path make coverage incomplete while preserving scanner findings. Absent optional dependencies are allowed. Python paths remain empty because pinned requirements alone do not establish dependency chains; `manifest` retains their source-file provenance. The package-map format follows the [npm lockfile documentation](https://github.com/npm/cli/blob/latest/docs/lib/content/configuring-npm/package-lock-json.md).

The adapter invokes only explicit lockfiles, overrides repository scanner configuration, disables dependency resolution and Go/Rust call analysis, and does not install dependencies or run repository build scripts. It queries advisory services through OSV-Scanner: package names and versions leave the machine. Local-source npm packages are marked as a coverage gap.

Requirements inputs support plain `name==version` lines, blank lines, full-line comments, whitespace-separated inline comments, and UTF-8 (including a BOM). Includes/constraints, editable or local dependencies, URLs/VCS references, ranges, wildcard pins, extras, markers, environment substitutions, hashes, continuations, and pip options are outside this initial contract. If any unsupported line is present, the entire requirements input is skipped before it is sent to OSV-Scanner; other supported inputs can still run, but the overall scan is incomplete (exit 2). Empty/comment-only inputs are also incomplete. This deliberately narrow subset is not a replacement for the full [pip requirements format](https://pip.pypa.io/en/stable/reference/requirements-file-format/).

Advisory IDs and aliases are deduplicated per package and manifest. Reports retain affected ranges, fixed-version events, severity evidence, raw scanner JSON, and diagnostic logs. They do not infer an upgrade across version branches or establish exploitability. Scan freshness is recorded as queried by the scanner, not as a verified complete advisory mirror. Use the on-demand refresh command below to query saved inventories again.

Exit codes for `scan`: **0** means the selected dependency checks completed without findings (or `--fail-on never` was selected); **1** means dependency findings; **2** means an incomplete scan or operational failure. `--fail-on never` never hides operational failures. A missing scanner, timeout, malformed response, unsupported manifest, unresolved version, or missing supported input cannot produce a clean scan. Static analysis and fuzzing remain explicitly skipped. `--timeout` limits each lockfile scan; `--exclude` accepts directory basenames.

Tests are deterministic and mock advisory/tool responses. The deliberately old fixture dependencies are for scanning only; do not install them.

## Refreshing saved dependency inventories

Use `scan_id` from a saved `scan` JSON report and the same database:

```powershell
cvefuzz refresh SCAN_ID --database .cvefuzz/scans.sqlite3 --output .cvefuzz/refresh.json --html .cvefuzz/refresh.html
cvefuzz history SCAN_ID --database .cvefuzz/scans.sqlite3
```

For the local portable runtime, replace `cvefuzz` with `.\cvefuzz.cmd`. Refresh works even if the original repository has moved or is unavailable: it uses only the saved PyPI/npm names, exact versions, manifests, and dependency paths. Inventory-only results have no dependency inventory to refresh. Files, dependencies, and repository scripts are not executed or changed. New dependencies require another `scan`.

The updater uses OSV's [package/version query API](https://google.github.io/osv.dev/post-v1-query/), including pagination, and [advisory lookup API](https://google.github.io/osv.dev/get-v1-vulns/) to check whether previously matched records were withdrawn. Package identities and versions are sent to OSV. No OSV-Scanner binary is needed for refresh; OSV handles affected-version matching. Provider identity, request configuration, fetched time, successful-refresh time, raw advisory records, and outcomes are saved locally. A successful query does not verify completeness or publication latency of the upstream advisory database.

Reports compare each successful refresh with the previous successful refresh (or the original scan on the first refresh). `changes` contains new, changed, withdrawn, and resolved alias groups, plus an unchanged count. Alias merges and splits count as changes when an identifier connects the old and new records. A fully withdrawn group requires explicit withdrawal evidence for all its previously active records. A resolved group means OSV no longer returns it for the saved version; it does **not** mean the dependency was upgraded or the project was repaired. First-refresh differences can include additional evidence returned by the API. Original scans and all refresh attempts remain available through `history`.

The updater commits the entire successful snapshot and history in one SQLite transaction. A failed package query, failed withdrawal lookup, invalid response, interrupted process, or cache-write failure retains the previous usable cache. Reports from unsuccessful attempts retain the previous findings and make no reconciliation claims. Competing refreshes cannot overwrite a cache updated since they started. Database schema v1 migrates automatically to v2 without changing saved scans; older CVEFuzz versions cannot open a v2 database.

`--timeout 30` sets the time budget per package query or advisory lookup, shared across its pages and retries; it is not a whole-refresh limit. The client checks deadlines between response reads and uses the remaining budget as the socket timeout. `--retries 2` retries transient network failures and HTTP 408/429/500/502/503/504 with backoff, honoring `Retry-After` when it fits the remaining budget. Each response is limited to 32 MiB and each package to 100 pages. A very large saved inventory can take many per-package budgets.

`--offline` shows retained findings with explicit stale/unavailable freshness and performs no network requests. It exits **2** because advisory changes were not checked. Online exit codes follow `scan`: **1** for current findings, **0** for a completed query without findings (or `--fail-on never`), and **2** for operational failure or incomplete original coverage. Refreshing a partial scan cannot make its coverage complete. Cross-inventory dependency comparisons remain pending.

## Refreshing and tracking multiple projects

Save dependency scans from multiple repositories in the same database, then use:

```powershell
cvefuzz refresh --all --database .cvefuzz/scans.sqlite3 --output .cvefuzz/batch.json --html .cvefuzz/batch.html
cvefuzz projects --database .cvefuzz/scans.sqlite3 --output .cvefuzz/projects.json --html .cvefuzz/projects.html
cvefuzz projects --newly-affected --since 2026-11-23T00:00:00Z --database .cvefuzz/scans.sqlite3
```

`--all` selects the latest **saved dependency attempt** for each repository root, in database save order. Inventory-only records do not replace dependency inventories. A failed latest scan is reported; an older successful inventory is never substituted. Roots use the current host's path case rules and are not opened. Moved repositories are separate projects until scanned at their new locations. Inventory-only projects are absent from this dependency-project list.

Batch results report each project's outcome and finding/change counts. Failures do not stop other projects. Each project's cache remains atomic independently; an interrupted batch retains already completed project updates. Empty batches, blocked projects, provider/storage failures, offline batches, and incomplete original coverage exit **2**. Otherwise the finding exit policy also considers retained findings on skipped projects. Full provider records and finding history remain available using `history SCAN_ID`.

`projects` lists advisory freshness, original coverage, and new finding events still present in the latest successful cache. New events survive unchanged refreshes; resolved/withdrawn findings and superseded scan inventories leave the current list. A project with existing findings can appear when an additional advisory group is detected. `--since` filters the event time inclusively and requires a timezone. An empty filtered list is not a safety conclusion. Listing exits **0** when the catalog was read successfully, even if project entries show stale, unavailable, or incomplete coverage.

`--max-age-hours 24` controls freshness in project listings. An old cache, a failed/offline latest attempt, or an invalid/future success time is stale; a project without a successful refresh is unavailable. Findings from stale caches remain visible with their freshness. This is query age, not proof of upstream feed completeness.

For periodic runs, `refresh --all --min-age-hours 24` skips a project only when its last successful refresh is recent enough and its latest attempt succeeded. Due, failed, unavailable, or future-dated results are queried again. Zero (the default) forces every selected inventory to refresh. Offline batches ignore the interval gate. Skips create no refresh-history entries. The interval applies to advisory queries and cannot complete a partial original inventory.

See [local scheduling recipes](docs/advisory-refresh.md) for Windows Task Scheduler and Linux systemd timers, including overlap controls, runtime limits, exit handling, and removal commands. Scheduling is configured explicitly by the operator; no task is installed by the CLI.
