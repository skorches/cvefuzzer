# CVEFuzz

Local-first, multi-language security testing controller. Inventories repositories, checks selected dependency files with OSV-Scanner v2, and stores versioned results in SQLite with JSON/HTML reports. Scheduled advisory updates, static analysis, and fuzzing are not implemented yet.

Requires Python 3.11 or newer. No runtime dependencies. From PowerShell:

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

The adapter invokes only explicit lockfiles, overrides repository scanner configuration, disables dependency resolution and Go/Rust call analysis, and does not install dependencies or run repository build scripts. It queries advisory services through OSV-Scanner: package names and versions leave the machine. Requirements includes and unsupported requirement forms are delegated to OSV-Scanner; use self-contained pinned inputs. Local-source npm packages are marked as a coverage gap.

Advisory IDs and aliases are deduplicated per package and manifest. Reports retain affected ranges, fixed-version events, severity evidence, raw scanner JSON, and diagnostic logs. They do not infer an upgrade across version branches or establish exploitability. Freshness is recorded as queried by the scanner, not as a verified complete advisory mirror. Automatic scheduled refresh is deferred to the next milestone.

Exit codes for `scan`: **0** means the selected dependency checks completed without findings (or `--fail-on never` was selected); **1** means dependency findings; **2** means an incomplete scan or operational failure. `--fail-on never` never hides operational failures. A missing scanner, timeout, malformed response, unsupported manifest, unresolved version, or missing supported input cannot produce a clean scan. Static analysis and fuzzing remain explicitly skipped. `--timeout` limits each lockfile scan; `--exclude` accepts directory basenames.

Tests are deterministic and mock advisory/tool responses. The deliberately old fixture dependencies are for scanning only; do not install them.
