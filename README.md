# CVEFuzz

Local-first, multi-language security testing controller. The current foundation inventories repositories and stores versioned JSON results in SQLite. Security analysis, CVE matching, advisory updates, and fuzzing are planned but not implemented.

Requires Python 3.11 or newer. No runtime dependencies. From PowerShell:

For local development, `cvefuzz.cmd` can use a separately downloaded portable Python runtime under `.tools/python`. That runtime is not distributed with this repository and has no pip. Use a full Python installation for the instructions below.

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
