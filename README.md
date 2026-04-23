# dep-timemachine

> Travel back through your dependency history — find exactly when a CVE entered your project.

[![CI](https://github.com/Aliipou/dep-timemachine/actions/workflows/ci.yml/badge.svg)](https://github.com/Aliipou/dep-timemachine/actions/workflows/ci.yml)
[![Python 3.11+](https://img.shields.io/badge/python-3.11%2B-blue)](https://python.org)
[![License: MIT](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)

**dep-timemachine** walks your git history commit-by-commit, parses every dependency manifest it finds, and cross-references each package against the [OSV.dev](https://osv.dev) vulnerability database. It tells you the exact commit — author, date, message — where a known CVE first entered your project.

## Features

- **Multi-ecosystem**: `requirements.txt`, `pyproject.toml`, `package.json`, `Cargo.toml`, `go.mod`, `Gemfile.lock`
- **Git-native**: reads blobs directly from git objects, no working-tree changes needed
- **OSV.dev powered**: queries the open-source vulnerability database used by GitHub Advisory
- **Fast**: concurrent async queries with configurable parallelism
- **Rich output**: beautiful terminal tables + JSON export for CI pipelines

## Installation

```bash
pip install dep-timemachine
```

Or from source:

```bash
git clone https://github.com/Aliipou/dep-timemachine
cd dep-timemachine
pip install -e ".[dev]"
```

## Usage

### Scan a repository's full history

```bash
dep-timemachine scan /path/to/your/repo
```

```bash
dep-timemachine scan . --max-commits 200 --output report.json
```

### Filter to a specific package

```bash
dep-timemachine scan . --package requests
```

### Check a single manifest (no git)

```bash
dep-timemachine check requirements.txt
dep-timemachine check package.json --output vulns.json
```

## Example Output

```
dep-timemachine v1.0.0
Scanning /home/user/myproject (up to 500 commits)

Found 3 CVE entry point(s)

╭─────────────────────┬──────────┬───────────────────┬────────────────┬────────────┬───────────────╮
│ CVE / ID            │ Severity │ Package           │ Introduced     │ Date       │ Author        │
├─────────────────────┼──────────┼───────────────────┼────────────────┼────────────┼───────────────┤
│ GHSA-j8r2-6x86-q33q │ HIGH     │ pypi:requests     │ a1b2c3d4e5f6   │ 2023-03-14 │ Jane Dev      │
│ CVE-2023-45803      │ MEDIUM   │ pypi:urllib3      │ f9e8d7c6b5a4   │ 2023-08-22 │ Bob Engineer  │
│ GHSA-v845-jxx5-vc9f │ HIGH     │ npm:axios         │ 12ab34cd56ef   │ 2024-01-10 │ Alice Coder   │
╰─────────────────────┴──────────┴───────────────────┴────────────────┴────────────┴───────────────╯
```

## How It Works

1. Opens the git repository and iterates commits (newest → oldest, reversed for display)
2. For each commit, extracts dependency manifest blobs from the git tree
3. Writes them to a temp directory and parses with ecosystem-aware parsers
4. Queries OSV.dev for all unique (ecosystem, package, version) tuples concurrently
5. Reports the first commit where each CVE-affected package version appeared

## CI Integration

```yaml
- name: Check dependencies for CVEs
  run: |
    pip install dep-timemachine
    dep-timemachine check requirements.txt --output cve-report.json

- name: Upload CVE report
  uses: actions/upload-artifact@v4
  with:
    name: cve-report
    path: cve-report.json
```

## License

MIT
