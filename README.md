# misra-ci

`misra-ci` is an open-source MISRA C:2012-inspired CI toolchain for scanning C/C++ projects, detecting unsafe patterns, generating compliance-oriented reports, and enforcing severity gates in CI pipelines.

The project is designed for developer workflows where early detection, audit evidence, and CI enforcement are important.

## What it does

`misra-ci` can:

- scan C/C++ source files recursively
- load heuristic rules from a YAML ruleset
- detect MISRA-like unsafe coding patterns
- generate multiple report formats
- enforce severity gates for CI pass/fail behavior
- run through direct CLI flags or a `misra-ci.toml` config file

## Report outputs

The tool generates the following reports:

```text
report.html        Human-readable report with summary and findings
report.json        Machine-readable report for dashboards and automation
report.junit.xml   CI test report format
report.sarif.json  SARIF report for code scanning integrations
```

## Problem it solves

Many C/C++ projects need early detection of unsafe coding patterns before code reaches production. Manual review is slow, and full compliance tooling can be difficult to integrate into lightweight CI workflows.

`misra-ci` provides a lightweight, open-source CI-first scanner that helps teams detect MISRA C:2012-inspired rule violations, generate audit-friendly reports, and fail builds based on severity thresholds.

## Use cases

- CI quality gates for embedded C/C++ projects
- early detection of unsafe C/C++ coding patterns
- compliance-oriented evidence generation
- developer feedback before formal review
- SARIF integration for code scanning workflows

## Example usage

Scan a project directly:

```bash
misra-ci --path ./src --rules rules/misra-c2012.yml --fail-on high
```

Run using a configuration file:

```bash
misra-ci --config misra-ci.toml
```

## Example configuration

```toml
path = "./src"
rules = "rules/misra-c2012.yml"
fail_on = "high"

[reports]
html = "report.html"
json = "report.json"
junit = "report.junit.xml"
sarif = "report.sarif.json"
```

## CI behavior

`misra-ci` can be used as a CI quality gate. When findings meet or exceed the configured severity threshold, the tool exits with a failing status code so the pipeline can block unsafe changes before merge or release.

Example:

```bash
misra-ci --path ./src --rules rules/misra-c2012.yml --fail-on high
```

If high-severity findings are detected, the CI job should fail.

## Status

`misra-ci` is currently an open-source developer tool focused on heuristic MISRA C:2012-inspired scanning and CI reporting.

It is not a certified MISRA compliance product. It is intended to support early detection, developer feedback, and audit-oriented engineering workflows.

## License

This project is licensed under the terms of the repository license.
