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
