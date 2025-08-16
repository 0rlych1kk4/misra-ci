# Integrations

## GitHub Actions

```yaml
name: MISRA CI
on: [push, pull_request]
jobs:
  scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: 0rlych1kk4/misra-ci@v0
        with:
          source: ./src
          rules: ./rulesets/misra-c-2012.yaml
          gate: "critical:0,high:0,medium:10,low:50"
      - uses: actions/upload-artifact@v4
        with:
          name: misra-reports
          path: target/misra-ci
```

## GitLab / Jenkins

Run the binary in a CI job, then collect `target/misra-ci` as artifacts and import `report.junit.xml` into your test viewer.
