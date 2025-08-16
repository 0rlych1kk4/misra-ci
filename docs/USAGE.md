# Usage

## CLI

```
misra-cli
  --source <PATH>    # directory to scan
  --rules <FILE>     # YAML ruleset
  --out dir:<PATH>   # output directory
  --gate "critical:X,high:Y,medium:Z,low:W"  # build gate
```

### Example

```bash
cargo run -p misra_cli --   --source ./examples/c_project   --rules ./rulesets/misra-c-2012.yaml   --out dir:target/misra-ci   --gate "critical:0,high:10,medium:50,low:200"
```

## Outputs

- `report.junit.xml` — CI test report
- `report.html` — human-readable summary
- `report.sarif.json` — code scanning dashboards
