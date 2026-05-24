use anyhow::{Context, Result};
use clap::Parser;
use regex::Regex;
use serde::Deserialize;
use std::{collections::HashMap, fs, path::PathBuf};
use time::{format_description::well_known::Rfc3339, OffsetDateTime};
use walkdir::WalkDir;

#[derive(Parser, Debug)]
#[command(name = "misra-cli", version)]
struct Args {
    /// Source directory to scan
    #[arg(long)]
    source: PathBuf,

    /// Rules YAML (patterns + severities)
    #[arg(long)]
    rules: PathBuf,

    /// Output directory, use: --out dir:<path>
    #[arg(long)]
    out: String,

    /// Gate thresholds, e.g. "critical:0,high:5,medium:20,low:100"
    #[arg(long, default_value = "")]
    gate: String,
}

#[derive(Debug, Deserialize)]
struct RuleItem {
    pattern: String,
    rule: String,
    severity: String, // critical|high|medium|low
}

#[derive(Debug, Deserialize, Default)]
struct Rules {
    // Accept "severities" from YAML, but we mark it unused internally.
    #[serde(default, rename = "severities")]
    _severities: HashMap<String, Vec<String>>,

    // Make heuristics optional in YAML; default to empty list if absent.
    #[serde(default)]
    heuristics: Vec<RuleItem>,
}

#[derive(Debug, Clone)]
struct Finding {
    file: String,
    line: usize,
    rule: String,
    severity: String,
    message: String,
}

#[derive(Debug, Clone)]
struct ReportSummary {
    files_scanned: usize,
    total_findings: usize,
    critical: usize,
    high: usize,
    medium: usize,
    low: usize,
    generated_at: String,
}

fn main() -> Result<()> {
    let args = Args::parse();
    let out_dir = parse_out_dir(&args.out)?;
    fs::create_dir_all(&out_dir).context("failed to create output directory")?;

    let rules: Rules = serde_yaml::from_str(&fs::read_to_string(&args.rules)?)
        .context("failed to parse rules YAML")?;

    let files = collect_source_files(&args.source);
    let findings = scan_files(&files, &rules)?;
    let summary = build_summary(files.len(), &findings)?;

    write_junit(&findings, &out_dir)?;
    write_html(&findings, &summary, &out_dir)?;
    write_sarif(&findings, &out_dir)?;

    if let Some(err) = evaluate_gate(&findings, &args.gate) {
        eprintln!("{err}");
        std::process::exit(2);
    }

    println!(
        "Completed. Reports at: {}/report.junit.xml, report.html, report.sarif.json",
        out_dir.display()
    );

    Ok(())
}

fn parse_out_dir(s: &str) -> Result<PathBuf> {
    let p = s.strip_prefix("dir:").unwrap_or(s);
    Ok(PathBuf::from(p))
}

fn collect_source_files(source: &PathBuf) -> Vec<PathBuf> {
    let mut files = vec![];

    for e in WalkDir::new(source).into_iter().filter_map(|e| e.ok()) {
        if !e.file_type().is_file() {
            continue;
        }

        let p = e.path();

        if let Some(ext) = p.extension().and_then(|s| s.to_str()) {
            if ["c", "h", "cpp", "hpp"].contains(&ext) {
                files.push(p.to_path_buf());
            }
        }
    }

    files
}

fn scan_files(files: &[PathBuf], rules: &Rules) -> Result<Vec<Finding>> {
    let mut findings = vec![];

    for f in files {
        let content = fs::read_to_string(f).unwrap_or_default();
        let lines: Vec<&str> = content.lines().collect();

        for h in &rules.heuristics {
            let re = Regex::new(&h.pattern)
                .with_context(|| format!("bad regex in ruleset: {}", h.pattern))?;

            for (idx, line) in lines.iter().enumerate() {
                if re.is_match(line) {
                    findings.push(Finding {
                        file: f.to_string_lossy().to_string(),
                        line: idx + 1,
                        rule: h.rule.clone(),
                        severity: h.severity.clone(),
                        message: format!("Heuristic match for {}", h.rule),
                    });
                }
            }
        }
    }

    Ok(findings)
}

fn build_summary(files_scanned: usize, findings: &[Finding]) -> Result<ReportSummary> {
    let mut critical = 0usize;
    let mut high = 0usize;
    let mut medium = 0usize;
    let mut low = 0usize;

    for f in findings {
        match f.severity.to_lowercase().as_str() {
            "critical" => critical += 1,
            "high" => high += 1,
            "medium" => medium += 1,
            "low" => low += 1,
            _ => {}
        }
    }

    let generated_at = OffsetDateTime::now_utc()
        .format(&Rfc3339)
        .context("failed to format generated timestamp")?;

    Ok(ReportSummary {
        files_scanned,
        total_findings: findings.len(),
        critical,
        high,
        medium,
        low,
        generated_at,
    })
}

fn write_junit(findings: &[Finding], out_dir: &PathBuf) -> Result<()> {
    use junit_report::{Duration, Report, TestCase, TestSuite};
    use std::fs::File;

    let mut suite = TestSuite::new("misra-ci");

    for f in findings {
        let name = format!("{}:{}", f.file, f.line);
        let msg = format!("[{}] {} - {}", f.severity, f.rule, f.message);
        let type_ = f.rule.as_str();
        let case = TestCase::failure(&name, Duration::seconds(0), type_, &msg);
        suite.add_testcase(case);
    }

    let mut report = Report::new();
    report.add_testsuite(suite);

    let mut file = File::create(out_dir.join("report.junit.xml"))?;
    report
        .write_xml(&mut file)
        .context("failed to write JUnit XML")?;

    Ok(())
}

fn write_html(findings: &[Finding], summary: &ReportSummary, out_dir: &PathBuf) -> Result<()> {
    let status = if summary.total_findings == 0 {
        "Passed"
    } else {
        "Findings Detected"
    };

    let status_class = if summary.total_findings == 0 {
        "status-pass"
    } else {
        "status-fail"
    };

    let mut rows = String::new();

    if findings.is_empty() {
        rows.push_str(
            r#"<tr><td colspan="5" class="empty">No findings detected.</td></tr>
"#,
        );
    } else {
        for f in findings {
            rows.push_str(&format!(
                "<tr><td class=\"sev sev-{severity_class}\">{severity}</td><td>{rule}</td><td>{file}</td><td>{line}</td><td>{message}</td></tr>\n",
                severity_class = html_escape(&f.severity.to_lowercase()),
                severity = html_escape(&f.severity),
                rule = html_escape(&f.rule),
                file = html_escape(&f.file),
                line = f.line,
                message = html_escape(&f.message)
            ));
        }
    }

    let doc = format!(
        r#"<!doctype html>
<html>
<head>
<meta charset="utf-8">
<title>MISRA CI Report</title>
<style>
body {{
  font-family: Arial, Helvetica, sans-serif;
  margin: 32px;
  color: #1f2937;
  background: #f9fafb;
}}

h1 {{
  margin-bottom: 4px;
}}

.meta {{
  color: #6b7280;
  margin-bottom: 16px;
}}

.status {{
  display: inline-block;
  padding: 6px 12px;
  border-radius: 999px;
  font-weight: 700;
  margin-bottom: 24px;
}}

.status-pass {{
  background: #dcfce7;
  color: #166534;
}}

.status-fail {{
  background: #fee2e2;
  color: #991b1b;
}}

.summary {{
  display: grid;
  grid-template-columns: repeat(auto-fit, minmax(150px, 1fr));
  gap: 12px;
  margin: 24px 0;
}}

.card {{
  background: #ffffff;
  border: 1px solid #e5e7eb;
  border-radius: 10px;
  padding: 16px;
  box-shadow: 0 1px 2px rgba(0, 0, 0, 0.04);
}}

.card-title {{
  color: #6b7280;
  font-size: 13px;
  margin-bottom: 8px;
}}

.card-value {{
  font-size: 28px;
  font-weight: 700;
}}

table {{
  width: 100%;
  border-collapse: collapse;
  background: #ffffff;
  border: 1px solid #e5e7eb;
}}

td, th {{
  border-bottom: 1px solid #e5e7eb;
  padding: 10px;
  text-align: left;
  vertical-align: top;
}}

th {{
  background: #f3f4f6;
  font-size: 13px;
  text-transform: uppercase;
  letter-spacing: 0.04em;
  color: #374151;
}}

tr:hover {{
  background: #f9fafb;
}}

.sev {{
  font-weight: 700;
  text-transform: uppercase;
}}

.sev-critical {{
  color: #991b1b;
}}

.sev-high {{
  color: #b45309;
}}

.sev-medium {{
  color: #92400e;
}}

.sev-low {{
  color: #1d4ed8;
}}

.empty {{
  text-align: center;
  color: #6b7280;
  padding: 24px;
}}
</style>
</head>
<body>
<h1>MISRA CI Report</h1>
<div class="meta">Generated at: {generated_at}</div>
<div class="status {status_class}">{status}</div>

<section class="summary">
  <div class="card">
    <div class="card-title">Files scanned</div>
    <div class="card-value">{files_scanned}</div>
  </div>
  <div class="card">
    <div class="card-title">Total findings</div>
    <div class="card-value">{total_findings}</div>
  </div>
  <div class="card">
    <div class="card-title">Critical</div>
    <div class="card-value">{critical}</div>
  </div>
  <div class="card">
    <div class="card-title">High</div>
    <div class="card-value">{high}</div>
  </div>
  <div class="card">
    <div class="card-title">Medium</div>
    <div class="card-value">{medium}</div>
  </div>
  <div class="card">
    <div class="card-title">Low</div>
    <div class="card-value">{low}</div>
  </div>
</section>

<h2>Findings</h2>
<table>
<thead>
<tr>
  <th>Severity</th>
  <th>Rule</th>
  <th>File</th>
  <th>Line</th>
  <th>Message</th>
</tr>
</thead>
<tbody>
{rows}
</tbody>
</table>
</body>
</html>"#,
        generated_at = html_escape(&summary.generated_at),
        status = status,
        status_class = status_class,
        files_scanned = summary.files_scanned,
        total_findings = summary.total_findings,
        critical = summary.critical,
        high = summary.high,
        medium = summary.medium,
        low = summary.low,
        rows = rows
    );

    fs::write(out_dir.join("report.html"), doc)?;

    Ok(())
}

fn write_sarif(findings: &[Finding], out_dir: &PathBuf) -> Result<()> {
    #[derive(serde::Serialize)]
    struct SarifLog<'a> {
        version: &'a str,
        #[serde(rename = "$schema")]
        schema: &'a str,
        runs: Vec<SarifRun<'a>>,
    }

    #[derive(serde::Serialize)]
    struct SarifRun<'a> {
        tool: SarifTool<'a>,
        results: Vec<SarifResult>,
    }

    #[derive(serde::Serialize)]
    struct SarifTool<'a> {
        driver: SarifDriver<'a>,
    }

    #[derive(serde::Serialize)]
    struct SarifDriver<'a> {
        name: &'a str,
    }

    #[derive(serde::Serialize)]
    struct SarifResult {
        #[serde(rename = "ruleId")]
        rule_id: String,
        level: String,
        message: SarifMessage,
        locations: Vec<SarifLocation>,
    }

    #[derive(serde::Serialize)]
    struct SarifMessage {
        text: String,
    }

    #[derive(serde::Serialize)]
    struct SarifLocation {
        #[serde(rename = "physicalLocation")]
        physical_location: SarifPhysicalLocation,
    }

    #[derive(serde::Serialize)]
    struct SarifPhysicalLocation {
        #[serde(rename = "artifactLocation")]
        artifact_location: SarifArtifactLocation,
        region: SarifRegion,
    }

    #[derive(serde::Serialize)]
    struct SarifArtifactLocation {
        uri: String,
    }

    #[derive(serde::Serialize)]
    struct SarifRegion {
        #[serde(rename = "startLine")]
        start_line: usize,
    }

    let level_map = |sev: &str| match sev {
        "critical" | "high" => "error",
        "medium" => "warning",
        _ => "note",
    };

    let results = findings
        .iter()
        .map(|f| SarifResult {
            rule_id: f.rule.clone(),
            level: level_map(&f.severity).to_string(),
            message: SarifMessage {
                text: format!("{} - {}", f.severity, f.message),
            },
            locations: vec![SarifLocation {
                physical_location: SarifPhysicalLocation {
                    artifact_location: SarifArtifactLocation {
                        uri: f.file.clone(),
                    },
                    region: SarifRegion { start_line: f.line },
                },
            }],
        })
        .collect::<Vec<_>>();

    let sarif = SarifLog {
        version: "2.1.0",
        schema: "https://schemastore.azurewebsites.net/schemas/json/sarif-2.1.0.json",
        runs: vec![SarifRun {
            tool: SarifTool {
                driver: SarifDriver { name: "misra-ci" },
            },
            results,
        }],
    };

    fs::write(
        out_dir.join("report.sarif.json"),
        serde_json::to_string_pretty(&sarif)?,
    )?;

    Ok(())
}

fn evaluate_gate(findings: &[Finding], gate: &str) -> Option<String> {
    if gate.trim().is_empty() {
        return None;
    }

    let mut budget = HashMap::<String, usize>::new();
    let cleaned = gate.replace(',', " ");

    for pair in cleaned.split_whitespace() {
        if let Some((k, v)) = pair.split_once(':') {
            if let Ok(n) = v.parse::<usize>() {
                budget.insert(k.to_lowercase(), n);
            }
        }
    }

    let mut counts = HashMap::from([
        ("critical".to_string(), 0usize),
        ("high".to_string(), 0usize),
        ("medium".to_string(), 0usize),
        ("low".to_string(), 0usize),
    ]);

    for f in findings {
        *counts.entry(f.severity.to_lowercase()).or_default() += 1;
    }

    let mut violations = vec![];

    for (sev, limit) in budget {
        let c = *counts.get(&sev).unwrap_or(&0);

        if c > limit {
            violations.push(format!("{sev}={c} > limit {limit}"));
        }
    }

    if violations.is_empty() {
        None
    } else {
        Some(format!("Gate failed: {}", violations.join(", ")))
    }
}

fn html_escape(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
}
